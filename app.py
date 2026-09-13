"""
Fraud Correlation Engine - Backend API
------------------------------------------
Real backend: Flask + SQLite (dev) / PostgreSQL (prod) + JWT auth.

Run locally:
    python app.py
    -> starts on http://localhost:5000, using a local SQLite file.

Run against real PostgreSQL:
    export DATABASE_URL="postgresql://user:pass@host:5432/dbname"
    export JWT_SECRET="some-long-random-string"
    python app.py

Endpoints:
    POST /api/signup           - create officer account
    POST /api/login            - log in, returns JWT token
    GET  /api/complaints       - list all complaints (requires auth)
    POST /api/complaints       - create a complaint (requires auth)
    PUT  /api/complaints/<id>  - edit a complaint (requires auth)
    DELETE /api/complaints/<id> - delete a complaint (requires auth)
    POST /api/complaints/bulk  - bulk create complaints (requires auth)
    GET  /api/rings            - computed fraud rings
    GET  /api/mule-clusters    - computed mule clusters
    GET  /api/mo-patterns      - computed MO text-similarity patterns
    GET  /api/analytics        - aggregate stats
"""

import os
import re
import jwt
import math
import base64
import datetime
from functools import wraps
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

import db
import correlation

app = Flask(__name__)

# Create database tables if they don't exist yet. This MUST run at module
# level (not just inside `if __name__ == "__main__"`), because production
# servers like gunicorn import this file as a module rather than running
# it directly - so the __main__ block never executes there. Without this,
# the app would deploy successfully but every request would fail with a
# 500 error because the tables were never created.
db.init_db()

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-only-secret-change-this-in-production")
JWT_ALGO = "HS256"
TOKEN_EXPIRY_HOURS = 12

# CORS - allow the React frontend (running on a different port/domain)
# to call this API. Tighten allowed_origins before real deployment.
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*")


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGINS
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


@app.route("/api/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return "", 204


# ---------------------------------------------------------------------
# VALIDATION (mirrors the frontend's validation rules exactly)
# ---------------------------------------------------------------------
PHONE_RE = re.compile(r"^\+91\d{10}$")
UPI_RE = re.compile(r"^[\w.\-]{2,256}@[a-zA-Z]{2,64}$")
ACCOUNT_RE = re.compile(r"^\d{9,18}$")
IFSC_RE = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")

STATE_REGISTRATION_CODES = {
    "Andhra Pradesh": "AP-CYBER-2026", "Bihar": "BR-CYBER-2026", "Delhi": "DL-CYBER-2026",
    "Gujarat": "GJ-CYBER-2026", "Karnataka": "KA-CYBER-2026", "Madhya Pradesh": "MP-CYBER-2026",
    "Maharashtra": "MH-CYBER-2026", "Rajasthan": "RJ-CYBER-2026", "Tamil Nadu": "TN-CYBER-2026",
    "Telangana": "TS-CYBER-2026", "Uttar Pradesh": "UP-CYBER-2026", "West Bengal": "WB-CYBER-2026",
}


def validate_complaint(data: dict) -> dict:
    errors = {}
    if not (data.get("state") or "").strip():
        errors["state"] = "State is required"
    if not (data.get("city") or "").strip():
        errors["city"] = "City is required"
    if not (data.get("victim_name") or "").strip():
        errors["victim_name"] = "Victim name is required"
    if not (data.get("fraud_type") or "").strip():
        errors["fraud_type"] = "Fraud type is required"
    try:
        if float(data.get("amount_lost_inr", 0)) <= 0:
            errors["amount_lost_inr"] = "Enter a valid amount"
    except (ValueError, TypeError):
        errors["amount_lost_inr"] = "Enter a valid amount"

    phone = (data.get("phone_used_by_fraudster") or "").strip()
    if phone and not PHONE_RE.match(phone):
        errors["phone_used_by_fraudster"] = "Format: +91 followed by 10 digits"
    upi = (data.get("upi_id") or "").strip()
    if upi and not UPI_RE.match(upi):
        errors["upi_id"] = "Format: name@bankhandle"
    account = (data.get("bank_account") or "").strip()
    if account and not ACCOUNT_RE.match(account):
        errors["bank_account"] = "9-18 digits only"
    ifsc = (data.get("ifsc_code") or "").strip().upper()
    if ifsc and not IFSC_RE.match(ifsc):
        errors["ifsc_code"] = "Format: 4 letters + 0 + 6 alphanumeric"

    if not any([phone, upi, account, ifsc]):
        errors["_identifier"] = "Enter at least one identifier so this complaint can be correlated"

    return errors


# ---------------------------------------------------------------------
# AUTH HELPERS
# ---------------------------------------------------------------------
def make_token(user: dict) -> str:
    payload = {
        "email": user["email"],
        "name": user["name"],
        "state": user["state"],
        "badge_id": user["badge_id"],
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=TOKEN_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth_header.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Session expired, please log in again"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        request.current_user = payload
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------
# AUTH ROUTES
# ---------------------------------------------------------------------
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    badge_id = (data.get("badge_id") or "").strip()
    state = (data.get("state") or "").strip()
    reg_code = (data.get("reg_code") or "").strip().upper()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not all([name, badge_id, state, email, password]):
        return jsonify({"error": "Please fill all required fields"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    expected_code = STATE_REGISTRATION_CODES.get(state)
    if not expected_code or reg_code != expected_code:
        return jsonify({"error": "Registration code does not match the selected state"}), 400

    existing = db.run("SELECT email FROM users WHERE email = ?", (email,), fetch="one")
    if existing:
        return jsonify({"error": "An account with this email already exists"}), 400

    password_hash = generate_password_hash(password)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    db.run(
        "INSERT INTO users (name, badge_id, state, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (name, badge_id, state, email, password_hash, now),
    )
    user = {"name": name, "email": email, "state": state, "badge_id": badge_id}
    return jsonify({"token": make_token(user), "user": user}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = db.run("SELECT * FROM users WHERE email = ?", (email,), fetch="one")
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid email or password"}), 401

    user_public = {"name": user["name"], "email": user["email"], "state": user["state"], "badge_id": user["badge_id"]}
    return jsonify({"token": make_token(user_public), "user": user_public})


# ---------------------------------------------------------------------
# COMPLAINT ROUTES
# ---------------------------------------------------------------------
COMPLAINT_FIELDS = [
    "complaint_id", "date_filed", "state", "city", "victim_name", "fraud_type",
    "phone_used_by_fraudster", "upi_id", "bank_account", "ifsc_code",
    "amount_lost_inr", "mo_description", "submitted_by_name", "submitted_by_email",
    "submitted_by_state", "last_edited_by", "last_edited_at",
]


def next_complaint_id():
    row = db.run("SELECT COUNT(*) as n FROM complaints", fetch="one")
    return f"CMP-{1000 + row['n'] + 1}"


@app.route("/api/complaints", methods=["GET"])
@require_auth
def list_complaints():
    rows = db.run(f"SELECT {', '.join(COMPLAINT_FIELDS)} FROM complaints ORDER BY date_filed DESC", fetch="all")
    return jsonify(rows)


@app.route("/api/complaints", methods=["POST"])
@require_auth
def create_complaint():
    data = request.get_json(force=True)
    errors = validate_complaint(data)
    if errors:
        return jsonify({"errors": errors}), 400

    cid = next_complaint_id()
    now_date = datetime.date.today().isoformat()
    user = request.current_user

    db.run(
        f"""INSERT INTO complaints
            (complaint_id, date_filed, state, city, victim_name, fraud_type,
             phone_used_by_fraudster, upi_id, bank_account, ifsc_code,
             amount_lost_inr, mo_description, submitted_by_name,
             submitted_by_email, submitted_by_state, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (cid, now_date, data["state"], data["city"], data["victim_name"], data["fraud_type"],
         data.get("phone_used_by_fraudster", ""), data.get("upi_id", ""), data.get("bank_account", ""),
         (data.get("ifsc_code") or "").upper(), float(data["amount_lost_inr"]),
         data.get("mo_description", "No description provided."), user["name"], user["email"],
         user["state"], datetime.datetime.now(datetime.timezone.utc).isoformat()),
    )
    row = db.run(f"SELECT {', '.join(COMPLAINT_FIELDS)} FROM complaints WHERE complaint_id = ?", (cid,), fetch="one")
    return jsonify(row), 201


@app.route("/api/complaints/bulk", methods=["POST"])
@require_auth
def bulk_create_complaints():
    data = request.get_json(force=True)
    rows = data.get("rows", [])
    if len(rows) > 1000:
        return jsonify({"error": "Max 1000 rows per bulk upload"}), 400

    user = request.current_user
    created = []
    row_errors = []
    for i, row in enumerate(rows):
        errors = validate_complaint(row)
        if errors:
            row_errors.append({"row": i + 1, "errors": errors})
            continue
        cid = next_complaint_id()
        now_date = row.get("date_filed") or datetime.date.today().isoformat()
        db.run(
            f"""INSERT INTO complaints
                (complaint_id, date_filed, state, city, victim_name, fraud_type,
                 phone_used_by_fraudster, upi_id, bank_account, ifsc_code,
                 amount_lost_inr, mo_description, submitted_by_name,
                 submitted_by_email, submitted_by_state, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (cid, now_date, row["state"], row["city"], row["victim_name"], row["fraud_type"],
             row.get("phone_used_by_fraudster", ""), row.get("upi_id", ""), row.get("bank_account", ""),
             (row.get("ifsc_code") or "").upper(), float(row["amount_lost_inr"]),
             row.get("mo_description", "No description provided."), user["name"], user["email"],
             user["state"], datetime.datetime.now(datetime.timezone.utc).isoformat()),
        )
        created.append(cid)

    return jsonify({"created": len(created), "created_ids": created, "row_errors": row_errors}), 201


@app.route("/api/complaints/<complaint_id>", methods=["PUT"])
@require_auth
def update_complaint(complaint_id):
    data = request.get_json(force=True)
    errors = validate_complaint(data)
    if errors:
        return jsonify({"errors": errors}), 400

    existing = db.run("SELECT complaint_id FROM complaints WHERE complaint_id = ?", (complaint_id,), fetch="one")
    if not existing:
        return jsonify({"error": "Complaint not found"}), 404

    user = request.current_user
    db.run(
        """UPDATE complaints SET
            state=?, city=?, victim_name=?, fraud_type=?, phone_used_by_fraudster=?,
            upi_id=?, bank_account=?, ifsc_code=?, amount_lost_inr=?, mo_description=?,
            last_edited_by=?, last_edited_at=?
           WHERE complaint_id=?""",
        (data["state"], data["city"], data["victim_name"], data["fraud_type"],
         data.get("phone_used_by_fraudster", ""), data.get("upi_id", ""), data.get("bank_account", ""),
         (data.get("ifsc_code") or "").upper(), float(data["amount_lost_inr"]),
         data.get("mo_description", ""), user["name"], datetime.datetime.now(datetime.timezone.utc).isoformat(), complaint_id),
    )
    row = db.run(f"SELECT {', '.join(COMPLAINT_FIELDS)} FROM complaints WHERE complaint_id = ?", (complaint_id,), fetch="one")
    return jsonify(row)


@app.route("/api/complaints/<complaint_id>", methods=["DELETE"])
@require_auth
def delete_complaint(complaint_id):
    existing = db.run("SELECT complaint_id FROM complaints WHERE complaint_id = ?", (complaint_id,), fetch="one")
    if not existing:
        return jsonify({"error": "Complaint not found"}), 404
    db.run("DELETE FROM complaints WHERE complaint_id = ?", (complaint_id,))
    return jsonify({"deleted": complaint_id})


# ---------------------------------------------------------------------
# ANALYSIS ROUTES (computed live from current DB contents)
# ---------------------------------------------------------------------
def _all_complaints():
    return db.run(f"SELECT {', '.join(COMPLAINT_FIELDS)} FROM complaints", fetch="all")


@app.route("/api/rings", methods=["GET"])
@require_auth
def get_rings():
    return jsonify(correlation.build_fraud_rings(_all_complaints()))


@app.route("/api/mule-clusters", methods=["GET"])
@require_auth
def get_mule_clusters():
    return jsonify(correlation.build_mule_clusters(_all_complaints()))


@app.route("/api/mo-patterns", methods=["GET"])
@require_auth
def get_mo_patterns():
    return jsonify(correlation.build_mo_pattern_clusters(_all_complaints()))


@app.route("/api/analytics", methods=["GET"])
@require_auth
def get_analytics():
    complaints = _all_complaints()
    total_loss = sum(float(c.get("amount_lost_inr") or 0) for c in complaints)
    states = {}
    fraud_types = {}
    for c in complaints:
        states[c["state"]] = states.get(c["state"], 0) + 1
        fraud_types[c["fraud_type"]] = fraud_types.get(c["fraud_type"], 0) + 1
    return jsonify({
        "total_complaints": len(complaints),
        "total_loss": total_loss,
        "avg_loss": round(total_loss / len(complaints)) if complaints else 0,
        "states_affected": len(states),
        "by_state": states,
        "by_fraud_type": fraud_types,
    })


# ---------------------------------------------------------------------
# CCTV CAMERA REGISTRY
# -----------------------------------------------------------------------
# There is no public API for real government/private CCTV camera
# locations - that data isn't openly available to anyone, including us.
# What several Indian city police forces actually do (e.g. citizen CCTV
# registration drives) is build their OWN registry over time: shop
# owners, housing societies, and citizens voluntarily register that they
# have a camera at a given address, so that when a crime happens nearby,
# police know exactly which doors to knock on to ask for footage. This
# endpoint set implements exactly that model - it is not a live feed or
# a database of India's cameras, it is a registry that starts empty and
# grows as officers/citizens add entries.
# ---------------------------------------------------------------------
def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two lat/long points, in kilometers."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


CCTV_FIELDS = ["id", "owner_name", "owner_contact", "camera_type", "address",
               "city", "state", "latitude", "longitude", "registered_by_name",
               "registered_by_email", "created_at"]


@app.route("/api/cctv", methods=["GET"])
@require_auth
def list_cctv_cameras():
    rows = db.run(f"SELECT {', '.join(CCTV_FIELDS)} FROM cctv_cameras ORDER BY created_at DESC", fetch="all")
    return jsonify(rows)


@app.route("/api/cctv", methods=["POST"])
@require_auth
def register_cctv_camera():
    data = request.get_json(force=True)
    required = ["owner_name", "camera_type", "address", "city", "state", "latitude", "longitude"]
    missing = [f for f in required if not str(data.get(f, "")).strip() and data.get(f) != 0]
    if missing:
        return jsonify({"error": f"Missing required field(s): {', '.join(missing)}"}), 400

    try:
        lat = float(data["latitude"])
        lng = float(data["longitude"])
    except (ValueError, TypeError):
        return jsonify({"error": "Latitude/longitude must be numbers"}), 400
    if not (-90 <= lat <= 90 and -180 <= lng <= 180):
        return jsonify({"error": "Latitude/longitude out of valid range"}), 400

    user = request.current_user
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    db.run(
        """INSERT INTO cctv_cameras
           (owner_name, owner_contact, camera_type, address, city, state,
            latitude, longitude, registered_by_name, registered_by_email, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (data["owner_name"], data.get("owner_contact", ""), data["camera_type"],
         data["address"], data["city"], data["state"], lat, lng,
         user["name"], user["email"], now),
    )
    return jsonify({"registered": True}), 201


@app.route("/api/cctv/nearby", methods=["GET"])
@require_auth
def nearby_cctv_cameras():
    """
    Given a lat/long (typically geocoded from a complaint's city on the
    frontend) and a radius in km, returns registered cameras within that
    radius, sorted nearest first. Distance is computed in Python rather
    than in SQL so this works identically on both SQLite and PostgreSQL.
    """
    try:
        lat = float(request.args.get("lat"))
        lng = float(request.args.get("lng"))
    except (TypeError, ValueError):
        return jsonify({"error": "lat and lng query parameters are required"}), 400
    radius_km = float(request.args.get("radius_km", 5))

    all_cameras = db.run(f"SELECT {', '.join(CCTV_FIELDS)} FROM cctv_cameras", fetch="all")
    nearby = []
    for cam in all_cameras:
        dist = haversine_km(lat, lng, cam["latitude"], cam["longitude"])
        if dist <= radius_km:
            cam_with_dist = dict(cam)
            cam_with_dist["distance_km"] = round(dist, 2)
            nearby.append(cam_with_dist)

    nearby.sort(key=lambda c: c["distance_km"])
    return jsonify(nearby)


# ---------------------------------------------------------------------
# EVIDENCE UPLOAD
# -----------------------------------------------------------------------
# Lets an officer attach photo evidence (or short video clips) to a
# specific complaint. Files are stored as base64 in the database - fine
# for a hackathon-scale demo with a handful of images per case, but a
# real production deployment should switch this to object storage
# (e.g. S3-compatible storage) once file volume grows, since storing
# large binaries directly in a relational database doesn't scale well.
# A hard size cap is enforced here specifically to prevent that from
# becoming a problem at this stage.
# ---------------------------------------------------------------------
MAX_EVIDENCE_SIZE_KB = 4000  # ~4 MB per file

EVIDENCE_FIELDS = ["id", "complaint_id", "file_name", "file_type", "file_size_kb",
                   "caption", "uploaded_by_name", "uploaded_by_email", "uploaded_at"]


@app.route("/api/complaints/<complaint_id>/evidence", methods=["GET"])
@require_auth
def list_evidence(complaint_id):
    rows = db.run(
        f"SELECT {', '.join(EVIDENCE_FIELDS)} FROM evidence WHERE complaint_id = ? ORDER BY uploaded_at DESC",
        (complaint_id,), fetch="all"
    )
    return jsonify(rows)


@app.route("/api/complaints/<complaint_id>/evidence/<int:evidence_id>", methods=["GET"])
@require_auth
def get_evidence_file(complaint_id, evidence_id):
    """Returns the actual file data (base64) - separate from the list
    endpoint above so listing evidence for a case stays fast even with
    several large files attached."""
    row = db.run(
        "SELECT file_name, file_type, file_data FROM evidence WHERE id = ? AND complaint_id = ?",
        (evidence_id, complaint_id), fetch="one"
    )
    if not row:
        return jsonify({"error": "Evidence not found"}), 404
    return jsonify(row)


@app.route("/api/complaints/<complaint_id>/evidence", methods=["POST"])
@require_auth
def upload_evidence(complaint_id):
    complaint = db.run("SELECT complaint_id FROM complaints WHERE complaint_id = ?", (complaint_id,), fetch="one")
    if not complaint:
        return jsonify({"error": "Complaint not found"}), 404

    data = request.get_json(force=True)
    file_name = (data.get("file_name") or "").strip()
    file_type = (data.get("file_type") or "").strip()
    file_data = data.get("file_data") or ""  # base64 string, no data: prefix
    caption = (data.get("caption") or "").strip()

    if not file_name or not file_type or not file_data:
        return jsonify({"error": "file_name, file_type, and file_data are required"}), 400

    size_kb = len(file_data) * 3 / 4 / 1024  # approximate decoded size from base64 length
    if size_kb > MAX_EVIDENCE_SIZE_KB:
        return jsonify({"error": f"File too large ({round(size_kb)} KB) - max {MAX_EVIDENCE_SIZE_KB} KB per file"}), 400

    user = request.current_user
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    db.run(
        """INSERT INTO evidence
           (complaint_id, file_name, file_type, file_size_kb, file_data, caption,
            uploaded_by_name, uploaded_by_email, uploaded_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (complaint_id, file_name, file_type, size_kb, file_data, caption,
         user["name"], user["email"], now),
    )
    return jsonify({"uploaded": True}), 201


@app.route("/api/complaints/<complaint_id>/evidence/<int:evidence_id>", methods=["DELETE"])
@require_auth
def delete_evidence(complaint_id, evidence_id):
    existing = db.run("SELECT id FROM evidence WHERE id = ? AND complaint_id = ?", (evidence_id, complaint_id), fetch="one")
    if not existing:
        return jsonify({"error": "Evidence not found"}), 404
    db.run("DELETE FROM evidence WHERE id = ?", (evidence_id,))
    return jsonify({"deleted": evidence_id})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "database": "postgresql" if db.USE_POSTGRES else "sqlite"})


if __name__ == "__main__":
    print(f"Database: {'PostgreSQL' if db.USE_POSTGRES else 'SQLite (local)'}")
    print("Starting server on http://localhost:5000")
    app.run(debug=False, port=5000, use_reloader=False)