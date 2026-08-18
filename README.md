# Fraud Correlation Engine — Backend API

Real backend: **Flask + SQLite (local dev) / PostgreSQL (production)** with JWT authentication.

## Why this design

- **Zero setup for local testing** — just run `python app.py` and it uses a local SQLite file. No database installation needed to develop and test.
- **Same code works with real PostgreSQL** — set one environment variable (`DATABASE_URL`) and it automatically switches to Postgres. No code changes.
- **Reuses the tested correlation logic** — `correlation.py` is the same fraud-ring / mule-cluster / MO-pattern detection logic from `correlation_engine.py`, adapted to work with database rows.

## Local setup (SQLite, no database installation needed)

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Server starts at `http://localhost:5000`. A file `fraud_correlation.db` is created automatically — that's your entire database, just one file.

## Test it's working

```bash
curl http://localhost:5000/api/health
# Should return: {"database": "sqlite", "status": "ok"}
```

## Switching to real PostgreSQL (production)

1. Get a free PostgreSQL database. Easiest free options:
   - **Neon** (neon.tech) — generous free tier, purpose-built for this
   - **Render** (render.com) — free Postgres + can host this Flask app too
   - **Railway** (railway.app) — free tier available

2. Copy your connection string (looks like `postgresql://user:pass@host:5432/dbname`)

3. Set environment variables:
```bash
export DATABASE_URL="postgresql://user:pass@host:5432/dbname"
export JWT_SECRET="generate-a-long-random-string-here"
pip install psycopg2-binary
python app.py
```

That's it — same code, now backed by real PostgreSQL that any number of officers can share.

## Connecting the React frontend to this backend

The current frontend (`fraud_correlation_dashboard_PRODUCTION.jsx`) uses browser-only storage
(`localStorage`/`window.storage`). To connect it to this real backend instead, the frontend's
`appStorage` calls and manual JS correlation logic need to be replaced with `fetch()` calls to
these endpoints. This is the next integration step — ask for it when you're ready, since it
involves rewriting the data-fetching parts of the dashboard.

## API Endpoints

| Method | Endpoint | Auth required | Purpose |
|---|---|---|---|
| POST | `/api/signup` | No | Create officer account (needs state registration code) |
| POST | `/api/login` | No | Log in, returns JWT token |
| GET | `/api/complaints` | Yes | List all complaints |
| POST | `/api/complaints` | Yes | Create a complaint |
| PUT | `/api/complaints/<id>` | Yes | Edit a complaint |
| DELETE | `/api/complaints/<id>` | Yes | Delete a complaint |
| POST | `/api/complaints/bulk` | Yes | Bulk create from parsed CSV/Excel rows |
| GET | `/api/rings` | Yes | Computed fraud rings |
| GET | `/api/mule-clusters` | Yes | Computed mule account clusters |
| GET | `/api/mo-patterns` | Yes | Computed MO text-similarity patterns |
| GET | `/api/analytics` | Yes | Aggregate stats |
| GET | `/api/health` | No | Check server + database status |

All authenticated endpoints need header: `Authorization: Bearer <token>`

## Security notes (read before any real deployment)

- `JWT_SECRET` **must** be changed from the default before production use — set it via
  environment variable, never commit a real secret to code.
- The state registration codes in `app.py` (`STATE_REGISTRATION_CODES`) are placeholders and
  must be replaced with real codes distributed securely to each state cyber cell.
- This uses Flask's built-in development server (`app.run()`), which is explicitly not meant
  for production traffic. For real deployment, run it behind a production WSGI server
  (e.g. `gunicorn app:app`) and a reverse proxy (e.g. nginx), with HTTPS enabled.
- `ALLOWED_ORIGINS` is currently `*` (any website can call this API) — restrict this to your
  actual frontend's domain before going live.
