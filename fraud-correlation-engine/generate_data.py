"""
Synthetic Cybercrime Complaint Data Generator
-----------------------------------------------
Generates FAKE fraud complaint records that mimic what cybercrime.gov.in
style complaints look like, but ALL data is fabricated. Purpose: build
and test a cross-state fraud correlation engine (graph-based link analysis)
without touching any real, sensitive, or legally protected data.

Design idea: create N "fraud rings" first. Each ring shares some identifiers
(a phone number, a UPI ID, a bank account, an IFSC) across MULTIPLE
complaints filed in DIFFERENT states/cities. This is exactly the pattern
a correlation engine should be able to detect and cluster.
"""

import random
import json
import csv
from datetime import datetime, timedelta

random.seed(42)  # reproducible output

# ---------- Reference pools (all fictional / generic) ----------

FIRST_NAMES = ["Raj", "Amit", "Priya", "Sneha", "Vikram", "Anita", "Suresh",
               "Kavita", "Manoj", "Pooja", "Ravi", "Neha", "Ajay", "Divya",
               "Sanjay", "Rekha", "Deepak", "Meena", "Arjun", "Simran"]

LAST_NAMES = ["Sharma", "Patel", "Verma", "Gupta", "Yadav", "Reddy", "Nair",
              "Iyer", "Mehta", "Joshi", "Chauhan", "Desai", "Rao", "Singh",
              "Kapoor"]

STATES_CITIES = {
    "Gujarat": ["Ahmedabad", "Surat", "Vadodara", "Rajkot"],
    "Maharashtra": ["Mumbai", "Pune", "Nagpur", "Nashik"],
    "Madhya Pradesh": ["Bhopal", "Indore", "Gwalior"],
    "Bihar": ["Patna", "Gaya", "Muzaffarpur"],
    "Delhi": ["New Delhi", "Dwarka", "Rohini"],
    "Karnataka": ["Bengaluru", "Mysuru", "Hubli"],
    "Uttar Pradesh": ["Lucknow", "Kanpur", "Noida", "Ghaziabad"],
    "West Bengal": ["Kolkata", "Howrah"],
    "Telangana": ["Hyderabad", "Warangal"],
    "Rajasthan": ["Jaipur", "Jodhpur"],
}

FRAUD_TYPES = [
    "UPI Fraud - Fake QR Code",
    "Loan App Harassment",
    "Investment/Trading Scam",
    "Digital Arrest Scam",
    "OTP Fraud",
    "Fake Job Offer Fraud",
    "KYC Update Scam",
    "Online Shopping Fraud",
    "Matrimonial Fraud",
    "Sextortion",
]

MO_TEMPLATES = [
    "Victim received a call from {phone} claiming to be from {bank} bank asking to verify KYC via UPI PIN.",
    "Victim was added to a Telegram investment group and asked to transfer funds to UPI ID {upi} for 'guaranteed returns'.",
    "Fraudster posing as courier company called from {phone} claiming a parcel was seized, demanded payment to account {acc}.",
    "Victim received video call from person claiming to be CBI officer, threatened digital arrest, asked for transfer to {acc} via IFSC {ifsc}.",
    "Victim clicked on a loan app link, after taking small loan started receiving harassment calls from {phone} for repayment to {upi}.",
    "Fake online store took payment via {upi} but never delivered product, seller phone {phone} now unreachable.",
]

BANKS = ["SBI", "HDFC", "ICICI", "Axis", "PNB", "Bank of Baroda", "Kotak"]

IFSC_PREFIXES = ["SBIN0", "HDFC0", "ICIC0", "UTIB0", "PUNB0", "BARB0", "KKBK0"]


def random_phone():
    return "+91" + str(random.randint(70000, 99999)) + str(random.randint(10000, 99999))


def random_upi(name_hint=""):
    handles = ["@okaxis", "@ybl", "@paytm", "@okhdfcbank", "@ibl", "@okicici"]
    base = name_hint.lower() if name_hint else "user" + str(random.randint(100, 999))
    return f"{base}{random.randint(10,99)}{random.choice(handles)}"


def random_account():
    return str(random.randint(10, 99)) + str(random.randint(100000000, 999999999))


def random_ifsc():
    return random.choice(IFSC_PREFIXES) + str(random.randint(100000, 999999))


def random_name():
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"


def random_date(start_days_ago=180):
    d = datetime.now() - timedelta(days=random.randint(0, start_days_ago))
    return d.strftime("%Y-%m-%d")


def build_fraud_rings(num_rings=15, complaints_per_ring_range=(4, 12)):
    """
    Each 'ring' is a fraud gang that reuses a SMALL set of identifiers
    (phone/UPI/account/IFSC) across MANY complaints filed in DIFFERENT
    states. This is the ground-truth pattern the correlation engine
    should be able to recover from the flat complaint list.
    """
    rings = []
    for r in range(num_rings):
        # Ring identity: a fixed set of reused identifiers
        ring = {
            "ring_id": f"RING-{r+1:03d}",
            "phones": [random_phone() for _ in range(random.randint(1, 3))],
            "upis": [random_upi() for _ in range(random.randint(1, 3))],
            "accounts": [random_account() for _ in range(random.randint(1, 2))],
            "ifscs": [random_ifsc() for _ in range(random.randint(1, 2))],
            "fraud_type": random.choice(FRAUD_TYPES),
            "num_complaints": random.randint(*complaints_per_ring_range),
        }
        rings.append(ring)
    return rings


def generate_complaints(rings, noise_complaints=200):
    complaints = []
    complaint_id = 1

    # 1. Generate complaints belonging to fraud rings (the signal)
    for ring in rings:
        states_used = random.sample(list(STATES_CITIES.keys()),
                                     k=min(len(STATES_CITIES), random.randint(2, 6)))
        for _ in range(ring["num_complaints"]):
            state = random.choice(states_used)
            city = random.choice(STATES_CITIES[state])
            phone = random.choice(ring["phones"])
            upi = random.choice(ring["upis"])
            acc = random.choice(ring["accounts"])
            ifsc = random.choice(ring["ifscs"])
            bank = random.choice(BANKS)
            mo = random.choice(MO_TEMPLATES).format(
                phone=phone, upi=upi, acc=acc, ifsc=ifsc, bank=bank
            )
            complaints.append({
                "complaint_id": f"CMP-{complaint_id:05d}",
                "date_filed": random_date(),
                "state": state,
                "city": city,
                "victim_name": random_name(),
                "fraud_type": ring["fraud_type"],
                "phone_used_by_fraudster": phone,
                "upi_id": upi,
                "bank_account": acc,
                "ifsc_code": ifsc,
                "amount_lost_inr": random.randint(2000, 500000),
                "mo_description": mo,
                "_ground_truth_ring_id": ring["ring_id"],  # for validation only
            })
            complaint_id += 1

    # 2. Generate pure noise complaints (isolated, unrelated cases)
    for _ in range(noise_complaints):
        state = random.choice(list(STATES_CITIES.keys()))
        city = random.choice(STATES_CITIES[state])
        phone = random_phone()
        upi = random_upi()
        acc = random_account()
        ifsc = random_ifsc()
        bank = random.choice(BANKS)
        fraud_type = random.choice(FRAUD_TYPES)
        mo = random.choice(MO_TEMPLATES).format(
            phone=phone, upi=upi, acc=acc, ifsc=ifsc, bank=bank
        )
        complaints.append({
            "complaint_id": f"CMP-{complaint_id:05d}",
            "date_filed": random_date(),
            "state": state,
            "city": city,
            "victim_name": random_name(),
            "fraud_type": fraud_type,
            "phone_used_by_fraudster": phone,
            "upi_id": upi,
            "bank_account": acc,
            "ifsc_code": ifsc,
            "amount_lost_inr": random.randint(2000, 500000),
            "mo_description": mo,
            "_ground_truth_ring_id": None,
        })
        complaint_id += 1

    random.shuffle(complaints)
    return complaints


def main():
    rings = build_fraud_rings(num_rings=15, complaints_per_ring_range=(4, 12))
    complaints = generate_complaints(rings, noise_complaints=200)

    # Save full JSON (includes ground truth ring id, useful for YOU to
    # validate whether your correlation engine correctly reconstructs rings)
    with open("synthetic_complaints_full.json", "w") as f:
        json.dump(complaints, f, indent=2)

    # Save a "clean" CSV WITHOUT ground truth — this is what you'd feed
    # into the correlation engine, pretending you don't know the answer
    clean_fields = [k for k in complaints[0].keys() if k != "_ground_truth_ring_id"]
    with open("synthetic_complaints_clean.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=clean_fields)
        writer.writeheader()
        for c in complaints:
            writer.writerow({k: c[k] for k in clean_fields})

    # Save ring ground truth separately (for scoring your engine's accuracy)
    with open("ring_ground_truth.json", "w") as f:
        json.dump(rings, f, indent=2)

    print(f"Generated {len(complaints)} complaints across {len(STATES_CITIES)} states.")
    print(f"  - {sum(r['num_complaints'] for r in rings)} complaints belong to {len(rings)} fraud rings (signal)")
    print(f"  - 200 complaints are pure noise (isolated cases)")
    print("\nFiles written:")
    print("  synthetic_complaints_full.json   (with ground truth ring id, for YOUR validation)")
    print("  synthetic_complaints_clean.csv    (what your engine will actually process)")
    print("  ring_ground_truth.json            (ring definitions, for scoring accuracy)")


if __name__ == "__main__":
    main()
