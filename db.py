"""
Database abstraction layer.
-----------------------------
Works with TWO backends using the SAME application code:

  - SQLite (default) - zero setup, perfect for local development and
    testing. This is what runs when you just do `python app.py` on
    your laptop with no extra configuration.

  - PostgreSQL (production) - set the DATABASE_URL environment variable
    to a real Postgres connection string, e.g.:
        postgresql://username:password@host:5432/dbname
    and this module automatically switches to using psycopg2 instead.
    You'll need to `pip install psycopg2-binary` on the machine that
    runs this in production (not needed for local SQLite testing).

Why this matters: you can build and test the ENTIRE backend on your
own laptop with zero database setup, then deploy to a real Postgres
database later by changing one environment variable - no code changes.
"""

import os
import sqlite3
import re

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
USE_POSTGRES = DATABASE_URL.startswith("postgres")

SQLITE_PATH = os.path.join(os.path.dirname(__file__), "fraud_correlation.db")

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras


def get_connection():
    """Returns a live DB connection. Caller is responsible for closing it."""
    if USE_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        return conn
    else:
        conn = sqlite3.connect(SQLITE_PATH)
        conn.row_factory = sqlite3.Row
        return conn


def _placeholder():
    """Postgres uses %s, SQLite uses ? - this lets query strings work with both."""
    return "%s" if USE_POSTGRES else "?"


def adapt_query(query: str) -> str:
    """
    Write queries using '?' placeholders everywhere (SQLite style) and
    this converts them to '%s' automatically when running on Postgres.
    Keeps every query in the codebase engine-agnostic.
    """
    if USE_POSTGRES:
        return query.replace("?", "%s")
    return query


def run(query: str, params: tuple = (), fetch: str = None):
    """
    Runs a query against whichever database is configured.
    fetch: None (no return), "one" (single row), "all" (all rows)
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(adapt_query(query), params)
        result = None
        if fetch == "one":
            row = cur.fetchone()
            result = dict(row) if row else None
        elif fetch == "all":
            rows = cur.fetchall()
            result = [dict(r) for r in rows]
        conn.commit()
        return result
    finally:
        conn.close()


SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    badge_id TEXT NOT NULL,
    state TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS complaints (
    complaint_id TEXT PRIMARY KEY,
    date_filed TEXT NOT NULL,
    state TEXT NOT NULL,
    city TEXT NOT NULL,
    victim_name TEXT NOT NULL,
    fraud_type TEXT NOT NULL,
    phone_used_by_fraudster TEXT,
    upi_id TEXT,
    bank_account TEXT,
    ifsc_code TEXT,
    amount_lost_inr REAL NOT NULL,
    mo_description TEXT,
    submitted_by_name TEXT,
    submitted_by_email TEXT,
    submitted_by_state TEXT,
    last_edited_by TEXT,
    last_edited_at TEXT,
    created_at TEXT NOT NULL
);
"""

SCHEMA_POSTGRES = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    badge_id TEXT NOT NULL,
    state TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS complaints (
    complaint_id TEXT PRIMARY KEY,
    date_filed TEXT NOT NULL,
    state TEXT NOT NULL,
    city TEXT NOT NULL,
    victim_name TEXT NOT NULL,
    fraud_type TEXT NOT NULL,
    phone_used_by_fraudster TEXT,
    upi_id TEXT,
    bank_account TEXT,
    ifsc_code TEXT,
    amount_lost_inr DOUBLE PRECISION NOT NULL,
    mo_description TEXT,
    submitted_by_name TEXT,
    submitted_by_email TEXT,
    submitted_by_state TEXT,
    last_edited_by TEXT,
    last_edited_at TEXT,
    created_at TEXT NOT NULL
);
"""


def init_db():
    """Creates tables if they don't exist yet. Safe to call every startup."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        schema = SCHEMA_POSTGRES if USE_POSTGRES else SCHEMA_SQLITE
        for statement in schema.strip().split(";"):
            if statement.strip():
                cur.execute(statement)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database initialized. Using: {'PostgreSQL' if USE_POSTGRES else 'SQLite (local file: ' + SQLITE_PATH + ')'}")