"""Database helpers: connection + schema setup."""
import os
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

load_dotenv()


def get_connection():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set (see .env.example)")
    return psycopg2.connect(url)


def init_db():
    """Create all tables, including the append-only audit_log."""
    import audit  # imported here to avoid a circular import

    schema = (Path(__file__).parent / "schema.sql").read_text()
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(schema)
    finally:
        conn.close()
    audit.init_audit_table()


def fetch_all(sql, params=()):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()


def fetch_one(sql, params=()):
    rows = fetch_all(sql, params)
    return rows[0] if rows else None


def execute(sql, params=()):
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(sql, params)
    finally:
        conn.close()


def execute_returning(sql, params=()):
    """Run a write that has RETURNING <col>; give back the first column or None."""
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return row[0] if row else None
    finally:
        conn.close()
