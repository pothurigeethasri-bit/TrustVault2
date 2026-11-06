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
