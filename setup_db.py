"""One-time setup: create tables and seed the demo accounts.
Usage:  python setup_db.py
"""
import os

from werkzeug.security import generate_password_hash

from database import get_connection, init_db

DEMO_USERS = [
    ("admin", "admin"),
    ("geetha", "owner"),
    ("meena", "owner"),
    ("ravi", "viewer"),
    ("sita", "viewer"),
]


def seed():
    password = os.environ.get("SEED_PASSWORD", "ChangeMe123!")
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            for username, role in DEMO_USERS:
                cur.execute(
                    "INSERT INTO users (username, password_hash, role) "
                    "VALUES (%s, %s, %s) ON CONFLICT (username) DO NOTHING",
                    (username, generate_password_hash(password), role),
                )
    finally:
        conn.close()


if __name__ == "__main__":
    # Setup needs table-creation rights. If the app itself runs as a restricted role
    # (see harden_db.py), point SETUP_DATABASE_URL at the owner account.
    if os.environ.get("SETUP_DATABASE_URL"):
        os.environ["DATABASE_URL"] = os.environ["SETUP_DATABASE_URL"]
    init_db()
    seed()
    print("Database ready. Demo users: admin, geetha + meena (owners), ravi + sita (viewers).")
