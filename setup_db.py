"""One-time setup: create tables and seed the demo accounts.
Usage:  python setup_db.py
"""
import os

from werkzeug.security import generate_password_hash

from database import get_connection, init_db

DEMO_USERS = [
    ("admin", "admin", "admin@trustvault.demo"),
    ("geetha", "owner", "geetha@trustvault.demo"),
    ("meena", "owner", "meena@trustvault.demo"),
    ("ravi", "viewer", "ravi@trustvault.demo"),
    ("sita", "viewer", "sita@trustvault.demo"),
]


def seed():
    password = os.environ.get("SEED_PASSWORD", "ChangeMe123!")
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            for username, role, email in DEMO_USERS:
                # Existing demo accounts keep their password; they just gain an email if
                # they did not have one, so they can sign in with it.
                cur.execute(
                    "INSERT INTO users (username, password_hash, role, email) "
                    "VALUES (%s, %s, %s, %s) ON CONFLICT (username) DO UPDATE "
                    "SET email = COALESCE(users.email, EXCLUDED.email)",
                    (username, generate_password_hash(password), role, email),
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
    print("Database ready. Sign in with the email addresses below (password = SEED_PASSWORD):")
    for username, role, email in DEMO_USERS:
        print(f"  {email:28} {role}")
