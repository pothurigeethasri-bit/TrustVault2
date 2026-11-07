"""Create a least-privilege database role for the running app, so the audit log is
protected at the database level, not only by the application code.

The app role can SELECT and INSERT into audit_log but can NOT update, delete or
truncate it, cannot drop the immutability triggers (only the table owner can), and
cannot create or alter tables.

Run ONCE, as the database owner, after setup_db.py:

    OWNER_DATABASE_URL=postgresql://owner:pw@host/db APP_DB_PASSWORD='long-random' \\
        python harden_db.py

then give the web app the printed DATABASE_URL (keep the owner URL only for
setup_db.py, via SETUP_DATABASE_URL). If your host does not let the owner create
roles, skip this: the triggers and the hash chain still make tampering detectable.
"""
import os
import sys

import psycopg2
from psycopg2 import sql
from urllib.parse import quote, urlsplit, urlunsplit

APP_TABLES = ("users", "categories", "documents", "permissions", "file_blobs", "email_tokens")


def apply_grants(cur, role):
    r = sql.Identifier(role)
    cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(r))
    cur.execute(sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {}").format(r))
    cur.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON {} TO {}").format(
        sql.SQL(", ").join(sql.Identifier(t) for t in APP_TABLES), r))
    cur.execute(sql.SQL("GRANT SELECT, INSERT ON audit_log TO {}").format(r))   # append-only
    cur.execute(sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}").format(r))


def create_role(cur, role, password):
    cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,))
    verb = "ALTER" if cur.fetchone() else "CREATE"
    cur.execute(sql.SQL(verb + " ROLE {} LOGIN PASSWORD %s NOSUPERUSER NOCREATEDB NOCREATEROLE")
                .format(sql.Identifier(role)), (password,))


def app_url(owner_url, role, password):
    """The owner's connection URL with the restricted role's credentials swapped in."""
    p = urlsplit(owner_url)
    host = p.hostname or ""
    host = f"[{host}]" if ":" in host else host
    netloc = f"{quote(role, safe='')}:{quote(password, safe='')}@{host}" + (f":{p.port}" if p.port else "")
    return urlunsplit((p.scheme, netloc, p.path, p.query, p.fragment))


def main():
    owner_url = os.environ.get("OWNER_DATABASE_URL") or os.environ.get("DATABASE_URL")
    password = os.environ.get("APP_DB_PASSWORD")
    role = os.environ.get("APP_DB_USER", "trustvault_app")
    if not owner_url or not password:
        sys.exit("Set OWNER_DATABASE_URL (or DATABASE_URL) and APP_DB_PASSWORD.")
    conn = psycopg2.connect(owner_url)
    try:
        with conn, conn.cursor() as cur:
            create_role(cur, role, password)
            apply_grants(cur, role)
    except psycopg2.errors.InsufficientPrivilege:
        sys.exit("This database user may not create roles. Skipping is fine: the audit log "
                 "still has its immutability triggers and hash chain.")
    finally:
        conn.close()
    print("Done. Use this as the web app's DATABASE_URL:")
    print(app_url(owner_url, role, password))


if __name__ == "__main__":
    main()
