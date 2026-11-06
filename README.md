# TrustVault — Secure Document Sharing with a Real Audit Trail

Flask + PostgreSQL app with three roles (Admin, Document Owner, Viewer), server-side permission
checks on every file request, immediate revocation, and a tamper-evident, append-only audit log.

## Roles
| Role | Can do |
|------|--------|
| **Admin** | Manage users and roles, deactivate accounts, view document activity, permission changes and security events, run the audit integrity check. Cannot read other people's documents. |
| **Document Owner** | Upload documents, create categories, search own documents, give read/edit access, revoke access, see each document's access history. |
| **Viewer** | View and download documents shared with them, and search them. Cannot edit, delete or share. |

## Setup (local)
1. `python -m venv venv && source venv/bin/activate` (Windows: `venv\Scripts\activate`)
2. `pip install -r requirements.txt`
3. Create a PostgreSQL database named `trustvault`.
4. Copy `.env.example` to `.env` and fill in the values (a long random `SECRET_KEY` is required).
5. `python setup_db.py` creates the tables and the demo users.
6. `python app.py`, then open http://127.0.0.1:5000

Demo accounts (password = `SEED_PASSWORD`): `admin`, `geetha` and `meena` (owners), `ravi` and `sita` (viewers).

## Automated tests
The security tests run the real app against a real PostgreSQL database.
1. Create an empty database whose name contains `test`, e.g. `createdb trustvault_test`.
2. Set `TEST_DATABASE_URL` (the schema is **dropped and recreated** on each run, so never use real data):
   `export TEST_DATABASE_URL=postgresql://user:pw@localhost:5432/trustvault_test`
3. `pytest`  (without `TEST_DATABASE_URL` only the pure unit tests run; the database tests are skipped)

| File | What it proves |
|------|----------------|
| `tests/test_access_control.py` | Unauthorised users and anonymous visitors are blocked, direct file URLs fail, revoke is immediate, viewers cannot edit/delete/share, CSRF, lockout, SQL injection, bad uploads |
| `tests/test_audit.py` | Every action (including failures) is logged, audit rows cannot be changed or deleted, tampering is detected, the restricted DB role cannot touch the log |
| `tests/test_admin.py` | Admin-only access, role changes and deactivation take effect at once and are logged, feeds and filters, XSS escaping |
| `tests/test_storage.py` | The database file-storage backend, with the same permission checks |
| `tests/test_validation.py`, `tests/test_passwords.py` | File validation and password rules |

## Database schema
Defined in `schema.sql` (created by `python setup_db.py`); the audit table and its triggers are in `audit.py`.

| Table | Purpose | Key columns |
|-------|---------|-------------|
| `users` | Accounts | `username` (unique), `password_hash`, `role` (admin/owner/viewer), `is_active` |
| `categories` | Owner-defined folders | `owner_id`, `name` (unique per owner) |
| `documents` | File metadata | `owner_id`, `category_id`, `original_name`, `stored_name` (random), `mime_type`, `size_bytes`, `sha256` |
| `permissions` | Who can open what | `document_id`, `user_id`, `access_level` (read/edit), `granted_by`. Revoking deletes the row. |
| `file_blobs` | File bytes when `STORAGE_BACKEND=db` | `stored_name`, `data` |
| `audit_log` | Append-only audit trail | `ts`, `username`, `action`, `document_id`, `target_user_id`, `result` (SUCCESS/DENIED/FAILURE), `ip_address`, `details`, `prev_hash`, `row_hash` |

## Security design in brief
- Documents are stored privately (never under `static/`, no public URLs); every view and download is permission-checked on the server.
- Permissions, role and active status are read from the database on every request, so revoke, demotion and deactivation take effect on the next request.
- `audit_log`: database triggers block UPDATE/DELETE/TRUNCATE; each row is hash-chained; the admin console can re-verify the chain. `harden_db.py` optionally creates an app role that can only SELECT/INSERT on it.
- Full threat list with the test for each defence: **[THREATS.md](THREATS.md)**.

## Deploy to Render
1. Push the repo to GitHub.
2. In Render: **New + > Blueprint**, choose the repo. `render.yaml` creates the web service and a PostgreSQL database and sets the environment (including `STORAGE_BACKEND=db`, because Render's disk is wiped on each deploy).
3. When asked, enter `SEED_PASSWORD` (the password for the demo accounts; use a strong one).
4. After the first deploy, open the site URL and sign in as `admin`, `geetha` and `ravi` (one per role).
5. Optional hardening: `OWNER_DATABASE_URL=<external DB url> APP_DB_PASSWORD=<long random> python harden_db.py`, then set the printed URL as `DATABASE_URL` and the owner URL as `SETUP_DATABASE_URL`.

## Project status
- [x] Step 1: Setup, schema, audit module
- [x] Step 2: Authentication and roles
- [x] Step 3: Document upload and management
- [x] Step 4: Permissions, grant and revoke
- [x] Step 5: Admin dashboard (users and roles, activity, permission changes, security events, integrity check)
- [x] Step 6: Security tests, THREATS.md, deployment config
- [ ] Step 7: API documentation, demo video, write-up
