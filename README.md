# TrustVault — Secure Document Sharing with a Real Audit Trail

Flask + PostgreSQL app with a security-PIN gate, IP + account throttling, **email-verified sign-up**, email sign-in, password reset, admin security alerts, three roles (Admin, Document Owner, Viewer), server-side permission
checks on every file request, immediate revocation, and a tamper-evident, append-only audit log.

## Roles
| Role | Can do |
|------|--------|
| **Admin** | Manage users and roles, deactivate accounts, view document activity, permission changes and security events, **see live security alerts (locked accounts, repeated failed sign-ins, noisy IP addresses)**, run the audit integrity check. Cannot read other people's documents. |
| **Document Owner** | Upload documents, create categories and **move documents between categories**, search own documents, give **view-only / view + download / view + download + edit** access, revoke access, see each document's access history. |
| **Viewer** | Open documents shared with them, as far as the owner allowed: **view only**, **view + download**. Can search them. Cannot edit, delete or share. |

## Setup (local)
1. `python -m venv venv && source venv/bin/activate` (Windows: `venv\Scripts\activate`)
2. `pip install -r requirements.txt`
3. Create a PostgreSQL database named `trustvault`.
4. Copy `.env.example` to `.env` (set `ACCESS_PIN` to try the PIN gate locally) and fill in the values (a long random `SECRET_KEY` is required). For real verification e-mails fill in the `SMTP_*` settings and `APP_BASE_URL`; with no `SMTP_HOST` (local dev only) the e-mail, including its link, is printed in the server console instead.
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
| `tests/test_pin_gate.py` | Login/register hidden until the PIN is entered, PIN throttling per IP, no open redirect, PIN rotation re-locks, production needs a PIN |
| `tests/test_throttle.py` | Limits by username AND IP (login, register, reset requests, password change) |
| `tests/test_password_reset.py` | User change, admin reset (one-time password, forced change, sessions ended, lockout cleared), forgot-password, audit |
| `tests/test_storage.py` | The database file-storage backend, with the same permission checks |
| `tests/test_email_verification.py` | Nothing is created before the link is used; links are single-use, expiring, hashed, race-safe; no enumeration; resend limits; mail failures; e-mail change confirmation; audit |
| `tests/test_mailer.py` | SMTP behaviour (STARTTLS before login, refused recipients, timeouts), start-up checks, links built from `APP_BASE_URL` (no database needed) |
| `tests/test_validation.py`, `tests/test_passwords.py` | File validation and password rules |

## Database schema
Defined in `schema.sql` (created by `python setup_db.py`); the audit table and its triggers are in `audit.py`.

| Table | Purpose | Key columns |
|-------|---------|-------------|
| `users` | Accounts | `username` (unique display name), `email` (unique, used to sign in), `email_verified_at`, `password_hash`, `role` (admin/owner/viewer), `is_active` |
| `email_tokens` | One-time verification links (sign-up and e-mail change) | `token_hash` (SHA-256; the token itself is never stored), `purpose`, `email`, `user_id`, `expires_at`, `used_at` |
| `categories` | Owner-defined folders | `owner_id`, `name` (unique per owner) |
| `documents` | File metadata | `owner_id`, `category_id`, `original_name`, `stored_name` (random), `mime_type`, `size_bytes`, `sha256` |
| `permissions` | Who can open what | `document_id`, `user_id`, `access_level` (view / download / edit), `granted_by`. Revoking deletes the row. |
| `file_blobs` | File bytes when `STORAGE_BACKEND=db` | `stored_name`, `data` |
| `audit_log` | Append-only audit trail | `ts`, `username`, `action`, `document_id`, `target_user_id`, `result` (SUCCESS/DENIED/FAILURE), `ip_address`, `details`, `prev_hash`, `row_hash` |

## Security design in brief
- Documents are stored privately (never under `static/`, no public URLs); every view and download is permission-checked on the server.
- Permissions, role and active status are read from the database on every request, so revoke, demotion and deactivation take effect on the next request.
- `audit_log`: database triggers block UPDATE/DELETE/TRUNCATE; each row is hash-chained; the admin console can re-verify the chain. `harden_db.py` optionally creates an app role that can only SELECT/INSERT on it.
- Full threat list with the test for each defence: **[THREATS.md](THREATS.md)**.

Full go-live and link-sharing guide: **[DEPLOY.md](DEPLOY.md)**. HTTP endpoints: **[API.md](API.md)**.

## Deploy to Render
1. Push the repo to GitHub.
2. In Render: **New + > Blueprint**, choose the repo. `render.yaml` creates the web service and a PostgreSQL database and sets the environment (including `STORAGE_BACKEND=db`, because Render's disk is wiped on each deploy).
3. When asked, enter `SEED_PASSWORD` (demo account password; strong) and `ACCESS_PIN` (the security PIN visitors must enter before login/register; required in production).
4. After the first deploy, open the site URL and sign in with the demo **emails** `admin@trustvault.demo`, `geetha@trustvault.demo` and `ravi@trustvault.demo` (one per role). Accounts created before email login keep working with their username until the person adds an email under **Email** in the top bar.
5. Optional hardening: `OWNER_DATABASE_URL=<external DB url> APP_DB_PASSWORD=<long random> python harden_db.py`, then set the printed URL as `DATABASE_URL` and the owner URL as `SETUP_DATABASE_URL`.

## Project status
- [x] Step 1: Setup, schema, audit module
- [x] Step 2: Authentication and roles
- [x] Step 3: Document upload and management
- [x] Step 4: Permissions, grant and revoke
- [x] Step 5: Admin dashboard (users and roles, activity, permission changes, security events, integrity check)
- [x] Step 6: Security tests, THREATS.md, deployment config
- [x] Step 7a: API docs (`API.md`), go-live guide (`DEPLOY.md`), PIN gate, IP + username throttling, password reset, Spotify theme
- [x] Step 7b: write-up (`WRITEUP.md`)
- [ ] Demo video

## What changed in the final version
- **Verified sign-up.** Registering asks for the email only. A one-time link (works once, 30 minutes) is mailed over SMTP; after opening it the person chooses a username and password, and only then is the account created. Changing the sign-in email later works the same way (a link to the new address). See *Set up e-mail* in DEPLOY.md.
- **Email sign-in.** Register with an email (unique, stored lower-case). The login box takes the email; an old account without an email can still type its username, then add an email under *Email*. Lockout and audit rows are shared between the two ways of signing in. 
- **Separate permissions.** `view` (opens in the browser only; no Download button and `/download` is refused), `download` (view + download) and `edit` (view + download + rename/replace, Owner-role accounts only). Old `read` rows are migrated to `download` automatically by `schema.sql`. View-only is only offered for types a browser can preview (PDF, PNG, JPG, TXT).
- **Organise documents.** Owners create categories and can move any of their documents to another category (or none) from the document list.
- **Admin alerts.** *Admin > Alerts* (with a badge on the tab and banners on the Overview) shows accounts locked out right now, IP addresses with repeated failed sign-ins, the latest failed sign-ins and waiting password-reset requests. They are read from the audit log, so nothing extra to maintain. Thresholds: `ALERT_FAILED_LOGINS_24H` (default 5) and `ALERT_IP_FAILURES_24H` (default 5).
