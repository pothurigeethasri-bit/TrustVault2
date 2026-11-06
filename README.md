# TrustVault — Secure Document Sharing with a Real Audit Trail

Flask + PostgreSQL app with three roles (Admin, Document Owner, Viewer),
server-side permission checks on every file access, and a tamper-evident audit log.

## Setup
1. `python -m venv venv && source venv/bin/activate` (Windows: `venv\Scripts\activate`)
2. `pip install -r requirements.txt`
3. Create a PostgreSQL database named `trustvault`.
4. Copy `.env.example` to `.env` and fill in the values.
5. `python setup_db.py`  (creates tables and demo users)
6. Run tests: `pytest`

## Project status
- [x] Step 1: Setup, schema, audit module
- [x] Step 2: Authentication and roles
- [x] Step 3: Document upload and management
- [x] Step 4: Permissions, grant and revoke
- [ ] Step 5: Admin dashboard and owner history
- [ ] Step 6: Security tests, THREATS.md, deployment
- [ ] Step 7: API docs, demo video, write-up

## Run the app
`python app.py`  then open http://127.0.0.1:5000

Demo accounts (password = SEED_PASSWORD from .env): `admin`, `geetha` (owner), `ravi`, `sita` (viewers).
