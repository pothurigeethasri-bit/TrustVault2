# PROMPTS.md — AI assistance log
| Date | Prompt (summary) | What I used / changed |
|------|------------------|-----------------------|
| 2026-11-05 | Asked for the audit module (append-only log, hash chain, admin/owner queries) | Used audit.py; replaced the DB role name with my own |
| 2026-11-05 | Asked for step-by-step project setup and schema | Used schema.sql, database.py, setup_db.py |
| 2026-11-06 | Asked to continue from Step 5: admin dashboard, then Step 6: automated security tests against a real database, THREATS.md, restricted DB user, Render deployment | Used admin_panel.py and the admin templates, tests/ (access control, audit, admin, storage), storage.py, harden_db.py, THREATS.md, render.yaml. (Add what you checked or changed yourself.) |
| 2026-11-07 | Asked for API docs, throttling by IP and username, admin + user password reset, a security PIN in front of login/register for the live link, Spotify theme, tests and audit | Used pin_gate.py, auth.py/admin_panel.py changes, templates, style.css, API.md, DEPLOY.md, tests/test_pin_gate.py, test_throttle.py, test_password_reset.py. (Add what you reviewed or changed yourself; the DB tests have not been run in the AI sandbox, so run `pytest` with TEST_DATABASE_URL.) |
| 2026-11-07 | Asked for completely robust e-mail verification: user enters an e-mail first, gets a link by SMTP, and can only choose a username after verifying | Used mailer.py, verification.py, the register/complete/confirm routes in auth.py, new templates, schema.sql (`email_tokens`, `email_verified_at`), tests/test_email_verification.py and test_mailer.py. The AI sandbox had no PostgreSQL, so only the mailer and the route logic (against an in-memory stand-in) were run there; the SQL and the database tests must be run with `pytest` and TEST_DATABASE_URL. (Add what you reviewed or changed yourself.) |

Add your own earlier entries honestly, with their real dates. The brief requires at least five genuine entries.
