# TrustVault: project write-up

## What it is
TrustVault is a web app for sharing confidential documents (for example a salary letter) with exactly the people who should see them, for exactly as long as they should, and with proof of who did what. Built with Flask and PostgreSQL, deployable to Render.

## The problem and the approach
Document sharing usually fails in three places: a link that keeps working after access is withdrawn, a "hidden button" that is the only thing stopping a user, and logs that can be quietly edited. TrustVault treats the server as the only authority:

- **Permissions are checked on every request.** Role, active status and access level are read from the database each time, so revoking access, demoting a user or deactivating an account takes effect on the very next request. There are no access tokens and no cached permission lists.
- **Three roles with clear limits.** Admin (manages users, sees the audit trail, cannot read other people's files), Document Owner (uploads, organises, shares, revokes) and Viewer (opens what was shared). Sharing has three separate levels: view only, view + download, and edit.
- **Files are private.** They are never served from `static/`, stored under random names, validated by content (not just extension), and capped at 10 MB. A missing document and a forbidden one return the same 403, so ids cannot be used to discover what exists.
- **A tamper-evident audit log.** Every action, including failures and denials, is written to an append-only table. Database triggers reject UPDATE, DELETE and TRUNCATE, and each row carries a SHA-256 hash chained to the previous row; the admin console can re-verify the whole chain.

## Sign-up and account security
- **Verified sign-up.** A visitor enters only an e-mail address. A one-time link (256-bit random, only its hash is stored, single use, 30 minutes) is sent by SMTP. No account and no username exists until the link is used. Opening the link does not consume it, so mail scanners cannot burn it.
- **No enumeration.** The sign-up page looks identical whether or not the address is registered. Links are always built from `APP_BASE_URL`, never from the request's Host header.
- **Abuse limits.** Throttling by IP and by account for sign-in, PIN entry, sign-up and password reset, all computed from the audit log. An optional security PIN hides the login and register pages from anyone without it.
- **Other defences.** CSRF tokens on every POST, strict CSP and security headers, parameterised SQL, escaped output, session invalidation on password change, and admin password reset with a one-time temporary password.

## How it was verified
The test suite runs the real app against a real PostgreSQL database and covers each threat in `THREATS.md` (38 entries, each linked to the code that defends it and the test that proves it). Pure unit tests (mailer, validation, passwords) run without a database.

## Known limitations
Listed honestly in `THREATS.md`: no per-user MFA (the PIN is a shared perimeter secret), the audit chain is tamper-evident but not proof against a database owner who can recompute it, view-only is an application rule rather than DRM, uploads are type-checked but not malware-scanned, and password reset is admin-mediated.

## Documentation
- `API.md`: every HTTP route, parameters, responses, rate limits and audit actions
- `README.md`: setup, tests, schema, deployment
- `THREATS.md`: threat table and limitations
- `DEPLOY.md`: go-live and e-mail setup
- `PROMPTS.md`: AI assistance log
