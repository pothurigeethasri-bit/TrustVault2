# TrustVault HTTP API

TrustVault is a server-rendered app: every endpoint below is an HTML route used by the browser (form posts, redirects).
There is no JSON API and no API token; authentication is the session cookie.

## Conventions
- **Session cookie**: `HttpOnly`, `SameSite=Lax`, `Secure` in production, 30-minute lifetime.
- **PIN gate** (when `ACCESS_PIN` is set): every route except `/pin`, `/healthz` and `/static/*` answers `302 -> /pin` until the PIN is entered.
- **CSRF**: every `POST` needs `csrf_token` (form field) or `X-CSRF-Token` header, matching the session. Otherwise `400` and a `CSRF_FAILURE` audit row.
- **Roles**: `admin`, `owner`, `viewer`. Not signed in: `302 -> /login`. Wrong role: `403` + `ACCESS_DENIED` audit row.
- **Errors**: `400` bad input, `401` bad credentials/PIN, `403` not allowed (also used for "does not exist" on documents), `404` page not found, `413` file too large, `429` throttled.
- **Rate limits** (all computed from the append-only audit log; blocked requests return `429` and a `THROTTLED`/`DENIED` row):

| Scope | Limit (default) | Key |
|---|---|---|
| Wrong PIN | 5 / 15 min | IP |
| Failed login | 5 / 15 min | username (cleared by a successful login or a password reset) |
| Failed login | 10 / 15 min | IP (counts all usernames, never reset by a success) |
| Registration | 5 / hour | IP |
| Reset request | 5 / hour | IP |
| Wrong current password on change | 5 / 15 min | username and IP |

## Public
| Method & path | Parameters | Responses |
|---|---|---|
| `GET /healthz` | - | `200 ok` (monitoring; always open) |
| `GET /pin` / `POST /pin` | `pin`, `csrf_token`; optional `?next=/path` (same-site paths only) | `302` to `next` or `/login`; `401` wrong PIN; `429` too many wrong PINs |
| `GET/POST /login` | `email` (a legacy `username` is also accepted), `password` | `302 -> /dashboard`; `401` same message for every cause; `429` throttled |
| `GET/POST /register` | `email`, `username` (display name, 3-30 of `a-z0-9_.-`), `password`, `confirm` | `302 -> /login`; `400` invalid; `429`. Always creates a **viewer** |
| `GET/POST /forgot-password` | `email` (or legacy `username`) | `302 -> /login` with an identical message whether or not the account exists; `429` |

## Any signed-in user
| Method & path | Parameters | Responses |
|---|---|---|
| `POST /logout` | - | `302 -> /login` |
| `GET/POST /account/email` | `email`, `current` (password) | Signed in. `302` saved; `400` invalid or taken; `401` wrong password; `429` throttled. Audited as `CHANGE_EMAIL` |
| `GET /dashboard` | - | `302` to `/admin`, `/owner` or `/viewer` by role |
| `GET/POST /account/password` | `current`, `new`, `confirm` | `302` success (other sessions ended); `401` wrong current; `400` mismatch/same/weak; `429` |

After an admin reset, every route except this one and `/logout` redirects here until the password is changed.

## Documents
| Method & path | Role | Parameters | Notes |
|---|---|---|---|
| `GET /owner`, `GET /viewer` | owner / viewer | `q`, `category`, `owner`, `date_from`, `date_to` (`YYYY-MM-DD`) | Search own / shared documents |
| `POST /documents/upload` | owner | multipart `file`, optional `category_id` | Type, content, size checked; `302` or `400` |
| `POST /categories` | owner | `name` | |
| `GET /documents/<id>/view` | view access or higher | - | `200` file shown inline; `403` otherwise (missing and forbidden look identical). Types a browser cannot preview need download access |
| `GET /documents/<id>/download` | download access or higher | - | `200` attachment; `403` for view-only users |
| `POST /documents/<id>/category` | owner | `category_id` (blank = none) | Moves the document to one of the owner's own categories; audited as `CHANGE_CATEGORY` |
| `GET/POST /documents/<id>/edit` | edit access | `name`, optional `file` | Owner or granted editor |
| `POST /documents/<id>/delete` | owner | - | |
| `GET /documents/<id>/share` | owner | - | Access list and per-document history |
| `POST /documents/<id>/grant` | owner | `user_id`, `access_level` = `view`/`download`/`edit` | `edit` cannot be given to a viewer-role account; `view` only for previewable types |
| `POST /documents/<id>/revoke` | owner | `user_id` | Takes effect on the very next request |

## Admin (all `admin` role only)
| Method & path | Parameters | Notes |
|---|---|---|
| `GET /admin` | - | Overview and counters |
| `GET /admin/alerts` | - | Locked accounts, IPs with repeated failures, latest failed sign-ins |
| `GET /admin/users` | - | Users, emails, roles, status, "reset requested" flags |
| `GET /admin/activity`, `/permissions`, `/security`, `/audit` | `user`, `result`, `action` (audit only), `page` | Filterable, paginated feeds (50/page) |
| `POST /admin/users/<id>/role` | `role` | Not on yourself |
| `POST /admin/users/<id>/active` | `active` = `1`/`0` | Not on yourself; deactivation signs the user out |
| `POST /admin/users/<id>/reset-password` | - | Returns `200` showing a one-time temporary password **once**. Hash stored, never logged. User must change it; their sessions end; lockout cleared. Not on yourself |
| `POST /admin/integrity` | - | Re-verifies the whole hash chain |

## Audit actions recorded
`PIN_ATTEMPT`, `LOGIN`, `LOGOUT`, `REGISTER_USER`, `THROTTLED`, `PASSWORD_CHANGE`, `PASSWORD_RESET_REQUEST`, `PASSWORD_RESET_ADMIN`,
`UPLOAD_DOCUMENT`, `VIEW_DOCUMENT`, `DOWNLOAD_DOCUMENT`, `EDIT_DOCUMENT`, `DELETE_DOCUMENT`, `GRANT_ACCESS`, `REVOKE_ACCESS`,
`CHANGE_ROLE`, `CHANGE_CATEGORY`, `CHANGE_EMAIL`, `DEACTIVATE_USER`, `ACTIVATE_USER`, `CREATE_CATEGORY`, `FILE_VALIDATION`, `ACCESS_DENIED`, `CSRF_FAILURE`, `AUDIT_INTEGRITY_CHECK`.
Each row has result `SUCCESS`/`DENIED`/`FAILURE`, IP address, and a hash chained to the previous row. PINs and passwords are never stored in it.
