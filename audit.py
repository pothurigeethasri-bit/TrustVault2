"""
audit.py - TrustVault audit trail.

Design:
  * Append-only: DB triggers reject UPDATE / DELETE / TRUNCATE, even from the app user.
  * Tamper-evident: each row stores a SHA-256 hash chained to the previous row,
    so edits made by a superuser (who can drop triggers) are still detectable
    with verify_chain().
  * Failed/denied attempts are logged on their own connection, so they persist
    even if the request's main transaction rolls back.

Assumes database.get_connection() returns a new psycopg2 connection.
"""
import hashlib
from datetime import datetime, timezone

from database import get_connection  # your existing module

# ---- Action and result constants (use these everywhere, avoid raw strings) ----
LOGIN = "LOGIN"
LOGOUT = "LOGOUT"
UPLOAD = "UPLOAD_DOCUMENT"
VIEW = "VIEW_DOCUMENT"
DOWNLOAD = "DOWNLOAD_DOCUMENT"
EDIT = "EDIT_DOCUMENT"
DELETE_DOC = "DELETE_DOCUMENT"
GRANT = "GRANT_ACCESS"
REVOKE = "REVOKE_ACCESS"
ROLE_CHANGE = "CHANGE_ROLE"
VALIDATION_FAIL = "FILE_VALIDATION"
REGISTER = "REGISTER_USER"
ACCESS_DENIED = "ACCESS_DENIED"
CSRF_FAILURE = "CSRF_FAILURE"
CREATE_CATEGORY = "CREATE_CATEGORY"
DEACTIVATE_USER = "DEACTIVATE_USER"
ACTIVATE_USER = "ACTIVATE_USER"
INTEGRITY_CHECK = "AUDIT_INTEGRITY_CHECK"
PIN_ATTEMPT = "PIN_ATTEMPT"                  # security-PIN gate in front of login/register
PASSWORD_CHANGE = "PASSWORD_CHANGE"          # user changes their own password
PASSWORD_RESET_ADMIN = "PASSWORD_RESET_ADMIN"      # admin issues a temporary password
PASSWORD_RESET_REQUEST = "PASSWORD_RESET_REQUEST"  # user asks an admin for a reset
THROTTLED = "THROTTLED"                      # request refused by an IP rate limit
CATEGORY_CHANGE = "CHANGE_CATEGORY"          # owner moves a document to another category
EMAIL_CHANGE = "CHANGE_EMAIL"                # user sets / changes their sign-in e-mail

# Which actions belong on which admin screen.
DOCUMENT_ACTIONS = (UPLOAD, VIEW, DOWNLOAD, EDIT, DELETE_DOC, CATEGORY_CHANGE)
PERMISSION_ACTIONS = (GRANT, REVOKE, ROLE_CHANGE, DEACTIVATE_USER, ACTIVATE_USER,
                      PASSWORD_RESET_ADMIN, PASSWORD_CHANGE, EMAIL_CHANGE)
# Events that clear a username lockout (a successful reset gives a clean slate).
RESET_ACTIONS = (PASSWORD_RESET_ADMIN, PASSWORD_CHANGE)

SUCCESS, DENIED, FAILURE = "SUCCESS", "DENIED", "FAILURE"

GENESIS_HASH = "0" * 64

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL,
    user_id        INTEGER,                 -- no FK: logs must outlive users
    username       TEXT NOT NULL,
    action         TEXT NOT NULL,
    document_id    INTEGER,                 -- no FK: logs must outlive documents
    target_user_id INTEGER,                 -- e.g. who was granted/revoked
    result         TEXT NOT NULL CHECK (result IN ('SUCCESS','DENIED','FAILURE')),
    ip_address     TEXT,
    details        TEXT,
    prev_hash      TEXT NOT NULL,
    row_hash       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_doc  ON audit_log (document_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log (user_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_res  ON audit_log (result, ts DESC);

CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_no_update_delete ON audit_log;
CREATE TRIGGER audit_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

DROP TRIGGER IF EXISTS audit_no_truncate ON audit_log;
CREATE TRIGGER audit_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();
"""

# Run once as the DB owner/superuser. Replace trustvault_app with your app's DB role.
# The app role should only INSERT and SELECT on audit_log.
GRANTS_SQL = """
REVOKE ALL ON audit_log FROM trustvault_app;
GRANT SELECT, INSERT ON audit_log TO trustvault_app;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO trustvault_app;
"""


def init_audit_table():
    """Create the table and immutability triggers. Call from your DB setup script."""
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------
def _compute_hash(prev_hash, ts, user_id, username, action, document_id,
                  target_user_id, result, ip_address, details):
    ts_str = ts.astimezone(timezone.utc).isoformat()
    parts = [prev_hash, ts_str, user_id, username, action, document_id,
             target_user_id, result, ip_address, details]
    payload = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------
def log_event(action, result, user=None, username=None, document_id=None,
              target_user_id=None, ip_address=None, details=None):
    """
    Record one audit event. Never raises into the request path for normal
    failures other than DB errors; callers should treat an audit failure as
    serious (fail closed for sensitive actions if you prefer).

    user:     dict/obj with 'id' and 'username' (optional)
    username: used when no user exists (e.g. failed login for unknown name)
    """
    if result not in (SUCCESS, DENIED, FAILURE):
        raise ValueError(f"invalid result: {result}")

    user_id = None
    if user is not None:
        user_id = user["id"] if isinstance(user, dict) else getattr(user, "id", None)
        if username is None:
            username = user["username"] if isinstance(user, dict) else getattr(user, "username", None)
    username = username or "anonymous"

    # Truncate untrusted free text so it can't bloat the log.
    if details is not None:
        details = str(details)[:500]
    if username:
        username = str(username)[:150]

    ts = datetime.now(timezone.utc)

    # Own connection => commits independently of the request's transaction.
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            # Serialise writers so the hash chain stays linear.
            cur.execute("SELECT pg_advisory_xact_lock(727001)")
            cur.execute("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            prev_hash = row[0] if row else GENESIS_HASH

            row_hash = _compute_hash(prev_hash, ts, user_id, username, action,
                                     document_id, target_user_id, result,
                                     ip_address, details)
            cur.execute(
                """INSERT INTO audit_log
                   (ts, user_id, username, action, document_id, target_user_id,
                    result, ip_address, details, prev_hash, row_hash)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (ts, user_id, username, action, document_id, target_user_id,
                 result, ip_address, details, prev_hash, row_hash),
            )
    finally:
        conn.close()


def client_ip(request):
    """Best-effort client IP for Flask. Behind Render's proxy, configure
    werkzeug ProxyFix instead of trusting X-Forwarded-For blindly."""
    return request.remote_addr


# --------------------------------------------------------------------------
# Reading (admin + owner views)
# --------------------------------------------------------------------------
_COLS = ("id, ts, user_id, username, action, document_id, target_user_id, "
         "result, ip_address, details")


def _fetch(sql, params):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
    finally:
        conn.close()


def get_recent_events(limit=100, offset=0, action=None, result=None, username=None):
    """Admin: filterable activity feed."""
    where, params = [], []
    if action:
        where.append("action = %s"); params.append(action)
    if result:
        where.append("result = %s"); params.append(result)
    if username:
        where.append("username = %s"); params.append(username)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    params += [min(int(limit), 500), int(offset)]
    return _fetch(
        f"SELECT {_COLS} FROM audit_log {clause} ORDER BY id DESC LIMIT %s OFFSET %s",
        params)


def get_security_events(limit=100):
    """Admin: denied and failed attempts only."""
    return _fetch(
        f"SELECT {_COLS} FROM audit_log WHERE result <> 'SUCCESS' "
        "ORDER BY id DESC LIMIT %s", (min(int(limit), 500),))


def get_permission_changes(limit=100):
    """Admin: grants, revokes, role changes and account (de)activations."""
    return _fetch(
        f"SELECT {_COLS} FROM audit_log WHERE action = ANY(%s) "
        "ORDER BY id DESC LIMIT %s", (list(PERMISSION_ACTIONS), min(int(limit), 500)))


def search_events(actions=None, only_problems=False, result=None, username=None,
                  limit=50, offset=0):
    """Admin screens: filterable, paginated feed.

    Returns (rows, total). Each row also carries `target_username` (who was
    granted/revoked/changed) and `document_name` (None if the document has
    since been deleted - the audit row itself is never touched).
    `only_problems` keeps DENIED and FAILURE rows (the security-events view).
    """
    where, params = [], []
    if actions:
        where.append("a.action = ANY(%s)"); params.append(list(actions))
    if only_problems:
        where.append("a.result <> 'SUCCESS'")
    if result in (SUCCESS, DENIED, FAILURE):
        where.append("a.result = %s"); params.append(result)
    if username:
        where.append("a.username ILIKE %s ESCAPE '\\'")
        params.append("%" + username.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    limit, offset = max(1, min(int(limit), 200)), max(0, int(offset))
    total = _fetch(f"SELECT count(*) AS n FROM audit_log a {clause}", params)[0]["n"]
    rows = _fetch(
        "SELECT a.id, a.ts, a.user_id, a.username, a.action, a.document_id, "
        "a.target_user_id, a.result, a.ip_address, a.details, "
        "t.username AS target_username, d.original_name AS document_name "
        "FROM audit_log a "
        "LEFT JOIN users t ON t.id = a.target_user_id "
        "LEFT JOIN documents d ON d.id = a.document_id "
        f"{clause} ORDER BY a.id DESC LIMIT %s OFFSET %s", params + [limit, offset])
    return rows, total


def activity_summary(hours=24):
    """Admin overview counters for the last `hours` hours."""
    rows = _fetch(
        """SELECT count(*) AS events,
                  count(*) FILTER (WHERE action = %s AND result = 'FAILURE') AS failed_logins,
                  count(*) FILTER (WHERE result = 'DENIED') AS denied,
                  count(*) FILTER (WHERE action = %s) AS csrf,
                  count(*) FILTER (WHERE action = ANY(%s) AND result = 'SUCCESS') AS doc_events
           FROM audit_log WHERE ts > now() - make_interval(hours => %s)""",
        (LOGIN, CSRF_FAILURE, list(DOCUMENT_ACTIONS), int(hours)))
    return rows[0]


def get_document_history(document_id, limit=200):
    """Owner: access history for one document.
    The route MUST first verify the caller owns this document."""
    return _fetch(
        f"SELECT {_COLS} FROM audit_log WHERE document_id = %s "
        "ORDER BY id DESC LIMIT %s", (document_id, min(int(limit), 500)))


def count_recent_failures(username, action, minutes):
    """Failed attempts for `username` in the last `minutes`, counted only
    since their last success or last password reset. Used for login lockout."""
    rows = _fetch(
        """SELECT count(*) AS n FROM audit_log
           WHERE action = %s AND username = %s AND result = 'FAILURE'
             AND ts > now() - make_interval(mins => %s)
             AND ts > GREATEST(
                   COALESCE((SELECT max(ts) FROM audit_log
                             WHERE action = %s AND username = %s
                               AND result = 'SUCCESS'), '-infinity'),
                   COALESCE((SELECT max(ts) FROM audit_log
                             WHERE action = ANY(%s) AND result = 'SUCCESS'
                               AND target_user_id = (SELECT id FROM users
                                                     WHERE username = %s)), '-infinity'))""",
        (action, username, int(minutes), action, username, list(RESET_ACTIONS), username))
    return rows[0]["n"]


def count_recent_by_ip(action, ip_address, minutes, results=("FAILURE", "DENIED")):
    """How many `action` rows from this IP in the last `minutes` (default: only
    failures and denials). Used for per-IP throttling. No row is ever edited:
    the limit is computed from the append-only log itself."""
    if not ip_address:
        return 0
    rows = _fetch(
        """SELECT count(*) AS n FROM audit_log
           WHERE action = %s AND ip_address = %s AND result = ANY(%s)
             AND ts > now() - make_interval(mins => %s)""",
        (action, ip_address, list(results), int(minutes)))
    return rows[0]["n"]


def recent_failed_logins(hours=24, limit=25):
    """Newest failed sign-ins (wrong password, unknown account, inactive account, lockout)."""
    return _fetch(
        "SELECT id, ts, username, ip_address, result, details FROM audit_log "
        "WHERE action = %s AND result <> 'SUCCESS' "
        "AND ts > now() - make_interval(hours => %s) ORDER BY id DESC LIMIT %s",
        (LOGIN, int(hours), max(1, min(int(limit), 200))))


def failed_login_count(hours=24):
    return _fetch(
        "SELECT count(*) AS n FROM audit_log WHERE action = %s AND result = 'FAILURE' "
        "AND ts > now() - make_interval(hours => %s)", (LOGIN, int(hours)))[0]["n"]


def locked_out_accounts(max_failures, minutes):
    """Accounts that are locked out RIGHT NOW: `max_failures` or more failed sign-ins within
    the last `minutes`, counted exactly the way the login lockout counts them (since the
    last success or password reset). Returns [{username, failures, last_ts}]."""
    names = _fetch(
        "SELECT username, max(ts) AS last_ts FROM audit_log "
        "WHERE action = %s AND result = 'FAILURE' AND username <> 'anonymous' "
        "AND ts > now() - make_interval(mins => %s) GROUP BY username", (LOGIN, int(minutes)))
    locked = []
    for row in names:
        n = count_recent_failures(row["username"], LOGIN, minutes)
        if n >= max_failures:
            locked.append({"username": row["username"], "failures": n, "last_ts": row["last_ts"]})
    return sorted(locked, key=lambda r: r["last_ts"], reverse=True)


def suspicious_ips(min_failures, hours=24):
    """IP addresses with `min_failures`+ failed sign-ins in the window (password spraying /
    brute force). Returns [{ip_address, failures, accounts, last_ts}], worst first."""
    return _fetch(
        "SELECT ip_address, count(*) AS failures, count(DISTINCT username) AS accounts, "
        "max(ts) AS last_ts FROM audit_log "
        "WHERE action = %s AND result = 'FAILURE' AND ip_address IS NOT NULL "
        "AND ts > now() - make_interval(hours => %s) "
        "GROUP BY ip_address HAVING count(*) >= %s ORDER BY failures DESC, last_ts DESC LIMIT 20",
        (LOGIN, int(hours), int(min_failures)))


# --------------------------------------------------------------------------
# Integrity check
# --------------------------------------------------------------------------
def verify_chain():
    """Walk the whole log and recompute hashes.
    Returns (True, None) if intact, else (False, id_of_first_bad_row)."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, ts, user_id, username, action, document_id, "
                "target_user_id, result, ip_address, details, prev_hash, row_hash "
                "FROM audit_log ORDER BY id ASC")
            expected_prev = GENESIS_HASH
            for (rid, ts, uid, uname, action, doc, tgt, res, ip, det,
                 prev_hash, row_hash) in cur:
                if prev_hash != expected_prev:
                    return False, rid
                calc = _compute_hash(prev_hash, ts, uid, uname, action, doc,
                                     tgt, res, ip, det)
                if calc != row_hash:
                    return False, rid
                expected_prev = row_hash
        return True, None
    finally:
        conn.close()
