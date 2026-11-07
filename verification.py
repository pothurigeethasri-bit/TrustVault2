"""E-mail ownership proof: one-time links that are e-mailed and then redeemed.

Sign-up order is  e-mail -> link in the inbox -> choose username + password.  No row in `users`
exists until the link has been used, so an address nobody controls can never become an account.

Token rules:
* 256 bits of randomness; only the SHA-256 hash is stored, so a database leak gives no usable link.
* Expires (EMAIL_TOKEN_MINUTES, default 30) and works exactly once. Redeeming is one atomic
  UPDATE ... WHERE used_at IS NULL, so two clicks / two tabs cannot both succeed.
* Asking for a new link kills the older ones for the same address.
* Opening a link (GET) never uses it up; only the form POST does. Mail scanners that pre-fetch
  links therefore cannot burn a user's link.
* If the account/username step fails (username taken, ...), nothing is consumed: the same link
  still works for another try.
"""
import hashlib
import html
import os
import secrets

from psycopg2 import errors as pg_errors
from werkzeug.security import generate_password_hash

import mailer
from database import execute, fetch_one, get_connection

REGISTER = "register"
CHANGE_EMAIL = "change_email"

TOKEN_MINUTES = int(os.environ.get("EMAIL_TOKEN_MINUTES", "30"))
RESEND_COOLDOWN_SECONDS = int(os.environ.get("EMAIL_RESEND_COOLDOWN_SECONDS", "60"))
MAX_LINKS_PER_EMAIL_HOUR = int(os.environ.get("EMAIL_MAX_LINKS_PER_HOUR", "5"))

# Outcomes of redeeming a link.
OK, INVALID, USERNAME_TAKEN, EMAIL_TAKEN = "ok", "invalid", "username_taken", "email_taken"


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _plausible(token):
    return isinstance(token, str) and 20 <= len(token) <= 100


# ------------------------------------------------------------------ issuing links
def may_send_link(email, purpose):
    """Per-address limits: one link per cooldown period, a few per hour. Stops anyone using
    the form to flood somebody's inbox (the per-IP limit is checked separately)."""
    row = fetch_one(
        "SELECT count(*) FILTER (WHERE created_at > now() - interval '1 hour') AS per_hour, "
        "       count(*) FILTER (WHERE created_at > now() - make_interval(secs => %s)) AS recent "
        "FROM email_tokens WHERE email = %s AND purpose = %s",
        (float(RESEND_COOLDOWN_SECONDS), email, purpose))
    return row["recent"] == 0 and row["per_hour"] < MAX_LINKS_PER_EMAIL_HOUR


def create_token(email, purpose, user_id=None):
    """Store a fresh token (older unused ones for the same address/user are cancelled)."""
    token = secrets.token_urlsafe(32)
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            if purpose == CHANGE_EMAIL:
                cur.execute("UPDATE email_tokens SET used_at = now() "
                            "WHERE purpose = %s AND user_id = %s AND used_at IS NULL",
                            (purpose, user_id))
            else:
                cur.execute("UPDATE email_tokens SET used_at = now() "
                            "WHERE purpose = %s AND email = %s AND used_at IS NULL",
                            (purpose, email))
            cur.execute(
                "INSERT INTO email_tokens (token_hash, purpose, email, user_id, expires_at) "
                "VALUES (%s, %s, %s, %s, now() + make_interval(mins => %s))",
                (_hash(token), purpose, email, user_id, TOKEN_MINUTES))
    finally:
        conn.close()
    return token


def discard_token(token):
    """The mail could not be sent: forget the token so the user may retry straight away."""
    execute("DELETE FROM email_tokens WHERE token_hash = %s AND used_at IS NULL", (_hash(token),))


# ---------------------------------------------------------------- checking links
def lookup(token, purpose, user_id=None):
    """The pending row for a still-valid link, or None. Does NOT use the link up."""
    if not _plausible(token):
        return None
    sql = ("SELECT id, email, user_id FROM email_tokens WHERE token_hash = %s AND purpose = %s "
           "AND used_at IS NULL AND expires_at > now()")
    params = [_hash(token), purpose]
    if user_id is not None:
        sql += " AND user_id = %s"
        params.append(user_id)
    return fetch_one(sql, params)


def complete_registration(token, username, password):
    """Redeem a register link and create the (viewer) account in ONE transaction.
    Returns (outcome, user_id, email). On any failure nothing is consumed or created."""
    if not _plausible(token):
        return INVALID, None, None
    pw_hash = generate_password_hash(password)      # slow hash computed outside the transaction
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE email_tokens SET used_at = now() WHERE token_hash = %s AND purpose = %s "
                "AND used_at IS NULL AND expires_at > now() RETURNING email",
                (_hash(token), REGISTER))
            row = cur.fetchone()
            if row is None:
                return INVALID, None, None
            email = row[0]
            cur.execute(
                "INSERT INTO users (username, password_hash, role, email, email_verified_at) "
                "VALUES (%s, %s, 'viewer', %s, now()) RETURNING id",
                (username, pw_hash, email))
            user_id = cur.fetchone()[0]
            cur.execute("UPDATE email_tokens SET used_at = now() "
                        "WHERE purpose = %s AND email = %s AND used_at IS NULL", (REGISTER, email))
            return OK, user_id, email
    except pg_errors.UniqueViolation as exc:
        # The `with conn` block rolled everything back, so the link is still unused.
        constraint = (exc.diag.constraint_name or "").lower()
        return (EMAIL_TAKEN if "email" in constraint else USERNAME_TAKEN), None, None
    finally:
        conn.close()


def confirm_email_change(token, user_id):
    """Redeem a change-email link for this signed-in user. Returns (outcome, new_email)."""
    if not _plausible(token):
        return INVALID, None
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE email_tokens SET used_at = now() WHERE token_hash = %s AND purpose = %s "
                "AND user_id = %s AND used_at IS NULL AND expires_at > now() RETURNING email",
                (_hash(token), CHANGE_EMAIL, user_id))
            row = cur.fetchone()
            if row is None:
                return INVALID, None
            cur.execute("UPDATE users SET email = %s, email_verified_at = now() WHERE id = %s",
                        (row[0], user_id))
            return OK, row[0]
    except pg_errors.UniqueViolation:
        return EMAIL_TAKEN, None
    finally:
        conn.close()


# --------------------------------------------------------------------- the e-mails
def _wrap(paragraphs, link=None, button="Continue"):
    body = "".join(f"<p>{html.escape(p)}</p>" for p in paragraphs)
    if link:
        safe = html.escape(link, quote=True)
        body += (f'<p><a href="{safe}" style="display:inline-block;padding:10px 18px;'
                 f'background:#1db954;color:#000;text-decoration:none;border-radius:20px;'
                 f'font-weight:600">{html.escape(button)}</a></p>'
                 f'<p style="font-size:12px;color:#666">If the button does not work, copy this '
                 f'address into your browser:<br>{html.escape(link)}</p>')
    return f'<div style="font-family:Arial,sans-serif;font-size:15px;color:#222">{body}</div>'


def send_registration_link(email, link):
    text = (f"Welcome to TrustVault.\n\nConfirm that this is your email address and choose your "
            f"username and password:\n\n{link}\n\nThe link works once and expires in "
            f"{TOKEN_MINUTES} minutes. If you did not ask for this, ignore this email: "
            f"no account is created unless the link is used.\n")
    mailer.send_mail(email, "Confirm your email for TrustVault", text, _wrap(
        ["Welcome to TrustVault.",
         "Confirm that this is your email address, then choose your username and password.",
         f"The link works once and expires in {TOKEN_MINUTES} minutes. If you did not ask for "
         f"this, ignore this email: no account is created unless the link is used."],
        link, "Confirm email and continue"))


def send_already_registered_notice(email, login_url):
    text = (f"Someone (hopefully you) tried to create a TrustVault account with this email "
            f"address, but an account already exists.\n\nSign in here: {login_url}\n\nIf you "
            f"forgot your password, use \"Forgot password?\" on the sign-in page. If this was "
            f"not you, you can ignore this email.\n")
    mailer.send_mail(email, "You already have a TrustVault account", text, _wrap(
        ["Someone (hopefully you) tried to create a TrustVault account with this email address, "
         "but an account already exists.",
         "If you forgot your password, use \"Forgot password?\" on the sign-in page. If this was "
         "not you, you can ignore this email."], login_url, "Go to sign in"))


def send_change_email_link(email, link, username):
    text = (f"Hello {username},\n\nConfirm that this is the email address you want to sign in "
            f"with on TrustVault (you must be signed in to finish):\n\n{link}\n\nThe link works "
            f"once and expires in {TOKEN_MINUTES} minutes. If you did not ask for this, ignore "
            f"this email: nothing changes unless the link is used.\n")
    mailer.send_mail(email, "Confirm your new TrustVault email", text, _wrap(
        [f"Hello {username},",
         "Confirm that this is the email address you want to sign in with on TrustVault "
         "(you must be signed in to finish).",
         f"The link works once and expires in {TOKEN_MINUTES} minutes. If you did not ask for "
         f"this, ignore this email: nothing changes unless the link is used."],
        link, "Confirm new email"))
