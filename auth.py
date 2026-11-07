"""Authentication, sessions, CSRF protection and role checks."""
import os
import re
import secrets
import string
from functools import wraps

from flask import (Blueprint, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from psycopg2 import errors as pg_errors
from werkzeug.security import check_password_hash, generate_password_hash

import audit
import pin_gate
from database import execute, execute_returning, get_connection
from passwords import validate_password

auth_bp = Blueprint("auth", __name__)

MAX_FAILED_LOGINS = 5                 # per USERNAME in the window (stops guessing one account)
LOCKOUT_MINUTES = 15
# Per IP address (stops one machine trying many usernames / spraying passwords).
MAX_FAILED_LOGINS_PER_IP = int(os.environ.get("LOGIN_MAX_FAILURES_PER_IP", "10"))
MAX_REGISTRATIONS_PER_IP = int(os.environ.get("REGISTER_MAX_PER_IP_HOUR", "5"))
MAX_RESET_REQUESTS_PER_IP = int(os.environ.get("RESET_REQUEST_MAX_PER_IP_HOUR", "5"))
USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,30}$")
# Used so unknown usernames take as long as real ones (no timing leak).
_DUMMY_HASH = generate_password_hash("not-a-real-password")


# ----------------------------------------------------------------- DB helpers
def _query_one(sql, params):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            if row is None:
                return None
            return dict(zip([d[0] for d in cur.description], row))
    finally:
        conn.close()


def get_user_by_username(username):
    return _query_one("SELECT * FROM users WHERE username = %s", (username,))


def get_user_by_id(user_id):
    return _query_one("SELECT * FROM users WHERE id = %s", (user_id,))


def create_user(username, password, role="viewer"):
    """Returns the new user id, or None if the username is taken."""
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, role) "
                "VALUES (%s, %s, %s) RETURNING id",
                (username, generate_password_hash(password), role))
            return cur.fetchone()[0]
    except pg_errors.UniqueViolation:
        return None
    finally:
        conn.close()


def set_password(user_id, new_password, must_change=False):
    """Store a new password hash, clear any pending reset request, and bump
    token_version so every session issued before now stops working.
    Returns the new token_version."""
    return execute_returning(
        "UPDATE users SET password_hash = %s, must_change_password = %s, "
        "token_version = token_version + 1, reset_requested_at = NULL "
        "WHERE id = %s RETURNING token_version",
        (generate_password_hash(new_password), must_change, user_id))


def generate_temp_password():
    """Random one-time password that always satisfies validate_password()."""
    alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no look-alikes
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(14))
        if (any(c.isalpha() for c in pw) and any(c.isdigit() for c in pw)
                and validate_password(pw) is None):
            return pw


def _throttled(action, ip, minutes, limit, results=("FAILURE",), what=""):
    """True (and logged) if this IP already hit `limit` `action` rows in the window."""
    if audit.count_recent_by_ip(action, ip, minutes, results=results) >= limit:
        audit.log_event(audit.THROTTLED, audit.DENIED, ip_address=ip,
                        details=f"{action}: too many from this IP{what}")
        return True
    return False


# ------------------------------------------------------- per-request plumbing
@auth_bp.before_app_request
def load_current_user():
    """Re-read the user from the DB on EVERY request, so deactivation or a
    role change takes effect immediately."""
    g.user = None
    user_id = session.get("user_id")
    if user_id is None:
        return
    user = get_user_by_id(user_id)
    if user is None or not user["is_active"]:
        pin_gate.keep_pin_across(session.clear)
        return
    # A password change/reset bumps token_version, which ends every older session.
    if session.get("tv") != user["token_version"]:
        pin_gate.keep_pin_across(session.clear)
        return
    g.user = user


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


@auth_bp.before_app_request
def check_csrf():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    expected = session.get("_csrf") or ""
    if not expected or not secrets.compare_digest(sent, expected):
        audit.log_event(audit.CSRF_FAILURE, audit.DENIED, user=g.user,
                        ip_address=audit.client_ip(request),
                        details=f"{request.method} {request.path}")
        abort(400)


@auth_bp.before_app_request
def force_password_change():
    """After an admin reset, the user may do nothing except choose a new password."""
    if g.user and g.user["must_change_password"] and request.endpoint not in (
            "auth.change_password", "auth.logout", "static", "pin.healthz"):
        return redirect(url_for("auth.change_password"))


# ----------------------------------------------------------------- decorators
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    """Allow only the listed roles. Wrong role => logged as DENIED + 403."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("auth.login"))
            if g.user["role"] not in roles:
                audit.log_event(
                    audit.ACCESS_DENIED, audit.DENIED, user=g.user,
                    ip_address=audit.client_ip(request),
                    details=f"{request.method} {request.path} needs {'/'.join(roles)}")
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


# --------------------------------------------------------------------- routes
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip().lower()[:150]
    password = request.form.get("password", "")
    ip = audit.client_ip(request)

    if _throttled(audit.LOGIN, ip, LOCKOUT_MINUTES, MAX_FAILED_LOGINS_PER_IP, what=" (login)"):
        flash(f"Too many failed attempts from your network. Try again in {LOCKOUT_MINUTES} minutes.", "danger")
        return render_template("login.html"), 429

    if audit.count_recent_failures(username, audit.LOGIN, LOCKOUT_MINUTES) >= MAX_FAILED_LOGINS:
        audit.log_event(audit.LOGIN, audit.DENIED, username=username,
                        ip_address=ip, details="locked out: too many failures")
        flash(f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.", "danger")
        return render_template("login.html"), 429

    user = get_user_by_username(username)
    password_ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)

    if user and password_ok and user["is_active"]:
        pin_gate.keep_pin_across(session.clear)     # prevents session fixation, keeps PIN state
        session["user_id"] = user["id"]
        session["tv"] = user["token_version"]
        session.permanent = True
        audit.log_event(audit.LOGIN, audit.SUCCESS, user=user, ip_address=ip)
        return redirect(url_for("dashboard"))

    audit.log_event(audit.LOGIN, audit.FAILURE, user=user, username=username,
                    ip_address=ip,
                    details="inactive account" if user and password_ok else "bad credentials")
    flash("Invalid username or password.", "danger")   # same message for every cause
    return render_template("login.html"), 401


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")
    ip = audit.client_ip(request)

    if _throttled(audit.REGISTER, ip, 60, MAX_REGISTRATIONS_PER_IP,
                  results=("SUCCESS", "FAILURE"), what=" (register)"):
        flash("Too many sign-up attempts from your network. Try again later.", "danger")
        return render_template("register.html"), 429

    error = None
    if not USERNAME_RE.match(username):
        error = "Username must be 3-30 characters: letters, numbers, . _ -"
    elif password != confirm:
        error = "Passwords do not match."
    else:
        error = validate_password(password, username)

    # Self-registration ALWAYS creates a viewer. Roles are changed by admins only.
    new_id = None if error else create_user(username, password, "viewer")
    if not error and new_id is None:
        error = "That username is already taken."

    if error:
        audit.log_event(audit.REGISTER, audit.FAILURE, username=username[:150],
                        ip_address=ip, details=error)
        flash(error, "danger")
        return render_template("register.html"), 400

    audit.log_event(audit.REGISTER, audit.SUCCESS,
                    user={"id": new_id, "username": username}, ip_address=ip)
    flash("Account created. Please sign in.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit.log_event(audit.LOGOUT, audit.SUCCESS, user=g.user,
                    ip_address=audit.client_ip(request))
    pin_gate.keep_pin_across(session.clear)
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


# ------------------------------------------------------------ password routes
@auth_bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    """Signed-in user picks a new password (also the forced step after an admin reset)."""
    forced = bool(g.user["must_change_password"])
    if request.method == "GET":
        return render_template("change_password.html", forced=forced)

    ip = audit.client_ip(request)
    me = g.user
    current = request.form.get("current", "")
    new = request.form.get("new", "")
    confirm = request.form.get("confirm", "")

    def refuse(message, status=400, note=None):
        audit.log_event(audit.PASSWORD_CHANGE, audit.FAILURE, user=me, target_user_id=me["id"],
                        ip_address=ip, details=note or message)
        flash(message, "danger")
        return render_template("change_password.html", forced=forced), status

    if (_throttled(audit.PASSWORD_CHANGE, ip, LOCKOUT_MINUTES, MAX_FAILED_LOGINS_PER_IP,
                   what=" (password change)")
            or audit.count_recent_failures(me["username"], audit.PASSWORD_CHANGE,
                                           LOCKOUT_MINUTES) >= MAX_FAILED_LOGINS):
        flash(f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.", "danger")
        return render_template("change_password.html", forced=forced), 429

    if not check_password_hash(me["password_hash"], current):
        return refuse("Your current password is not correct.", 401, "wrong current password")
    if new != confirm:
        return refuse("The new passwords do not match.")
    if new == current:
        return refuse("Choose a password different from the current one.")
    error = validate_password(new, me["username"])
    if error:
        return refuse(error)

    session["tv"] = set_password(me["id"], new, must_change=False)   # this browser stays signed in
    audit.log_event(audit.PASSWORD_CHANGE, audit.SUCCESS, user=me, target_user_id=me["id"],
                    ip_address=ip, details="forced change after reset" if forced else None)
    flash("Password changed. Any other signed-in sessions were ended.", "success")
    return redirect(url_for("dashboard"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """No e-mail in this system, so 'forgot' = ask an admin. The answer is identical whether
    or not the account exists (no username enumeration)."""
    if g.user:
        return redirect(url_for("auth.change_password"))
    if request.method == "GET":
        return render_template("forgot_password.html")

    ip = audit.client_ip(request)
    username = request.form.get("username", "").strip().lower()[:150]
    if _throttled(audit.PASSWORD_RESET_REQUEST, ip, 60, MAX_RESET_REQUESTS_PER_IP,
                  results=("SUCCESS", "FAILURE"), what=" (reset request)"):
        flash("Too many requests from your network. Try again later.", "danger")
        return render_template("forgot_password.html"), 429

    user = get_user_by_username(username)
    if user and user["is_active"]:
        execute("UPDATE users SET reset_requested_at = now() WHERE id = %s", (user["id"],))
        audit.log_event(audit.PASSWORD_RESET_REQUEST, audit.SUCCESS, user=user,
                        target_user_id=user["id"], ip_address=ip)
    else:
        audit.log_event(audit.PASSWORD_RESET_REQUEST, audit.FAILURE, username=username,
                        ip_address=ip, details="unknown or inactive account")
    flash("If that account exists, an administrator has been asked to reset it. "
          "They will give you a temporary password.", "info")
    return redirect(url_for("auth.login"))
