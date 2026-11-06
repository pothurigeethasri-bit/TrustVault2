"""Authentication, sessions, CSRF protection and role checks."""
import re
import secrets
from functools import wraps

from flask import (Blueprint, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from psycopg2 import errors as pg_errors
from werkzeug.security import check_password_hash, generate_password_hash

import audit
from database import get_connection
from passwords import validate_password

auth_bp = Blueprint("auth", __name__)

MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
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
        session.clear()
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

    if audit.count_recent_failures(username, audit.LOGIN, LOCKOUT_MINUTES) >= MAX_FAILED_LOGINS:
        audit.log_event(audit.LOGIN, audit.DENIED, username=username,
                        ip_address=ip, details="locked out: too many failures")
        flash(f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.", "danger")
        return render_template("login.html"), 429

    user = get_user_by_username(username)
    password_ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)

    if user and password_ok and user["is_active"]:
        session.clear()                 # prevents session fixation
        session["user_id"] = user["id"]
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
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
