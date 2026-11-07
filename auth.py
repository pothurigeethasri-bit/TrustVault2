"""Authentication, sessions, CSRF protection and role checks."""
import os
import re
import secrets
import string
from functools import wraps

from flask import (Blueprint, abort, flash, g, make_response, redirect, render_template,
                   request, session, url_for)
from psycopg2 import errors as pg_errors
from werkzeug.security import check_password_hash, generate_password_hash

import audit
import mailer
import pin_gate
import verification
from database import execute, execute_returning, get_connection
from passwords import validate_password
from validation import normalise_email

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


def get_user_by_email(email):
    return _query_one("SELECT * FROM users WHERE email = %s", (email,))


def find_user(identifier):
    """Resolve what someone typed into the sign-in box. An '@' means e-mail (usernames can
    never contain one); anything else is treated as a legacy username so accounts that have
    not added an e-mail yet can still sign in."""
    if "@" in identifier:
        return get_user_by_email(identifier)
    return get_user_by_username(identifier)


def get_user_by_id(user_id):
    return _query_one("SELECT * FROM users WHERE id = %s", (user_id,))


def create_user(username, password, role="viewer", email=None):
    """Insert an account directly. ONLY for trusted callers (seed script, tests): an e-mail
    given here is recorded as verified. Self sign-up never calls this; it goes through
    verification.complete_registration() so the address is proven first.
    Returns the new user id, or None if the username (or e-mail) is already taken."""
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, role, email, email_verified_at) "
                "VALUES (%s, %s, %s, %s, CASE WHEN %s IS NULL THEN NULL ELSE now() END) "
                "RETURNING id",
                (username, generate_password_hash(password), role, email, email))
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

    # The sign-in box is "Email". The field is still accepted as "username" for old clients.
    identifier = (request.form.get("email") or request.form.get("username") or "").strip().lower()[:254]
    password = request.form.get("password", "")
    ip = audit.client_ip(request)
    user = find_user(identifier)
    # Lockout and audit rows are keyed by the account's username, so signing in with the
    # e-mail or with the username counts against the SAME limit.
    username = user["username"] if user else identifier[:150]

    if _throttled(audit.LOGIN, ip, LOCKOUT_MINUTES, MAX_FAILED_LOGINS_PER_IP, what=" (login)"):
        flash(f"Too many failed attempts from your network. Try again in {LOCKOUT_MINUTES} minutes.", "danger")
        return render_template("login.html"), 429

    if audit.count_recent_failures(username, audit.LOGIN, LOCKOUT_MINUTES) >= MAX_FAILED_LOGINS:
        audit.log_event(audit.LOGIN, audit.DENIED, username=username,
                        ip_address=ip, details="locked out: too many failures")
        flash(f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.", "danger")
        return render_template("login.html"), 429

    password_ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)

    if user and password_ok and user["is_active"]:
        pin_gate.keep_pin_across(session.clear)     # prevents session fixation, keeps PIN state
        session["user_id"] = user["id"]
        session["tv"] = user["token_version"]
        session.permanent = True
        audit.log_event(audit.LOGIN, audit.SUCCESS, user=user, ip_address=ip)
        if not user["email"]:
            flash("Add your email address (top right: Email) so you can sign in with it.", "info")
        return redirect(url_for("dashboard"))

    audit.log_event(audit.LOGIN, audit.FAILURE, user=user, username=username,
                    ip_address=ip,
                    details="inactive account" if user and password_ok else "bad credentials")
    flash("Invalid email or password.", "danger")   # same message for every cause
    return render_template("login.html"), 401


def _verification_link(endpoint, token):
    return f"{mailer.base_url(request)}{url_for(endpoint)}?token={token}"


def _mail_failure_message(exc):
    if exc.rejected:
        return "That email address was rejected by the mail server. Check it for typos."
    return "We could not send the email right now. Please try again in a few minutes."


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Step 1 of sign-up: ONLY an e-mail address. A link is mailed to it; the username and
    password are chosen after the link is opened (register_complete). No account exists, and
    no username is reserved, until then. The answer is the same whether or not the address
    already has an account, so the form cannot be used to find out who is registered."""
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "GET":
        return render_template("register.html")

    raw_email = request.form.get("email", "")
    email = normalise_email(raw_email)
    ip = audit.client_ip(request)

    if _throttled(audit.EMAIL_VERIFY_REQUEST, ip, 60, MAX_REGISTRATIONS_PER_IP,
                  results=("SUCCESS", "FAILURE"), what=" (sign-up email)"):
        flash("Too many sign-up attempts from your network. Try again later.", "danger")
        return render_template("register.html"), 429

    if email is None:     # typos are not counted against the per-IP limit: nothing is sent
        audit.log_event(audit.REGISTER, audit.FAILURE, username=raw_email.strip()[:150],
                        ip_address=ip, details="invalid email address")
        flash("Enter a valid email address.", "danger")
        return render_template("register.html"), 400

    try:
        if get_user_by_email(email):
            verification.send_already_registered_notice(
                email, f"{mailer.base_url(request)}{url_for('auth.login')}")
            result, details = audit.SUCCESS, "address already registered: notice sent"
        elif verification.may_send_link(email, verification.REGISTER):
            token = verification.create_token(email, verification.REGISTER)
            try:
                verification.send_registration_link(
                    email, _verification_link("auth.register_complete", token))
            except mailer.MailError:
                verification.discard_token(token)       # let them retry at once
                raise
            result, details = audit.SUCCESS, "verification link sent"
        else:
            result, details = audit.DENIED, "not sent: per-address limit (cooldown or hourly cap)"
    except mailer.MailError as exc:
        audit.log_event(audit.EMAIL_VERIFY_REQUEST, audit.FAILURE, username=email,
                        ip_address=ip,
                        details="mail server refused the address" if exc.rejected else "send failed")
        flash(_mail_failure_message(exc), "danger")
        return render_template("register.html"), (400 if exc.rejected else 503)

    audit.log_event(audit.EMAIL_VERIFY_REQUEST, result, username=email, ip_address=ip,
                    details=details)
    return render_template("register_sent.html", email=email,
                           minutes=verification.TOKEN_MINUTES,
                           cooldown=verification.RESEND_COOLDOWN_SECONDS)


@auth_bp.route("/register/complete", methods=["GET", "POST"])
def register_complete():
    """Step 2: the e-mailed link. Opening it only shows the form (so link-scanners cannot use
    it up); submitting the form redeems it and creates the account in one transaction."""
    if g.user:
        return redirect(url_for("dashboard"))
    is_post = request.method == "POST"
    token = ((request.form if is_post else request.args).get("token") or "").strip()
    ip = audit.client_ip(request)

    def dead_link(message="This link is invalid, has expired or was already used."):
        return _no_store(make_response(render_template("verify_failed.html", message=message), 400))

    def form(error=None, status=200, email=None, username=""):
        if error:
            flash(error, "danger")
        return _no_store(make_response(render_template(
            "register_complete.html", token=token, email=email, username=username), status))

    pending = verification.lookup(token, verification.REGISTER)
    if pending is None:
        return dead_link()
    if not is_post:
        return form(email=pending["email"])

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")

    error = None
    if not USERNAME_RE.match(username):
        error = "Username must be 3-30 characters: letters, numbers, . _ -"
    elif password != confirm:
        error = "Passwords do not match."
    else:
        error = validate_password(password, username)
    if error:
        audit.log_event(audit.REGISTER, audit.FAILURE, username=username[:150],
                        ip_address=ip, details=error)
        return form(error, 400, pending["email"], username)

    outcome, new_id, email = verification.complete_registration(token, username, password)
    if outcome == verification.USERNAME_TAKEN:        # link NOT used up: pick another name
        audit.log_event(audit.REGISTER, audit.FAILURE, username=username[:150],
                        ip_address=ip, details="username already taken")
        return form("That username is already taken. Choose another.", 400, pending["email"])
    if outcome == verification.EMAIL_TAKEN:
        return dead_link("An account with this email already exists. Please sign in.")
    if outcome != verification.OK:
        return dead_link()

    new_user = {"id": new_id, "username": username}
    audit.log_event(audit.EMAIL_VERIFIED, audit.SUCCESS, user=new_user, target_user_id=new_id,
                    ip_address=ip, details=f"sign-up email {email} verified")
    audit.log_event(audit.REGISTER, audit.SUCCESS, user=new_user, ip_address=ip)
    flash("Email verified and account created. Please sign in.", "success")
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
    """No outgoing mail in this system, so 'forgot' = ask an admin. The person types their
    email (or legacy username). The answer is identical whether or not the account exists."""
    if g.user:
        return redirect(url_for("auth.change_password"))
    if request.method == "GET":
        return render_template("forgot_password.html")

    ip = audit.client_ip(request)
    identifier = (request.form.get("email") or request.form.get("username") or "").strip().lower()[:254]
    username = identifier[:150]
    if _throttled(audit.PASSWORD_RESET_REQUEST, ip, 60, MAX_RESET_REQUESTS_PER_IP,
                  results=("SUCCESS", "FAILURE"), what=" (reset request)"):
        flash("Too many requests from your network. Try again later.", "danger")
        return render_template("forgot_password.html"), 429

    user = find_user(identifier)
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


@auth_bp.route("/account/email", methods=["GET", "POST"])
@login_required
def change_email():
    """Set or change the e-mail used to sign in. Needs the current password (an e-mail
    address is a login name) AND proof that the new address is the user's: the address only
    changes after the link mailed to it is opened (confirm_email)."""
    if request.method == "GET":
        return render_template("change_email.html")

    ip = audit.client_ip(request)
    me = g.user

    def refuse(message, status=400, note=None):
        audit.log_event(audit.EMAIL_CHANGE, audit.FAILURE, user=me, target_user_id=me["id"],
                        ip_address=ip, details=note or message)
        flash(message, "danger")
        return render_template("change_email.html"), status

    if (_throttled(audit.EMAIL_CHANGE, ip, LOCKOUT_MINUTES, MAX_FAILED_LOGINS_PER_IP,
                   what=" (email change)")
            or audit.count_recent_failures(me["username"], audit.EMAIL_CHANGE,
                                           LOCKOUT_MINUTES) >= MAX_FAILED_LOGINS):
        flash(f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.", "danger")
        return render_template("change_email.html"), 429

    if not check_password_hash(me["password_hash"], request.form.get("current", "")):
        return refuse("Your current password is not correct.", 401, "wrong current password")
    email = normalise_email(request.form.get("email", ""))
    if email is None:
        return refuse("Enter a valid email address.")
    if email == me["email"]:
        return refuse("That is already your sign-in email.")
    owner = get_user_by_email(email)
    if owner and owner["id"] != me["id"]:
        return refuse("That email is already registered.")
    if not verification.may_send_link(email, verification.CHANGE_EMAIL):
        flash(f"A link was sent to that address a moment ago. Check your inbox (and spam), or "
              f"wait about {verification.RESEND_COOLDOWN_SECONDS} seconds and try again.", "info")
        return render_template("change_email.html"), 429

    token = verification.create_token(email, verification.CHANGE_EMAIL, me["id"])
    try:
        verification.send_change_email_link(
            email, _verification_link("auth.confirm_email", token), me["username"])
    except mailer.MailError as exc:
        verification.discard_token(token)
        return refuse(_mail_failure_message(exc), 400 if exc.rejected else 503,
                      "mail server refused the address" if exc.rejected else "send failed")

    audit.log_event(audit.EMAIL_VERIFY_REQUEST, audit.SUCCESS, user=me, target_user_id=me["id"],
                    ip_address=ip, details=f"link sent to {email} for email change")
    flash(f"We sent a confirmation link to {email}. Your sign-in email changes only after you "
          f"open it.", "success")
    return redirect(url_for("auth.change_email"))


@auth_bp.route("/account/email/confirm", methods=["GET", "POST"])
def confirm_email():
    """The link mailed by change_email. Must be opened while signed in as the same user."""
    if g.user is None:
        flash("Sign in first, then open the link from your email again.", "info")
        return redirect(url_for("auth.login"))
    me = g.user
    is_post = request.method == "POST"
    token = ((request.form if is_post else request.args).get("token") or "").strip()
    ip = audit.client_ip(request)

    pending = verification.lookup(token, verification.CHANGE_EMAIL, user_id=me["id"])
    if pending is None:
        flash("This link is invalid, has expired, was already used, or belongs to another "
              "account. Request a new one below.", "danger")
        return redirect(url_for("auth.change_email"))
    if not is_post:
        return _no_store(make_response(render_template(
            "confirm_email.html", token=token, new_email=pending["email"])))

    outcome, new_email = verification.confirm_email_change(token, me["id"])
    if outcome == verification.EMAIL_TAKEN:
        audit.log_event(audit.EMAIL_CHANGE, audit.FAILURE, user=me, target_user_id=me["id"],
                        ip_address=ip, details="address taken by another account")
        flash("That email is now registered to another account.", "danger")
        return redirect(url_for("auth.change_email"))
    if outcome != verification.OK:
        flash("This link is invalid, has expired or was already used.", "danger")
        return redirect(url_for("auth.change_email"))
    audit.log_event(audit.EMAIL_VERIFIED, audit.SUCCESS, user=me, target_user_id=me["id"],
                    ip_address=ip, details=f"{new_email} verified")
    audit.log_event(audit.EMAIL_CHANGE, audit.SUCCESS, user=me, target_user_id=me["id"],
                    ip_address=ip, details=f"email set to {new_email}")
    flash("Email confirmed. You can now sign in with it.", "success")
    return redirect(url_for("dashboard"))
