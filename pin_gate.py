"""Security-PIN gate: nobody reaches login or registration until the PIN is entered.

* The PIN lives only in the ACCESS_PIN environment variable (never in the repo or DB).
* It is compared in constant time.
* A verified browser stores a fingerprint of the PIN in its signed session, so changing
  ACCESS_PIN instantly invalidates everybody's "PIN passed" state.
* Wrong guesses are throttled per IP address (counted from the audit log) and every
  attempt is audited (PIN_ATTEMPT).
"""
import hashlib
import hmac
import os
from urllib.parse import urlparse

from flask import (Blueprint, current_app, flash, g, redirect, render_template,
                   request, session, url_for)

import audit

pin_bp = Blueprint("pin", __name__)

MAX_PIN_FAILURES_PER_IP = int(os.environ.get("PIN_MAX_FAILURES_PER_IP", "5"))
PIN_WINDOW_MINUTES = int(os.environ.get("PIN_WINDOW_MINUTES", "15"))
MIN_PIN_LENGTH = 6

# Endpoints reachable without the PIN: the PIN page itself, static assets, health check.
EXEMPT = {"pin.enter", "pin.healthz", "static"}


def configured_pin():
    return os.environ.get("ACCESS_PIN", "").strip()


def gate_enabled():
    return bool(configured_pin())


def _fingerprint():
    """Stored in the session instead of the PIN. Changes when the PIN or SECRET_KEY changes."""
    key = current_app.config["SECRET_KEY"].encode()
    return hmac.new(key, ("pin:" + configured_pin()).encode(), hashlib.sha256).hexdigest()


def pin_matches(candidate):
    a = hashlib.sha256(candidate.encode()).digest()
    b = hashlib.sha256(configured_pin().encode()).digest()
    return hmac.compare_digest(a, b)


def pin_passed():
    return (not gate_enabled()) or hmac.compare_digest(str(session.get("pin_ok", "")), _fingerprint())


def mark_passed():
    if gate_enabled():
        session["pin_ok"] = _fingerprint()
        session.permanent = True


def keep_pin_across(clear_fn):
    """session.clear() on login/logout would drop the PIN state; carry it over."""
    ok = pin_passed()
    clear_fn()
    if ok:
        mark_passed()


def validate_configuration(secure_mode):
    pin = configured_pin()
    if pin and len(pin) < MIN_PIN_LENGTH:
        raise RuntimeError(f"ACCESS_PIN must be at least {MIN_PIN_LENGTH} characters")
    if secure_mode and not pin:
        raise RuntimeError("Production (COOKIE_SECURE=1) requires ACCESS_PIN to be set")


def _safe_next(target):
    """Only allow same-site relative redirects (no open redirect)."""
    if not target:
        return None
    parts = urlparse(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//"):
        return None
    return target


@pin_bp.before_app_request
def require_pin():
    if not gate_enabled() or request.endpoint in EXEMPT or request.endpoint is None:
        return None
    if pin_passed():
        return None
    nxt = request.full_path.rstrip("?") if request.method == "GET" else None
    return redirect(url_for("pin.enter", next=nxt) if nxt and nxt != "/" else url_for("pin.enter"))


@pin_bp.route("/healthz")
def healthz():
    return "ok", 200, {"Content-Type": "text/plain"}


@pin_bp.route("/pin", methods=["GET", "POST"])
def enter():
    if not gate_enabled() or pin_passed():
        return redirect(_safe_next(request.args.get("next")) or url_for("index"))
    if request.method == "GET":
        return render_template("pin.html")

    ip = audit.client_ip(request)
    recent = audit.count_recent_by_ip(audit.PIN_ATTEMPT, ip, PIN_WINDOW_MINUTES,
                                       results=("FAILURE",))
    if recent >= MAX_PIN_FAILURES_PER_IP:
        audit.log_event(audit.PIN_ATTEMPT, audit.DENIED, ip_address=ip,
                        details="locked out: too many wrong PINs from this IP")
        flash(f"Too many wrong PINs. Try again in {PIN_WINDOW_MINUTES} minutes.", "danger")
        return render_template("pin.html"), 429

    if pin_matches(request.form.get("pin", "").strip()[:128]):
        session.clear()
        mark_passed()
        audit.log_event(audit.PIN_ATTEMPT, audit.SUCCESS, ip_address=ip)
        return redirect(_safe_next(request.args.get("next")) or url_for("auth.login"))

    audit.log_event(audit.PIN_ATTEMPT, audit.FAILURE, ip_address=ip, details="wrong PIN")
    flash("That PIN is not correct.", "danger")
    return render_template("pin.html"), 401
