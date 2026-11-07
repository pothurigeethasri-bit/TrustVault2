"""Outgoing e-mail over SMTP (used for e-mail verification links).

All settings come from the environment / .env (see .env.example):

    SMTP_HOST, SMTP_PORT, SMTP_SECURITY (starttls | ssl | none), SMTP_USER, SMTP_PASSWORD,
    SMTP_FROM, SMTP_TIMEOUT, APP_BASE_URL

Rules enforced here:
* Links in e-mails are built from APP_BASE_URL, never from the request's Host header
  (a forged Host header could otherwise point a verification link at an attacker's site).
* Production (COOKIE_SECURE=1) refuses to start without working SMTP settings and an https
  APP_BASE_URL, and never sends mail in clear text.
* Local development without SMTP settings does NOT send anything: the e-mail (with its link)
  is written to the server log instead, so you can still click through the flow.
* The server's answer to a refused recipient is reported separately (MailError.rejected), so
  a mistyped address is caught immediately instead of silently never arriving.
"""
import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

log = logging.getLogger("trustvault.mail")

SECURITY_MODES = ("starttls", "ssl", "none")
_DEFAULT_PORT = {"starttls": 587, "ssl": 465, "none": 25}


class MailError(Exception):
    """The message could not be handed to the mail server."""

    def __init__(self, message, rejected=False):
        super().__init__(message)
        self.rejected = rejected          # True: the server refused this recipient address


def _production():
    return os.environ.get("COOKIE_SECURE", "0") == "1"


def settings():
    """Read the SMTP settings fresh each time (so a changed .env/environment is honoured)."""
    security = os.environ.get("SMTP_SECURITY", "starttls").strip().lower()
    return {
        "host": os.environ.get("SMTP_HOST", "").strip(),
        "port": int(os.environ.get("SMTP_PORT", "") or _DEFAULT_PORT.get(security, 587)),
        "security": security,
        "user": os.environ.get("SMTP_USER", "").strip(),
        "password": os.environ.get("SMTP_PASSWORD", ""),
        "sender": os.environ.get("SMTP_FROM", "").strip(),
        "timeout": float(os.environ.get("SMTP_TIMEOUT", "") or 10),
    }


def is_configured():
    s = settings()
    return bool(s["host"] and s["sender"])


def base_url(request=None):
    """Public address of the site, used in e-mailed links. No trailing slash."""
    configured = os.environ.get("APP_BASE_URL", "").strip().rstrip("/")
    if configured:
        return configured
    if request is not None and not _production():          # local dev convenience only
        return request.url_root.rstrip("/")
    raise MailError("APP_BASE_URL is not set")


def validate_configuration(production):
    """Called at start-up. Fails loudly instead of failing at the first sign-up."""
    try:
        s = settings()
    except ValueError as exc:
        raise RuntimeError(f"SMTP_PORT / SMTP_TIMEOUT must be numbers ({exc})")
    if s["security"] not in SECURITY_MODES:
        raise RuntimeError("SMTP_SECURITY must be one of: " + ", ".join(SECURITY_MODES))
    if s["user"] and not s["password"]:
        raise RuntimeError("SMTP_USER is set but SMTP_PASSWORD is empty")
    if s["host"] and not s["sender"]:
        raise RuntimeError("SMTP_HOST is set but SMTP_FROM is empty")
    if production:
        if not is_configured():
            raise RuntimeError("Production (COOKIE_SECURE=1) requires SMTP_HOST and SMTP_FROM "
                               "so new users can verify their e-mail address")
        if s["security"] == "none":
            raise RuntimeError("Production requires SMTP_SECURITY=starttls or ssl")
        if not os.environ.get("APP_BASE_URL", "").strip().startswith("https://"):
            raise RuntimeError("Production requires APP_BASE_URL=https://your-site (used in e-mailed links)")


def send_mail(to, subject, text, html=None):
    """Send one message. Raises MailError if it could not be delivered to the mail server."""
    s = settings()
    if not is_configured():
        if _production():
            raise MailError("SMTP is not configured")
        log.warning("SMTP not configured, e-mail NOT sent (dev mode).\nTo: %s\nSubject: %s\n\n%s",
                    to, subject, text)
        return

    msg = EmailMessage()
    msg["From"] = s["sender"]
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=(s["sender"].rsplit("@", 1)[-1].strip("> ") or None))
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")

    context = ssl.create_default_context()
    try:
        if s["security"] == "ssl":
            server = smtplib.SMTP_SSL(s["host"], s["port"], timeout=s["timeout"], context=context)
        else:
            server = smtplib.SMTP(s["host"], s["port"], timeout=s["timeout"])
        with server:
            server.ehlo()
            if s["security"] == "starttls":
                server.starttls(context=context)
                server.ehlo()
            if s["user"]:
                server.login(s["user"], s["password"])
            server.send_message(msg)
    except smtplib.SMTPRecipientsRefused as exc:
        log.warning("SMTP server refused recipient: %s", exc)
        raise MailError("recipient refused", rejected=True) from exc
    except (smtplib.SMTPException, OSError) as exc:        # ssl.SSLError is an OSError
        log.error("SMTP send failed: %s: %s", type(exc).__name__, exc)
        raise MailError("could not send") from exc
