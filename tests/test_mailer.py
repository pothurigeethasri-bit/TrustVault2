"""Mailer and start-up configuration. Pure unit tests: no database, no real SMTP server."""
import logging
import smtplib

import pytest

import mailer

SMTP_ENV = {"SMTP_HOST": "smtp.example.com", "SMTP_FROM": "TrustVault <no-reply@example.com>",
            "SMTP_USER": "apikey", "SMTP_PASSWORD": "s3cret", "APP_BASE_URL": "https://vault.example"}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in ("SMTP_HOST", "SMTP_PORT", "SMTP_SECURITY", "SMTP_USER", "SMTP_PASSWORD",
                "SMTP_FROM", "SMTP_TIMEOUT", "APP_BASE_URL", "COOKIE_SECURE"):
        monkeypatch.delenv(key, raising=False)


def configure(monkeypatch, **extra):
    for key, value in {**SMTP_ENV, **extra}.items():
        monkeypatch.setenv(key, value)


class FakeSMTP:
    """Records the conversation; class attributes let each test script the server's behaviour."""
    calls, refuse, connect_error = [], False, None

    def __init__(self, host, port, timeout=None, context=None):
        if FakeSMTP.connect_error:
            raise FakeSMTP.connect_error
        FakeSMTP.calls.append(("connect", host, port, timeout, context is not None))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        FakeSMTP.calls.append(("quit",))

    def ehlo(self):
        FakeSMTP.calls.append(("ehlo",))

    def starttls(self, context=None):
        FakeSMTP.calls.append(("starttls", context is not None))

    def login(self, user, password):
        FakeSMTP.calls.append(("login", user))

    def send_message(self, msg):
        if FakeSMTP.refuse:
            raise smtplib.SMTPRecipientsRefused({msg["To"]: (550, b"no such user")})
        FakeSMTP.calls.append(("send", msg["To"], msg["Subject"], msg.get_body(("plain",)).get_content()))


@pytest.fixture()
def smtp(monkeypatch):
    FakeSMTP.calls, FakeSMTP.refuse, FakeSMTP.connect_error = [], False, None
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    return FakeSMTP


def test_starttls_runs_before_login_and_the_message_is_sent(monkeypatch, smtp):
    configure(monkeypatch)
    mailer.send_mail("a@example.com", "Hi", "body text")
    names = [c[0] for c in smtp.calls]
    assert names.index("starttls") < names.index("login") < names.index("send")
    # smtplib.SMTP() takes no ssl context (only SMTP_SSL does); the context is handed to starttls().
    assert ("connect", "smtp.example.com", 587, 10.0, False) in smtp.calls
    assert ("starttls", True) in smtp.calls
    assert smtp.calls[-1] == ("quit",)
    assert ("send", "a@example.com", "Hi", "body text\n") in smtp.calls


def test_ssl_mode_uses_port_465_and_no_starttls(monkeypatch, smtp):
    configure(monkeypatch, SMTP_SECURITY="ssl")
    mailer.send_mail("a@example.com", "Hi", "body")
    assert ("connect", "smtp.example.com", 465, 10.0, True) in smtp.calls
    assert "starttls" not in [c[0] for c in smtp.calls]


def test_a_refused_recipient_is_reported_as_rejected(monkeypatch, smtp):
    configure(monkeypatch)
    smtp.refuse = True
    with pytest.raises(mailer.MailError) as err:
        mailer.send_mail("nobody@example.com", "Hi", "body")
    assert err.value.rejected is True


@pytest.mark.parametrize("error", [ConnectionRefusedError("down"), TimeoutError("slow"),
                                   smtplib.SMTPAuthenticationError(535, b"bad login")])
def test_network_and_login_failures_become_mail_errors(monkeypatch, smtp, error):
    configure(monkeypatch)
    smtp.connect_error = error
    with pytest.raises(mailer.MailError) as err:
        mailer.send_mail("a@example.com", "Hi", "body")
    assert err.value.rejected is False


def test_development_without_smtp_logs_the_mail_instead(caplog):
    with caplog.at_level(logging.WARNING, logger="trustvault.mail"):
        mailer.send_mail("a@example.com", "Hi", "http://localhost/register/complete?token=abc")
    assert "register/complete?token=abc" in caplog.text


def test_production_never_pretends_to_send(monkeypatch):
    monkeypatch.setenv("COOKIE_SECURE", "1")
    with pytest.raises(mailer.MailError):
        mailer.send_mail("a@example.com", "Hi", "body")


# ------------------------------------------------------------ start-up validation
def test_production_requires_smtp_and_an_https_base_url(monkeypatch):
    with pytest.raises(RuntimeError):
        mailer.validate_configuration(production=True)                      # nothing set
    configure(monkeypatch, APP_BASE_URL="http://vault.example")
    with pytest.raises(RuntimeError):
        mailer.validate_configuration(production=True)                      # not https
    configure(monkeypatch, SMTP_SECURITY="none", APP_BASE_URL="https://vault.example")
    with pytest.raises(RuntimeError):
        mailer.validate_configuration(production=True)                      # clear-text SMTP
    configure(monkeypatch, SMTP_SECURITY="starttls")
    mailer.validate_configuration(production=True)                          # fine


def test_development_may_run_without_smtp_but_bad_settings_still_fail(monkeypatch):
    mailer.validate_configuration(production=False)
    monkeypatch.setenv("SMTP_SECURITY", "carrier-pigeon")
    with pytest.raises(RuntimeError):
        mailer.validate_configuration(production=False)
    monkeypatch.setenv("SMTP_SECURITY", "starttls")
    monkeypatch.setenv("SMTP_USER", "me")                                   # user without password
    with pytest.raises(RuntimeError):
        mailer.validate_configuration(production=False)


def test_links_use_app_base_url_not_the_request_host(monkeypatch):
    class Req:                                                              # forged Host header
        url_root = "http://evil.example/"
    assert mailer.base_url(Req()) == "http://evil.example"                  # dev fallback only
    monkeypatch.setenv("APP_BASE_URL", "https://vault.example/")
    assert mailer.base_url(Req()) == "https://vault.example"
    monkeypatch.delenv("APP_BASE_URL")
    monkeypatch.setenv("COOKIE_SECURE", "1")
    with pytest.raises(mailer.MailError):
        mailer.base_url(Req())
