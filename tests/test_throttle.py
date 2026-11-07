"""Rate limiting by username AND by IP address."""
import os

import pytest

import auth
import database
from conftest import PASSWORD

pytestmark = pytest.mark.db


def test_one_ip_cannot_spray_many_usernames(make_user, browser, events):
    attacker, innocent_ip = browser(), browser()
    for i in range(auth.MAX_FAILED_LOGINS_PER_IP):                          # 1 try each on 10 usernames
        assert attacker.login(f"nobody{i}{os.urandom(2).hex()}", "wrong-password-1").status_code == 401
    victim = make_user("viewer")
    assert attacker.login(victim["username"], PASSWORD).status_code == 429   # even the RIGHT password
    assert any(r["action"] == "THROTTLED" and r["ip_address"] == attacker.ip
               for r in database.fetch_all("SELECT * FROM audit_log WHERE action='THROTTLED'"))
    assert innocent_ip.login(victim["username"], PASSWORD).status_code == 302  # other IPs unaffected


def test_username_lockout_still_applies_when_attempts_come_from_many_ips(make_user, browser):
    victim = make_user("viewer")
    for _ in range(auth.MAX_FAILED_LOGINS):                                  # 5 different IPs, 1 try each
        assert browser().login(victim["username"], "wrong-password-1").status_code == 401
    assert browser().login(victim["username"], PASSWORD).status_code == 429


def test_sign_up_emails_are_limited_per_ip(browser, mailbox):
    b = browser()
    for _ in range(auth.MAX_REGISTRATIONS_PER_IP):
        name = "new" + os.urandom(4).hex()
        assert b.post("/register", {"email": f"{name}@example.com"}).status_code == 200
    extra = "new" + os.urandom(4).hex()
    assert b.post("/register", {"email": f"{extra}@example.com"}).status_code == 429
    assert not mailbox.to(f"{extra}@example.com")
    other = "new" + os.urandom(4).hex()
    assert browser().post("/register", {"email": f"{other}@example.com"}).status_code == 200


def test_password_reset_requests_are_limited_per_ip(make_user, browser):
    b = browser()
    for i in range(auth.MAX_RESET_REQUESTS_PER_IP):
        assert b.post("/forgot-password", {"username": f"x{i}"}).status_code == 302
    assert b.post("/forgot-password", {"username": "again"}).status_code == 429


def test_password_change_attempts_are_limited(make_user, browser, events):
    user = make_user("viewer")
    b = browser(user)
    for _ in range(auth.MAX_FAILED_LOGINS):
        assert b.post("/account/password", {"current": "wrong-password-1", "new": "Qx9-new-passphrase-7",
                                            "confirm": "Qx9-new-passphrase-7"}).status_code == 401
    r = b.post("/account/password", {"current": PASSWORD, "new": "Qx9-new-passphrase-7",
                                     "confirm": "Qx9-new-passphrase-7"})
    assert r.status_code == 429
