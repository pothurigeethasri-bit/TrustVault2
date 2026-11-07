"""Security-PIN gate: nothing (login, register, dashboards) is reachable until the PIN is entered."""
import pytest

import database
import pin_gate
from conftest import PASSWORD

PIN = "482913"
pytestmark = pytest.mark.db


@pytest.fixture()
def gate(monkeypatch):
    monkeypatch.setenv("ACCESS_PIN", PIN)


def pin_rows(ip):
    return database.fetch_all(
        "SELECT * FROM audit_log WHERE action = 'PIN_ATTEMPT' AND ip_address = %s ORDER BY id", (ip,))


def test_login_and_register_are_hidden_until_the_pin_is_entered(gate, browser):
    anon = browser()
    for url in ["/", "/login", "/register", "/forgot-password", "/owner", "/viewer", "/admin",
                "/account/password", "/documents/1/download"]:
        r = anon.get(url)
        assert r.status_code == 302 and "/pin" in r.headers["Location"], url


def test_posting_credentials_without_the_pin_does_nothing(gate, make_user, browser):
    user = make_user("viewer")
    anon = browser()
    r = anon.login(user["username"], PASSWORD)
    assert r.status_code == 302 and "/pin" in r.headers["Location"]
    assert anon.get("/viewer").status_code == 302 and "/pin" in anon.get("/viewer").headers["Location"]
    # the login handler never ran, so no LOGIN row exists for this user
    assert not database.fetch_all("SELECT 1 FROM audit_log WHERE action='LOGIN' AND username=%s",
                                  (user["username"],))


def test_pin_page_health_check_and_static_files_stay_open(gate, browser):
    anon = browser()
    assert anon.get("/pin").status_code == 200
    assert anon.get("/healthz").status_code == 200
    assert anon.get("/static/css/style.css").status_code == 200


def test_correct_pin_unlocks_login_and_registration_then_sign_in_works(gate, make_user, browser):
    user = make_user("viewer")
    b = browser()
    r = b.post("/pin", {"pin": PIN})
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")
    assert b.get("/login").status_code == 200
    assert b.get("/register").status_code == 200
    assert b.login(user["username"], PASSWORD).status_code == 302
    assert b.get("/viewer").status_code == 200
    # signing out keeps the PIN state: the person is not asked again on the same browser
    b.post("/logout")
    assert b.get("/login").status_code == 200


def test_wrong_pin_is_refused_and_audited_without_storing_the_guess(gate, browser):
    b = browser()
    assert b.post("/pin", {"pin": "000000"}).status_code == 401
    assert b.get("/login").status_code == 302
    rows = pin_rows(b.ip)
    assert [(r["result"]) for r in rows] == ["FAILURE"]
    assert "000000" not in str(rows) and PIN not in str(rows)


def test_successful_pin_is_audited(gate, browser):
    b = browser()
    b.post("/pin", {"pin": PIN})
    assert [r["result"] for r in pin_rows(b.ip)] == ["SUCCESS"]


def test_pin_guessing_is_throttled_per_ip_even_for_the_right_pin(gate, browser):
    attacker, other = browser(), browser()
    for _ in range(pin_gate.MAX_PIN_FAILURES_PER_IP):
        assert attacker.post("/pin", {"pin": "111111"}).status_code == 401
    assert attacker.post("/pin", {"pin": PIN}).status_code == 429          # locked out
    assert attacker.get("/login").status_code == 302                       # and still not in
    assert any(r["result"] == "DENIED" for r in pin_rows(attacker.ip))
    assert other.post("/pin", {"pin": PIN}).status_code == 302             # a different IP is unaffected


def test_pin_cannot_redirect_to_another_site(gate, browser):
    for evil in ("//evil.example", "https://evil.example", "javascript:alert(1)"):
        b = browser()
        r = b.post(f"/pin?next={evil}", {"pin": PIN})
        assert r.status_code == 302 and "evil" not in r.headers["Location"]


def test_deep_link_returns_to_the_page_after_the_pin(gate, browser):
    b = browser()
    r = b.get("/register")
    assert r.headers["Location"].endswith("/pin?next=/register")
    assert b.post(r.headers["Location"], {"pin": PIN}).headers["Location"].endswith("/register")


def test_changing_the_pin_locks_everyone_out_again(gate, browser, monkeypatch):
    b = browser()
    b.post("/pin", {"pin": PIN})
    assert b.get("/login").status_code == 200
    monkeypatch.setenv("ACCESS_PIN", "739204")                              # rotate the PIN
    r = b.get("/login")
    assert r.status_code == 302 and "/pin" in r.headers["Location"]


def test_gate_is_off_when_no_pin_is_configured(browser, monkeypatch):
    monkeypatch.setenv("ACCESS_PIN", "")
    assert browser().get("/login").status_code == 200


def test_pin_post_needs_a_csrf_token(gate, browser):
    assert browser().post("/pin", {"pin": PIN}, csrf=False).status_code == 400


# ---- pure unit tests (no database needed) -------------------------------------------
@pytest.mark.parametrize("target,ok", [("/register", True), ("/a?b=1", True), ("//evil.com", False),
                                       ("https://evil.com", False), ("evil.com", False), ("", False)])
def test_safe_next(target, ok):
    assert (pin_gate._safe_next(target) is not None) is ok


def test_production_refuses_to_start_without_a_pin(monkeypatch):
    monkeypatch.setenv("ACCESS_PIN", "")
    with pytest.raises(RuntimeError):
        pin_gate.validate_configuration(secure_mode=True)
    pin_gate.validate_configuration(secure_mode=False)                      # dev is fine


def test_short_pins_are_rejected_at_startup(monkeypatch):
    monkeypatch.setenv("ACCESS_PIN", "1234")
    with pytest.raises(RuntimeError):
        pin_gate.validate_configuration(secure_mode=False)
