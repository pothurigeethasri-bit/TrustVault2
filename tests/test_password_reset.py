"""Password change (user) and password reset (admin), including audit and session effects."""
import pytest

import auth
import database
from conftest import PASSWORD

pytestmark = pytest.mark.db
NEW = "Qx9-new-passphrase-7"


@pytest.fixture()
def admin(make_user, browser):
    return browser(make_user("admin", "adm"))


def reset(admin_b, user):
    r = admin_b.post(f"/admin/users/{user['id']}/reset-password")
    assert r.status_code == 200
    html = r.data.decode()
    marker = "temp-pw-code\">"
    return html.split(marker)[1].split("<")[0]


# ------------------------------------------------------------- user changes own password
def test_user_changes_password_and_other_sessions_end(make_user, browser, events):
    user = make_user("viewer")
    laptop, phone = browser(user), browser(user)
    assert laptop.post("/account/password", {"current": PASSWORD, "new": NEW, "confirm": NEW}).status_code == 302
    assert laptop.get("/viewer").status_code == 200                   # this browser stays signed in
    assert phone.get("/viewer").status_code == 302                    # the other device is signed out
    assert browser().login(user["username"], PASSWORD).status_code == 401
    assert browser().login(user["username"], NEW).status_code == 302
    row = events(username=user["username"], action="PASSWORD_CHANGE")[0]
    assert row["result"] == "SUCCESS" and row["target_user_id"] == user["id"]


@pytest.mark.parametrize("current,new,confirm,status", [
    ("wrong-password-1", NEW, NEW, 401),        # wrong current password
    (PASSWORD, NEW, NEW + "x", 400),            # confirmation mismatch
    (PASSWORD, PASSWORD, PASSWORD, 400),        # same as current
    (PASSWORD, "short1", "short1", 400),        # too short
    (PASSWORD, "password123", "password123", 400),  # too common
])
def test_bad_password_changes_are_refused_and_logged(make_user, browser, events, current, new, confirm, status):
    user = make_user("viewer")
    b = browser(user)
    assert b.post("/account/password", {"current": current, "new": new, "confirm": confirm}).status_code == status
    assert events(username=user["username"], action="PASSWORD_CHANGE")[0]["result"] == "FAILURE"
    assert browser().login(user["username"], PASSWORD).status_code == 302   # password unchanged


def test_password_change_requires_login_and_csrf(make_user, browser):
    assert browser().get("/account/password").status_code == 302
    b = browser(make_user("viewer"))
    assert b.post("/account/password", {"current": PASSWORD, "new": NEW, "confirm": NEW}, csrf=False).status_code == 400


# ------------------------------------------------------------------------- admin reset
def test_admin_reset_full_flow(admin, make_user, browser, events):
    user = make_user("viewer", "ravi")
    old_session = browser(user)
    temp = reset(admin, user)
    assert len(temp) == 14 and auth.validate_password(temp, user["username"]) is None

    assert old_session.get("/viewer").status_code == 302                    # old session ended at once
    assert browser().login(user["username"], PASSWORD).status_code == 401   # old password dead

    b = browser()
    assert b.login(user["username"], temp).status_code == 302               # temp password works...
    for url in ("/viewer", "/dashboard", "/"):                              # ...but only to change it
        r = b.get(url)
        assert r.status_code == 302 and r.headers["Location"].endswith("/account/password")
    assert b.get("/account/password").status_code == 200
    assert b.post("/account/password", {"current": temp, "new": NEW, "confirm": NEW}).status_code == 302
    assert b.get("/viewer").status_code == 200                              # forced step is over
    assert browser().login(user["username"], temp).status_code == 401       # temp password is one-shot


def test_reset_is_audited_and_never_logs_the_password(admin, make_user):
    user = make_user("viewer")
    temp = reset(admin, user)
    rows = database.fetch_all("SELECT * FROM audit_log WHERE action = 'PASSWORD_RESET_ADMIN' "
                              "AND target_user_id = %s", (user["id"],))
    assert len(rows) == 1 and rows[0]["result"] == "SUCCESS" and rows[0]["username"] == admin.user["username"]
    assert temp not in str(rows)
    page = admin.get("/admin/permissions").data
    assert b"Password Reset Admin" in page and temp.encode() not in page   # page shows readable labels
    assert temp.encode() not in admin.get("/admin/users").data              # shown only once


def test_reset_clears_a_lockout(admin, make_user, browser):
    user = make_user("viewer")
    for _ in range(auth.MAX_FAILED_LOGINS):
        browser().login(user["username"], "wrong-password-1")
    assert browser().login(user["username"], PASSWORD).status_code == 429   # locked
    temp = reset(admin, user)
    assert browser().login(user["username"], temp).status_code == 302       # reset gives a clean slate


def test_only_admins_can_reset_and_denials_are_logged(make_user, browser, events):
    target = make_user("viewer")
    for role in ("owner", "viewer"):
        u = make_user(role)
        assert browser(u).post(f"/admin/users/{target['id']}/reset-password").status_code == 403
        assert any(e["action"] == "ACCESS_DENIED" for e in events(username=u["username"]))
    assert browser().post(f"/admin/users/{target['id']}/reset-password").status_code in (302, 403)
    assert browser().login(target["username"], PASSWORD).status_code == 302  # password untouched


def test_reset_needs_csrf_and_admin_cannot_reset_self_or_unknown(admin, make_user):
    target = make_user("viewer")
    assert admin.post(f"/admin/users/{target['id']}/reset-password", csrf=False).status_code == 400
    assert admin.post(f"/admin/users/{admin.user['id']}/reset-password").status_code == 302
    assert admin.post("/admin/users/99999999/reset-password").status_code == 302
    assert not database.fetch_all("SELECT 1 FROM audit_log WHERE action='PASSWORD_RESET_ADMIN' "
                                  "AND result='SUCCESS' AND target_user_id IN (%s, %s)",
                                  (admin.user["id"], 99999999))


# -------------------------------------------------------------- user asks for a reset
def test_forgot_password_gives_the_same_answer_for_real_and_fake_users(admin, make_user, browser):
    user = make_user("viewer", "sita")
    b1, b2 = browser(), browser()
    a = b1.post("/forgot-password", {"username": user["username"]}, follow_redirects=True)
    c = b2.post("/forgot-password", {"username": "nobody-" + user["username"]}, follow_redirects=True)
    assert a.status_code == c.status_code == 200 and a.data == c.data         # no username enumeration
    assert database.fetch_one("SELECT reset_requested_at FROM users WHERE id = %s",
                              (user["id"],))["reset_requested_at"] is not None


def test_admin_sees_requests_and_a_reset_clears_the_flag(admin, make_user, browser):
    user = make_user("viewer")
    browser().post("/forgot-password", {"username": user["username"]})
    assert b"reset requested" in admin.get("/admin/users").data
    reset(admin, user)
    assert database.fetch_one("SELECT reset_requested_at FROM users WHERE id = %s",
                              (user["id"],))["reset_requested_at"] is None


def test_deactivated_accounts_cannot_request_resets(admin, make_user, browser, events):
    user = make_user("viewer")
    admin.post(f"/admin/users/{user['id']}/active", {"active": "0"})
    browser().post("/forgot-password", {"username": user["username"]})
    assert database.fetch_one("SELECT reset_requested_at FROM users WHERE id = %s",
                              (user["id"],))["reset_requested_at"] is None
    assert events(username=user["username"], action="PASSWORD_RESET_REQUEST")[0]["result"] == "FAILURE"


def test_forgot_password_events_appear_in_the_security_feed(make_user, browser, admin):
    browser().post("/forgot-password", {"username": "ghost" + make_user("viewer")["username"]})
    assert b"Password Reset Request" in admin.get("/admin/security").data
