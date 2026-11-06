"""Admin console tests: access, user/role management, activity feeds."""
import pytest

import database

pytestmark = pytest.mark.db

ADMIN_GETS = ["/admin", "/admin/users", "/admin/activity", "/admin/permissions",
              "/admin/security", "/admin/audit"]


@pytest.fixture()
def admin(make_user, browser):
    return browser(make_user("admin", "adm"))


def test_every_admin_page_renders_for_an_admin(admin):
    for url in ADMIN_GETS:
        r = admin.get(url)
        assert r.status_code == 200, url
        assert b"Admin" in r.data or b"admin" in r.data


def test_non_admins_are_blocked_from_every_admin_route(make_user, browser, events):
    owner, viewer = make_user("owner"), make_user("viewer")
    target = make_user("viewer")
    for user in (owner, viewer):
        b = browser(user)
        for url in ADMIN_GETS:
            assert b.get(url).status_code == 403, url
        assert b.post(f"/admin/users/{target['id']}/role", {"role": "admin"}).status_code == 403
        assert b.post(f"/admin/users/{target['id']}/active", {"active": "0"}).status_code == 403
        assert b.post("/admin/integrity").status_code == 403
        assert any(e["action"] == "ACCESS_DENIED" for e in events(username=user["username"]))
    assert database.fetch_one("SELECT role, is_active FROM users WHERE id = %s", (target["id"],)) \
        == {"role": "viewer", "is_active": True}


def test_anonymous_cannot_reach_admin_routes(browser):
    anon = browser()
    for url in ADMIN_GETS:
        assert anon.get(url).status_code == 302
    assert anon.post("/admin/integrity").status_code in (302, 403)


def test_role_change_takes_effect_at_once_and_is_audited(admin, make_user, browser, events):
    ravi = make_user("viewer", "ravi")
    r = browser(ravi)
    assert r.get("/owner").status_code == 403
    assert admin.post(f"/admin/users/{ravi['id']}/role", {"role": "owner"}).status_code == 302
    assert r.get("/owner").status_code == 200                            # no re-login needed
    row = events(username=admin.user["username"], action="CHANGE_ROLE")[0]
    assert row["result"] == "SUCCESS" and row["target_user_id"] == ravi["id"]
    assert "viewer -> owner" in row["details"]
    page = admin.get("/admin/permissions").data
    assert ravi["username"].encode() in page and b"viewer -&gt; owner" in page


def test_invalid_role_values_are_rejected_and_logged(admin, make_user, events):
    ravi = make_user("viewer")
    for bad in ["superadmin", "", "ADMIN ", "owner; DROP TABLE users"]:
        admin.post(f"/admin/users/{ravi['id']}/role", {"role": bad})
    assert database.fetch_one("SELECT role FROM users WHERE id = %s", (ravi["id"],))["role"] == "viewer"
    assert len([e for e in events(username=admin.user["username"], action="CHANGE_ROLE")
                if e["result"] == "FAILURE"]) == 4
    admin.post("/admin/users/99999999/role", {"role": "owner"})            # unknown user: no crash
    admin.post("/admin/users/99999999/active", {"active": "0"})


def test_admin_cannot_demote_or_deactivate_themselves(admin, events):
    me = admin.user["id"]
    admin.post(f"/admin/users/{me}/role", {"role": "viewer"})
    admin.post(f"/admin/users/{me}/active", {"active": "0"})
    row = database.fetch_one("SELECT role, is_active FROM users WHERE id = %s", (me,))
    assert row == {"role": "admin", "is_active": True}
    assert admin.get("/admin").status_code == 200
    assert len([e for e in events(username=admin.user["username"]) if e["result"] == "FAILURE"]) == 2


def test_deactivate_and_reactivate_round_trip(admin, make_user, browser, events):
    ravi = make_user("viewer", "ravi")
    r = browser(ravi)
    assert r.get("/viewer").status_code == 200
    admin.post(f"/admin/users/{ravi['id']}/active", {"active": "0"})
    assert r.get("/viewer").status_code == 302                             # session ended
    admin.post(f"/admin/users/{ravi['id']}/active", {"active": "1"})
    assert browser(ravi).get("/viewer").status_code == 200                 # can log in again
    acts = [e["action"] for e in events(username=admin.user["username"])]
    assert "DEACTIVATE_USER" in acts and "ACTIVATE_USER" in acts


def test_feeds_show_the_right_events(admin, make_user, browser, upload_doc):
    geetha, ravi, sita = make_user("owner", "geetha"), make_user("viewer", "ravi"), make_user("viewer", "sita")
    g, r, s = browser(geetha), browser(ravi), browser(sita)
    doc_id, _ = upload_doc(g, name="Feed_Check.pdf")
    g.post(f"/documents/{doc_id}/grant", {"user_id": ravi["id"], "access_level": "read"})
    r.get(f"/documents/{doc_id}/download")
    s.get(f"/documents/{doc_id}/view")
    browser().login(sita["username"], "wrong-password-1")

    activity = admin.get("/admin/activity", query_string={"user": sita["username"]}).data
    assert sita["username"].encode() in activity and b"DENIED" in activity
    assert b"Feed_Check.pdf" in admin.get("/admin/activity", query_string={"user": ravi["username"]}).data

    perms = admin.get("/admin/permissions", query_string={"user": geetha["username"]}).data
    assert b"Grant Access" in perms and ravi["username"].encode() in perms     # target shown by name

    sec = admin.get("/admin/security", query_string={"user": sita["username"]}).data
    assert b"DENIED" in sec and b"FAILURE" in sec and b"SUCCESS" not in sec    # problems only
    assert ravi["username"].encode() not in sec

    log = admin.get("/admin/audit", query_string={"user": ravi["username"], "action": "DOWNLOAD_DOCUMENT"}).data
    assert b"<td>Download Document</td>" in log and b"<td>View Document</td>" not in log


def test_filters_and_paging_survive_hostile_input(admin):
    for qs in [{"page": "abc"}, {"page": "-5"}, {"page": "99999999999999"}, {"page": "0"},
               {"user": "%"}, {"user": "_"}, {"user": "' OR 1=1 --"}, {"user": "\\"},
               {"result": "NOPE"}, {"action": "NOPE"}, {"user": "x" * 5000}]:
        assert admin.get("/admin/audit", query_string=qs).status_code == 200, qs


def test_user_input_is_escaped_in_admin_tables(admin, browser):
    evil = '<script>alert(1)</script>'
    browser().login(evil, "wrong-password-1")                               # lands in the audit log
    page = admin.get("/admin/security").data
    assert b"<script>alert(1)</script>" not in page
    assert b"&lt;script&gt;" in page
