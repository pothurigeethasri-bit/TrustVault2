"""Audit trail tests: everything is recorded (including failures) and cannot be altered."""
import psycopg2
import pytest

import audit
import database
from conftest import PASSWORD
from harden_db import apply_grants, app_url, create_role

pytestmark = pytest.mark.db


def rows_for(events, username):
    return [(e["action"], e["result"]) for e in reversed(events(username=username))]


def test_every_step_of_the_brief_example_is_recorded(make_user, browser, upload_doc, events):
    geetha, ravi, sita = make_user("owner", "geetha"), make_user("viewer", "ravi"), make_user("viewer", "sita")
    g, r, s = browser(geetha), browser(ravi), browser(sita)
    doc_id, _ = upload_doc(g)
    g.post(f"/documents/{doc_id}/grant", {"user_id": ravi["id"], "access_level": "read"})
    r.get(f"/documents/{doc_id}/view")
    r.get(f"/documents/{doc_id}/download")
    s.get(f"/documents/{doc_id}/view")
    g.post(f"/documents/{doc_id}/revoke", {"user_id": ravi["id"]})

    assert rows_for(events, ravi["username"]) == [
        ("LOGIN", "SUCCESS"), ("VIEW_DOCUMENT", "SUCCESS"), ("DOWNLOAD_DOCUMENT", "SUCCESS")]
    assert rows_for(events, sita["username"]) == [("LOGIN", "SUCCESS"), ("VIEW_DOCUMENT", "DENIED")]
    g_rows = rows_for(events, geetha["username"])
    assert ("GRANT_ACCESS", "SUCCESS") in g_rows and g_rows[-1] == ("REVOKE_ACCESS", "SUCCESS")

    # Details a reviewer needs: who, which document, from where.
    denied = events(username=sita["username"], action="VIEW_DOCUMENT")[0]
    assert denied["document_id"] == doc_id and denied["ip_address"]
    revoke_row = events(username=geetha["username"], action="REVOKE_ACCESS")[0]
    assert revoke_row["target_user_id"] == ravi["id"]


def test_failed_login_and_failed_registration_are_recorded(make_user, browser, events):
    user = make_user("viewer")
    b = browser()
    b.login(user["username"], "wrong-password-1")
    b.post("/register", {"username": user["username"], "password": PASSWORD, "confirm": PASSWORD})
    got = rows_for(events, user["username"])
    assert ("LOGIN", "FAILURE") in got and ("REGISTER_USER", "FAILURE") in got


def test_document_history_is_shown_to_the_owner_only(make_user, browser, upload_doc):
    owner, other = make_user("owner"), make_user("owner")
    o, x = browser(owner), browser(other)
    doc_id, _ = upload_doc(o)
    page = o.get(f"/documents/{doc_id}/share")
    assert page.status_code == 200 and b"Access history" in page.data
    assert x.get(f"/documents/{doc_id}/share").status_code == 403


# ------------------------------------------------------------- immutability
@pytest.mark.parametrize("sql", [
    "UPDATE audit_log SET result = 'SUCCESS'",
    "UPDATE audit_log SET username = 'someone-else' WHERE id = (SELECT min(id) FROM audit_log)",
    "DELETE FROM audit_log",
    "DELETE FROM audit_log WHERE id = (SELECT min(id) FROM audit_log)",
    "TRUNCATE audit_log",
])
def test_audit_rows_cannot_be_changed_or_deleted(make_user, browser, sql):
    browser(make_user("viewer"))                       # make sure at least one row exists
    before = database.fetch_one("SELECT count(*) AS n FROM audit_log")["n"]
    with pytest.raises(psycopg2.Error) as err:
        database.execute(sql)
    assert "append-only" in str(err.value)
    assert database.fetch_one("SELECT count(*) AS n FROM audit_log")["n"] == before


def test_no_web_route_can_modify_the_audit_log(app):
    for rule in app.url_map.iter_rules():
        if "audit" in rule.rule:
            assert rule.methods <= {"GET", "HEAD", "OPTIONS"}, rule.rule


def test_app_database_role_gets_insert_and_select_only(app):
    """The 'restricted database user' hardening, proven against a real role."""
    import os
    role, pw = "tv_app_" + os.urandom(3).hex(), "Zq7-role-password-42"
    owner = database.get_connection()
    try:
        try:
            with owner, owner.cursor() as cur:
                create_role(cur, role, pw)
                apply_grants(cur, role)
        except psycopg2.errors.InsufficientPrivilege:
            pytest.skip("test database user may not create roles")
        app_conn = psycopg2.connect(app_url(os.environ["DATABASE_URL"], role, pw))
        try:
            for sql in ("UPDATE audit_log SET result = 'SUCCESS'", "DELETE FROM audit_log",
                        "TRUNCATE audit_log", "DROP TABLE audit_log",
                        "ALTER TABLE audit_log DISABLE TRIGGER audit_no_update_delete",
                        "DROP TRIGGER audit_no_update_delete ON audit_log"):
                with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                    with app_conn, app_conn.cursor() as cur:
                        cur.execute(sql)
            with app_conn, app_conn.cursor() as cur:       # what the app needs still works
                cur.execute("SELECT count(*) FROM audit_log")
                cur.execute("SELECT count(*) FROM users")
        finally:
            app_conn.close()
    finally:
        with owner, owner.cursor() as cur:
            cur.execute(f'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM "{role}"')
            cur.execute(f'REVOKE ALL ON SCHEMA public FROM "{role}"')
            cur.execute(f'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM "{role}"')
            cur.execute(f'DROP ROLE "{role}"')
        owner.close()


# ------------------------------------------------------- tamper evidence
def test_hash_chain_detects_an_edit_made_behind_the_apps_back(make_user, browser):
    """Even someone who can switch the triggers off (a superuser) cannot edit a row
    without the admin integrity check catching it."""
    admin = make_user("admin")
    a = browser(admin)
    victim = make_user("viewer")
    browser().login(victim["username"], "wrong-password-1")           # a FAILURE row to 'clean up'
    assert audit.verify_chain() == (True, None)

    row = database.fetch_one("SELECT id, details FROM audit_log WHERE username = %s ORDER BY id DESC LIMIT 1",
                             (victim["username"],))

    def tamper(details):
        conn = database.get_connection()
        try:
            with conn, conn.cursor() as cur:
                cur.execute("ALTER TABLE audit_log DISABLE TRIGGER audit_no_update_delete")
                cur.execute("UPDATE audit_log SET details = %s WHERE id = %s", (details, row["id"]))
                cur.execute("ALTER TABLE audit_log ENABLE TRIGGER audit_no_update_delete")
        finally:
            conn.close()

    try:
        tamper("nothing to see here")
        assert audit.verify_chain() == (False, row["id"])
        r = a.post("/admin/integrity")
        assert r.status_code == 302
        assert b"TAMPERING DETECTED" in a.get("/admin").data
        assert database.fetch_one("SELECT result FROM audit_log WHERE action = 'AUDIT_INTEGRITY_CHECK' "
                                  "ORDER BY id DESC LIMIT 1")["result"] == "FAILURE"
    finally:
        tamper(row["details"])                                        # put it back for the other tests
    assert audit.verify_chain() == (True, None)


def test_integrity_check_passes_on_an_untouched_log(make_user, browser):
    a = browser(make_user("admin"))
    assert a.post("/admin/integrity").status_code == 302
    page = a.get("/admin").data
    assert b"Chain intact" in page and b"TAMPERED" not in page
