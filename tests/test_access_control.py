"""Security tests: unauthorised access, direct URLs, immediate revoke, role limits.

Every test runs the real Flask app against a real PostgreSQL database.
"""
import io
import os

import pytest

import database
from conftest import PASSWORD, make_pdf

pytestmark = pytest.mark.db


@pytest.fixture()
def cast(make_user, browser):
    """Geetha (owner), Ravi + Sita (viewers) - the example from the project brief."""
    geetha, ravi, sita = make_user("owner", "geetha"), make_user("viewer", "ravi"), make_user("viewer", "sita")
    return {"geetha": geetha, "ravi": ravi, "sita": sita,
            "g": browser(geetha), "r": browser(ravi), "s": browser(sita)}


def grant(owner_b, doc_id, user, level="read"):
    return owner_b.post(f"/documents/{doc_id}/grant", {"user_id": user["id"], "access_level": level})


def revoke(owner_b, doc_id, user):
    return owner_b.post(f"/documents/{doc_id}/revoke", {"user_id": user["id"]})


# ------------------------------------------------------------ the brief's scenario
def test_brief_scenario_share_block_revoke(cast, upload_doc):
    doc_id, content = upload_doc(cast["g"])

    assert cast["r"].get(f"/documents/{doc_id}/view").status_code == 403      # not yet shared
    assert grant(cast["g"], doc_id, cast["ravi"]).status_code == 302

    ok = cast["r"].get(f"/documents/{doc_id}/download")
    assert ok.status_code == 200 and ok.data == content                       # Ravi can open it
    assert cast["s"].get(f"/documents/{doc_id}/view").status_code == 403      # Sita is blocked
    assert cast["s"].get(f"/documents/{doc_id}/download").status_code == 403

    assert revoke(cast["g"], doc_id, cast["ravi"]).status_code == 302
    after = cast["r"].get(f"/documents/{doc_id}/download")                    # stops IMMEDIATELY
    assert after.status_code == 403 and content not in after.data
    assert cast["r"].get(f"/documents/{doc_id}/view").status_code == 403


def test_revoke_stops_access_on_the_very_next_request_every_time(cast, upload_doc):
    doc_id, _ = upload_doc(cast["g"])
    for _ in range(3):                                      # grant/revoke cycles never leak access
        grant(cast["g"], doc_id, cast["ravi"])
        assert cast["r"].get(f"/documents/{doc_id}/view").status_code == 200
        revoke(cast["g"], doc_id, cast["ravi"])
        assert cast["r"].get(f"/documents/{doc_id}/view").status_code == 403


# ------------------------------------------------------- unauthenticated + direct URLs
def test_anonymous_is_redirected_from_every_protected_url(cast, upload_doc, browser):
    doc_id, content = upload_doc(cast["g"])
    anon = browser()
    for url in ["/owner", "/viewer", "/admin", "/admin/users", "/admin/audit", "/dashboard",
                f"/documents/{doc_id}/view", f"/documents/{doc_id}/download",
                f"/documents/{doc_id}/share", f"/documents/{doc_id}/edit"]:
        r = anon.get(url)
        assert r.status_code == 302 and "/login" in r.headers["Location"], url
        assert content not in r.data


def test_anonymous_cannot_post_actions(cast, upload_doc, browser):
    doc_id, _ = upload_doc(cast["g"])
    anon = browser()
    for url, data in [(f"/documents/{doc_id}/grant", {"user_id": cast["sita"]["id"], "access_level": "read"}),
                      (f"/documents/{doc_id}/delete", {}),
                      ("/documents/upload", {}), ("/admin/integrity", {})]:
        assert anon.post(url, data).status_code in (302, 403), url
    assert database.fetch_one("SELECT 1 AS x FROM documents WHERE id = %s", (doc_id,))
    assert not database.fetch_one("SELECT 1 AS x FROM permissions WHERE document_id = %s", (doc_id,))


def test_files_are_not_reachable_by_direct_url(cast, upload_doc, app):
    doc_id, content = upload_doc(cast["g"])
    stored = database.fetch_one("SELECT stored_name FROM documents WHERE id = %s", (doc_id,))["stored_name"]
    upload_dir = app.config["UPLOAD_DIR"]
    assert os.path.exists(os.path.join(upload_dir, stored))          # it IS on disk...
    for url in [f"/uploads/{stored}", f"/static/{stored}", f"/static/uploads/{stored}",
                f"/static/../uploads/{stored}", f"/uploads/../{stored}", f"/{stored}"]:
        for b in (cast["g"], cast["r"]):                              # ...but no URL serves it, even to its owner
            r = b.get(url)
            assert r.status_code in (404, 308, 400), url
            assert content not in r.data, url


def test_document_ids_cannot_be_walked_by_strangers(cast, upload_doc):
    doc_id, content = upload_doc(cast["g"])
    for i in range(max(1, doc_id - 3), doc_id + 4):
        for path in ("view", "download", "share"):
            r = cast["s"].get(f"/documents/{i}/{path}")
            assert r.status_code == 403 and content not in r.data


def test_missing_and_forbidden_documents_look_identical(cast, upload_doc):
    doc_id, _ = upload_doc(cast["g"])
    real = cast["s"].get(f"/documents/{doc_id}/view")
    missing = cast["s"].get("/documents/99999999/view")
    assert real.status_code == missing.status_code == 403
    assert real.data == missing.data                                  # no "exists but forbidden" oracle


# ------------------------------------------------------------------- role limits
def test_viewer_with_read_access_cannot_edit_delete_upload_or_share(cast, upload_doc):
    doc_id, content = upload_doc(cast["g"])
    grant(cast["g"], doc_id, cast["ravi"])
    r = cast["r"]
    assert r.post(f"/documents/{doc_id}/edit", {"name": "Hacked.pdf"}).status_code == 403
    assert r.post(f"/documents/{doc_id}/delete").status_code == 403
    assert r.post("/documents/upload", {"file": (io.BytesIO(make_pdf()), "x.pdf")},
                  content_type="multipart/form-data").status_code == 403
    assert r.post(f"/documents/{doc_id}/grant", {"user_id": cast["sita"]["id"],
                                                  "access_level": "read"}).status_code == 403
    assert r.post(f"/documents/{doc_id}/revoke", {"user_id": cast["ravi"]["id"]}).status_code == 403
    assert r.get(f"/documents/{doc_id}/share").status_code == 403
    row = database.fetch_one("SELECT original_name FROM documents WHERE id = %s", (doc_id,))
    assert row["original_name"] == "Salary_Letter.pdf"                # untouched
    assert cast["g"].get(f"/documents/{doc_id}/download").data == content


def test_edit_access_cannot_be_given_to_a_viewer(cast, upload_doc, events):
    doc_id, _ = upload_doc(cast["g"])
    grant(cast["g"], doc_id, cast["ravi"], "edit")
    assert not database.fetch_one(
        "SELECT 1 AS x FROM permissions WHERE document_id = %s AND user_id = %s",
        (doc_id, cast["ravi"]["id"]))
    assert any(e["action"] == "GRANT_ACCESS" and e["result"] == "FAILURE"
               for e in events(document_id=doc_id))


def test_even_a_forced_edit_row_does_not_let_a_viewer_edit(cast, upload_doc):
    doc_id, _ = upload_doc(cast["g"])
    database.execute("INSERT INTO permissions (document_id, user_id, access_level, granted_by) "
                     "VALUES (%s,%s,'edit',%s)", (doc_id, cast["ravi"]["id"], cast["geetha"]["id"]))
    assert cast["r"].post(f"/documents/{doc_id}/edit", {"name": "Hacked.pdf"}).status_code == 403
    assert database.fetch_one("SELECT original_name FROM documents WHERE id = %s",
                              (doc_id,))["original_name"] == "Salary_Letter.pdf"


def test_owner_role_with_edit_access_can_edit_until_revoked(cast, make_user, browser, upload_doc):
    meena = make_user("owner", "meena")
    m = browser(meena)
    doc_id, _ = upload_doc(cast["g"])
    assert m.post(f"/documents/{doc_id}/edit", {"name": "Nope.pdf"}).status_code == 403   # no access yet
    grant(cast["g"], doc_id, meena, "edit")
    assert m.post(f"/documents/{doc_id}/edit", {"name": "Renamed.pdf"}).status_code == 302
    assert database.fetch_one("SELECT original_name FROM documents WHERE id = %s",
                              (doc_id,))["original_name"] == "Renamed.pdf"
    assert m.post(f"/documents/{doc_id}/delete").status_code == 403        # edit is not ownership
    assert m.post(f"/documents/{doc_id}/grant", {"user_id": cast["sita"]["id"],
                                                  "access_level": "read"}).status_code == 403
    revoke(cast["g"], doc_id, meena)
    assert m.post(f"/documents/{doc_id}/edit", {"name": "Again.pdf"}).status_code == 403


def test_another_owner_cannot_touch_my_documents(cast, make_user, browser, upload_doc):
    meena = make_user("owner", "meena")
    m = browser(meena)
    doc_id, content = upload_doc(cast["g"])
    assert m.get(f"/documents/{doc_id}/view").status_code == 403
    assert m.get(f"/documents/{doc_id}/share").status_code == 403
    assert m.post(f"/documents/{doc_id}/delete").status_code == 403
    assert m.post(f"/documents/{doc_id}/grant", {"user_id": meena["id"], "access_level": "read"}).status_code == 403
    assert cast["g"].get(f"/documents/{doc_id}/download").data == content


def test_admin_manages_the_system_but_cannot_read_documents(cast, make_user, browser, upload_doc):
    admin = make_user("admin", "adm")
    a = browser(admin)
    doc_id, content = upload_doc(cast["g"])
    assert a.get("/admin").status_code == 200
    r = a.get(f"/documents/{doc_id}/download")
    assert r.status_code == 403 and content not in r.data
    assert a.post(f"/documents/{doc_id}/delete").status_code == 403


def test_pages_are_limited_to_their_role_and_denials_are_logged(cast, make_user, browser, events):
    owner_b, viewer_b = cast["g"], cast["r"]
    assert viewer_b.get("/owner").status_code == 403
    assert owner_b.get("/viewer").status_code == 403
    assert owner_b.get("/admin").status_code == 403
    assert viewer_b.get("/admin/users").status_code == 403
    for name in ("ravi", "geetha"):
        user = cast[name]
        assert any(e["action"] == "ACCESS_DENIED" and e["result"] == "DENIED"
                   for e in events(username=user["username"])), name


def test_demoted_owner_loses_ownership_powers_immediately(cast, make_user, browser, upload_doc):
    admin = make_user("admin", "adm")
    a = browser(admin)
    doc_id, _ = upload_doc(cast["g"])
    assert cast["g"].get(f"/documents/{doc_id}/share").status_code == 200
    a.post(f"/admin/users/{cast['geetha']['id']}/role", {"role": "viewer"})
    assert cast["g"].get(f"/documents/{doc_id}/share").status_code == 403
    assert cast["g"].post(f"/documents/{doc_id}/delete").status_code == 403
    assert cast["g"].post(f"/documents/{doc_id}/grant", {"user_id": cast["sita"]["id"],
                                                          "access_level": "read"}).status_code == 403
    assert database.fetch_one("SELECT 1 AS x FROM documents WHERE id = %s", (doc_id,))


def test_deactivated_user_is_cut_off_on_the_next_request(cast, make_user, browser, upload_doc):
    admin = make_user("admin", "adm")
    a = browser(admin)
    doc_id, _ = upload_doc(cast["g"])
    grant(cast["g"], doc_id, cast["ravi"])
    assert cast["r"].get(f"/documents/{doc_id}/view").status_code == 200
    a.post(f"/admin/users/{cast['ravi']['id']}/active", {"active": "0"})
    r = cast["r"].get(f"/documents/{doc_id}/view")
    assert r.status_code == 302 and "/login" in r.headers["Location"]         # session is dead
    assert browser().login(cast["ravi"]["username"], PASSWORD).status_code == 401   # cannot log back in


# ------------------------------------------------------------------ CSRF + sessions
def test_state_changes_without_csrf_token_are_rejected_and_logged(cast, upload_doc, events):
    doc_id, _ = upload_doc(cast["g"])
    r = cast["g"].post(f"/documents/{doc_id}/grant",
                       {"user_id": cast["sita"]["id"], "access_level": "read"}, csrf=False)
    assert r.status_code == 400
    r = cast["g"].post(f"/documents/{doc_id}/grant",
                       {"user_id": cast["sita"]["id"], "access_level": "read",
                        "csrf_token": "forged"}, csrf=False)
    assert r.status_code == 400
    assert not database.fetch_one("SELECT 1 AS x FROM permissions WHERE document_id = %s", (doc_id,))
    assert any(e["action"] == "CSRF_FAILURE" and e["result"] == "DENIED"
               for e in events(username=cast["geetha"]["username"]))
    assert cast["g"].post("/logout", csrf=False).status_code == 400


def test_session_cookie_is_httponly_and_samesite(make_user, browser):
    user = make_user("viewer")
    b = browser()
    r = b.login(user["username"], PASSWORD)
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_security_headers_and_no_store(cast):
    r = cast["g"].get("/owner")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store"


def test_downloads_are_attachments_with_nosniff(cast, upload_doc):
    doc_id, content = upload_doc(cast["g"])
    r = cast["g"].get(f"/documents/{doc_id}/download")
    assert r.status_code == 200 and r.data == content
    assert r.headers["Content-Disposition"].startswith("attachment")
    assert r.headers["X-Content-Type-Options"] == "nosniff"


# ------------------------------------------------------------------ login security
def test_account_locks_after_repeated_failures_even_with_the_right_password(make_user, browser, events):
    user = make_user("viewer")
    b = browser()
    for _ in range(5):
        assert b.login(user["username"], "wrong-password-1").status_code == 401
    assert b.login(user["username"], PASSWORD).status_code == 429             # locked out
    rows = events(username=user["username"], action="LOGIN")
    assert sum(e["result"] == "FAILURE" for e in rows) == 5
    assert any(e["result"] == "DENIED" for e in rows)


def test_unknown_user_and_bad_password_give_the_same_response(make_user, browser, events):
    user = make_user("viewer")
    b = browser()
    a = b.login(user["username"], "wrong-password-1")
    c = b.login("nobody-" + user["username"], "wrong-password-1")
    assert a.status_code == c.status_code == 401
    assert a.data == c.data
    assert events(username="nobody-" + user["username"], action="LOGIN")      # failed attempt still recorded


def test_registration_always_creates_a_viewer(browser):
    b = browser()
    name = "newbie" + os.urandom(3).hex()
    r = b.post("/register", {"username": name, "password": PASSWORD, "confirm": PASSWORD,
                             "role": "admin", "is_admin": "1"})
    assert r.status_code == 302
    assert database.fetch_one("SELECT role FROM users WHERE username = %s", (name,))["role"] == "viewer"


def test_sql_injection_attempts_fail(cast, upload_doc, make_user, browser):
    geetha_doc, _ = upload_doc(cast["g"], name="Geetha_Private.pdf")
    meena = make_user("owner", "meena")
    m = browser(meena)
    for payload in ["' OR '1'='1", "x' OR 1=1 --", "'; DROP TABLE documents; --", "%' OR '%'='"]:
        r = m.get("/owner", query_string={"q": payload, "owner": payload, "category": payload})
        assert r.status_code == 200 and b"Geetha_Private.pdf" not in r.data
        assert browser().login(payload, payload).status_code == 401
    assert database.fetch_one("SELECT 1 AS x FROM documents WHERE id = %s", (geetha_doc,))


# ----------------------------------------------------------------- file validation
def test_bad_uploads_are_rejected_and_logged(cast, events):
    before = database.fetch_one("SELECT count(*) AS n FROM documents WHERE owner_id = %s",
                                (cast["geetha"]["id"],))["n"]
    for name, data in [("virus.exe", b"MZ\x90\x00"), ("shell.php", b"<?php ?>"),
                       ("fake.pdf", b"MZ not a pdf"), ("huge.pdf", b"%PDF-" + b"x" * (11 * 1024 * 1024)),
                       ("empty.pdf", b"")]:
        r = cast["g"].post("/documents/upload", {"file": (io.BytesIO(data), name)},
                           content_type="multipart/form-data")
        assert r.status_code in (302, 413), name
    after = database.fetch_one("SELECT count(*) AS n FROM documents WHERE owner_id = %s",
                               (cast["geetha"]["id"],))["n"]
    assert after == before
    rows = events(username=cast["geetha"]["username"], action="FILE_VALIDATION")
    assert len(rows) >= 4 and all(e["result"] == "FAILURE" for e in rows)


def test_uploaded_filename_never_becomes_the_path(cast, upload_doc, app):
    doc_id, _ = upload_doc(cast["g"], name="../../etc/passwd.pdf")
    row = database.fetch_one("SELECT original_name, stored_name FROM documents WHERE id = %s", (doc_id,))
    assert "/" not in row["original_name"] and ".." not in row["original_name"]
    assert len(row["stored_name"]) == 32 and row["stored_name"].isalnum()
    assert os.path.dirname(os.path.join(app.config["UPLOAD_DIR"], row["stored_name"])) == app.config["UPLOAD_DIR"]


def test_hsts_is_sent_when_running_securely(app, browser):
    app.config["SESSION_COOKIE_SECURE"] = True
    try:
        assert "max-age=" in browser().get("/login").headers["Strict-Transport-Security"]
    finally:
        app.config["SESSION_COOKIE_SECURE"] = False
    assert "Strict-Transport-Security" not in browser().get("/login").headers
