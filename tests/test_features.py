"""Email login, separate view/download/edit permissions, re-categorising, failed-login alerts.

Runs against a real PostgreSQL test database like the other tests (see conftest.py).
"""
import io

import pytest

import auth
import database
from conftest import PASSWORD, make_pdf

pytestmark = pytest.mark.db


def make_docx():
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", "<x/>")
    return buf.getvalue()


def grant(owner_b, doc_id, user, level):
    return owner_b.post(f"/documents/{doc_id}/grant", {"user_id": user["id"], "access_level": level})


@pytest.fixture()
def cast(make_user, browser):
    geetha, ravi = make_user("owner", "geetha"), make_user("viewer", "ravi")
    return {"geetha": geetha, "ravi": ravi, "g": browser(geetha), "r": browser(ravi)}


# ------------------------------------------------------------------ email login
def test_sign_in_with_email(make_user, browser):
    user = make_user("viewer")
    assert browser().post("/login", {"email": user["email"], "password": PASSWORD}).status_code == 302
    assert browser().post("/login", {"email": user["email"].upper(), "password": PASSWORD}).status_code == 302


def test_wrong_password_with_email_is_refused_and_logged(make_user, browser, events):
    user = make_user("viewer")
    r = browser().post("/login", {"email": user["email"], "password": "wrong-password-1"})
    assert r.status_code == 401 and b"Invalid email or password" in r.data
    assert events(username=user["username"], action="LOGIN")[0]["result"] == "FAILURE"


def test_lockout_is_shared_between_email_and_username(make_user, browser):
    user = make_user("viewer")
    for i in range(auth.MAX_FAILED_LOGINS):
        b = browser()
        b.post("/login", {"email": user["email"] if i % 2 else user["username"],
                          "password": "wrong-password-1"})
    assert browser().post("/login", {"email": user["email"], "password": PASSWORD}).status_code == 429


def test_register_requires_a_valid_email(browser, mailbox):
    b = browser()
    assert b.post("/register", {"email": "not-an-email"}).status_code == 400
    assert b.post("/register", {"email": ""}).status_code == 400
    assert not mailbox.sent                                   # nothing is mailed for bad input
    ok = b.post("/register", {"email": "New.Person@Example.com"})
    assert ok.status_code == 200
    assert mailbox.to("new.person@example.com")               # normalised to lower-case


def test_existing_user_can_add_an_email_after_confirming_it(browser, mailbox):
    name = "legacy" + __import__("os").urandom(3).hex()
    uid = auth.create_user(name, PASSWORD, "viewer")          # old account: no email
    b = browser({"id": uid, "username": name, "role": "viewer"})
    new = f"{name}@example.com"
    assert b.post("/account/email", {"email": new, "current": "wrong"}).status_code == 401
    assert not mailbox.sent
    assert b.post("/account/email", {"email": new, "current": PASSWORD}).status_code == 302
    token = mailbox.token_for(new)
    assert token
    # Not usable until the link is opened and confirmed.
    assert database.fetch_one("SELECT email FROM users WHERE id = %s", (uid,))["email"] is None
    assert browser().post("/login", {"email": new, "password": PASSWORD}).status_code == 401
    assert b.get(f"/account/email/confirm?token={token}").status_code == 200
    assert b.post("/account/email/confirm", {"token": token}).status_code == 302
    assert browser().post("/login", {"email": new, "password": PASSWORD}).status_code == 302


def test_email_cannot_be_taken_from_someone_else(make_user, browser, mailbox):
    a, other = make_user("viewer"), make_user("viewer")
    r = browser(a).post("/account/email", {"email": other["email"], "current": PASSWORD})
    assert r.status_code == 400 and b"already registered" in r.data
    assert not mailbox.sent


# -------------------------------------------- view / download / edit are separate
def test_view_only_can_view_but_not_download(cast, upload_doc):
    doc_id, content = upload_doc(cast["g"])
    assert grant(cast["g"], doc_id, cast["ravi"], "view").status_code == 302
    view = cast["r"].get(f"/documents/{doc_id}/view")
    assert view.status_code == 200 and view.data == content
    assert "attachment" not in view.headers.get("Content-Disposition", "")
    dl = cast["r"].get(f"/documents/{doc_id}/download")
    assert dl.status_code == 403 and content not in dl.data
    page = cast["r"].get("/viewer").get_data(as_text=True)
    assert "View only" in page and f"/documents/{doc_id}/download" not in page


def test_download_level_can_view_and_download(cast, upload_doc):
    doc_id, content = upload_doc(cast["g"])
    grant(cast["g"], doc_id, cast["ravi"], "download")
    assert cast["r"].get(f"/documents/{doc_id}/view").status_code == 200
    assert cast["r"].get(f"/documents/{doc_id}/download").data == content


def test_edit_level_needs_owner_role_and_includes_download(cast, make_user, browser, upload_doc):
    doc_id, content = upload_doc(cast["g"])
    meena = make_user("owner", "meena")
    m = browser(meena)
    assert grant(cast["g"], doc_id, meena, "edit").status_code == 302
    assert m.get(f"/documents/{doc_id}/view").status_code == 200
    assert m.get(f"/documents/{doc_id}/download").data == content
    assert m.post(f"/documents/{doc_id}/edit", {"name": "Renamed.pdf"}).status_code == 302
    # a viewer-role user is refused edit access and a forced row is capped at download
    grant(cast["g"], doc_id, cast["ravi"], "edit")
    assert database.fetch_one("SELECT 1 FROM permissions WHERE user_id = %s", (cast["ravi"]["id"],)) is None
    database.execute("INSERT INTO permissions (document_id,user_id,access_level,granted_by) "
                     "VALUES (%s,%s,'edit',%s)", (doc_id, cast["ravi"]["id"], cast["geetha"]["id"]))
    assert cast["r"].post(f"/documents/{doc_id}/edit", {"name": "X.pdf"}).status_code == 403
    assert cast["r"].get(f"/documents/{doc_id}/download").status_code == 200


def test_view_only_is_refused_for_files_a_browser_cannot_preview(cast, upload_doc):
    doc_id, _ = upload_doc(cast["g"], name="Plan.docx", content=make_docx())
    r = grant(cast["g"], doc_id, cast["ravi"], "view")
    assert r.status_code == 302
    assert database.fetch_one("SELECT 1 FROM permissions WHERE document_id = %s", (doc_id,)) is None
    # even a forced view-only row cannot be used to pull the file through /view
    database.execute("INSERT INTO permissions (document_id,user_id,access_level,granted_by) "
                     "VALUES (%s,%s,'view',%s)", (doc_id, cast["ravi"]["id"], cast["geetha"]["id"]))
    assert cast["r"].get(f"/documents/{doc_id}/view").status_code == 403
    assert cast["r"].get(f"/documents/{doc_id}/download").status_code == 403


def test_upgrading_and_downgrading_applies_on_the_next_request(cast, upload_doc):
    doc_id, _ = upload_doc(cast["g"])
    grant(cast["g"], doc_id, cast["ravi"], "download")
    assert cast["r"].get(f"/documents/{doc_id}/download").status_code == 200
    grant(cast["g"], doc_id, cast["ravi"], "view")
    assert cast["r"].get(f"/documents/{doc_id}/download").status_code == 403
    assert cast["r"].get(f"/documents/{doc_id}/view").status_code == 200


def test_invalid_access_level_is_rejected(cast, upload_doc):
    doc_id, _ = upload_doc(cast["g"])
    for bad in ("read", "owner", "", "admin"):
        assert grant(cast["g"], doc_id, cast["ravi"], bad).status_code == 302
    assert database.fetch_one("SELECT 1 FROM permissions WHERE document_id = %s", (doc_id,)) is None


# ------------------------------------------------------------ organise documents
def test_owner_can_move_a_document_between_categories(cast, upload_doc, events):
    doc_id, _ = upload_doc(cast["g"])
    cast["g"].post("/categories", {"name": "HR"})
    cat = database.fetch_one("SELECT id FROM categories WHERE owner_id = %s AND name = 'HR'",
                             (cast["geetha"]["id"],))
    assert cast["g"].post(f"/documents/{doc_id}/category", {"category_id": str(cat["id"])}).status_code == 302
    assert database.fetch_one("SELECT category_id FROM documents WHERE id = %s", (doc_id,))["category_id"] == cat["id"]
    cast["g"].post(f"/documents/{doc_id}/category", {"category_id": ""})
    assert database.fetch_one("SELECT category_id FROM documents WHERE id = %s", (doc_id,))["category_id"] is None
    assert events(document_id=doc_id, action="CHANGE_CATEGORY")


def test_only_the_owner_can_recategorise_and_only_into_their_own_categories(cast, make_user, browser, upload_doc):
    doc_id, _ = upload_doc(cast["g"])
    grant(cast["g"], doc_id, cast["ravi"], "download")
    assert cast["r"].post(f"/documents/{doc_id}/category", {"category_id": ""}).status_code == 403
    meena = make_user("owner", "meena")
    m = browser(meena)
    m.post("/categories", {"name": "Private"})
    foreign = database.fetch_one("SELECT id FROM categories WHERE owner_id = %s", (meena["id"],))
    cast["g"].post(f"/documents/{doc_id}/category", {"category_id": str(foreign["id"])})
    assert database.fetch_one("SELECT category_id FROM documents WHERE id = %s", (doc_id,))["category_id"] is None
    assert m.post(f"/documents/{doc_id}/category", {"category_id": ""}).status_code == 403


# ------------------------------------------------------------------ admin alerts
def _admin(make_user, browser):
    return browser(make_user("admin"))


def test_admin_alert_for_locked_account_and_failed_logins(make_user, browser):
    admin = _admin(make_user, browser)
    victim = make_user("viewer")
    for _ in range(auth.MAX_FAILED_LOGINS):
        browser().post("/login", {"email": victim["email"], "password": "wrong-password-1"})
    page = admin.get("/admin/alerts").get_data(as_text=True)
    assert "locked out" in page and victim["username"] in page
    assert "Latest failed sign-ins" in page
    overview = admin.get("/admin").get_data(as_text=True)
    assert "locked out" in overview


def test_alerts_page_is_admin_only(cast, browser):
    for b in (cast["g"], cast["r"], browser()):
        assert b.get("/admin/alerts").status_code in (302, 403)
