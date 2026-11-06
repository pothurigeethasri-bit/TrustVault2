"""The database storage backend (used on Render, whose disk is wiped on every deploy)."""
import io
import os

import pytest

import database
from conftest import make_pdf

pytestmark = pytest.mark.db


@pytest.fixture()
def db_storage(app):
    old = app.config["STORAGE_BACKEND"]
    app.config["STORAGE_BACKEND"] = "db"
    yield
    app.config["STORAGE_BACKEND"] = old


def test_full_lifecycle_in_the_database_with_nothing_on_disk(db_storage, app, make_user, browser, upload_doc):
    owner, ravi = make_user("owner"), make_user("viewer")
    o, r = browser(owner), browser(ravi)
    doc_id, content = upload_doc(o)
    stored = database.fetch_one("SELECT stored_name FROM documents WHERE id = %s", (doc_id,))["stored_name"]

    assert not os.path.exists(os.path.join(app.config["UPLOAD_DIR"], stored))
    assert bytes(database.fetch_one("SELECT data FROM file_blobs WHERE stored_name = %s",
                                    (stored,))["data"]) == content

    # Permission checks are identical with this backend.
    assert r.get(f"/documents/{doc_id}/download").status_code == 403
    o.post(f"/documents/{doc_id}/grant", {"user_id": ravi["id"], "access_level": "read"})
    assert r.get(f"/documents/{doc_id}/download").data == content
    o.post(f"/documents/{doc_id}/revoke", {"user_id": ravi["id"]})
    assert r.get(f"/documents/{doc_id}/download").status_code == 403

    # Replacing the file swaps the blob and removes the old one.
    new = make_pdf(b"replacement")
    o.post(f"/documents/{doc_id}/edit", {"file": (io.BytesIO(new), "Salary_Letter.pdf")},
           content_type="multipart/form-data")
    assert o.get(f"/documents/{doc_id}/download").data == new
    assert not database.fetch_one("SELECT 1 AS x FROM file_blobs WHERE stored_name = %s", (stored,))

    # Deleting the document removes the blob.
    new_stored = database.fetch_one("SELECT stored_name FROM documents WHERE id = %s", (doc_id,))["stored_name"]
    o.post(f"/documents/{doc_id}/delete")
    assert not database.fetch_one("SELECT 1 AS x FROM file_blobs WHERE stored_name = %s", (new_stored,))
    assert o.get(f"/documents/{doc_id}/download").status_code == 403


def test_missing_file_is_a_404_and_logged_not_a_crash(app, make_user, browser, upload_doc, events):
    o = browser(make_user("owner"))
    doc_id, _ = upload_doc(o)
    stored = database.fetch_one("SELECT stored_name FROM documents WHERE id = %s", (doc_id,))["stored_name"]
    os.remove(os.path.join(app.config["UPLOAD_DIR"], stored))
    assert o.get(f"/documents/{doc_id}/download").status_code == 404
    assert events(document_id=doc_id, action="DOWNLOAD_DOCUMENT")[0]["result"] == "FAILURE"
