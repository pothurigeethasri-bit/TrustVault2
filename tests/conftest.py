"""Test fixtures. These tests run against a REAL PostgreSQL database.

Set TEST_DATABASE_URL to a database whose name contains "test", e.g.
    postgresql://postgres:pw@localhost:5432/trustvault_test
The whole schema is DROPPED and recreated at the start of the run, so never point
this at your real data (the name check below refuses anything not containing "test").
Without TEST_DATABASE_URL the database tests are skipped; the pure unit tests still run.
"""
import io
import os
import re
import shutil
import sys
import tempfile
import random
import uuid
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEST_URL = os.environ.get("TEST_DATABASE_URL", "")
if TEST_URL:
    dbname = TEST_URL.rsplit("/", 1)[-1].split("?")[0]
    if "test" not in dbname.lower():
        raise RuntimeError(f"Refusing to run: database '{dbname}' does not look like a test database.")
    # Must be set BEFORE app/database are imported; load_dotenv() never overrides these.
    os.environ["DATABASE_URL"] = TEST_URL
    os.environ["SECRET_KEY"] = "test-secret-key-for-pytest-only-0123456789"
    os.environ["COOKIE_SECURE"] = "0"
    os.environ["TRUST_PROXY"] = "0"
    os.environ["ACCESS_PIN"] = ""        # gate is OFF by default; test_pin_gate.py switches it on
    os.environ.setdefault("STORAGE_BACKEND", "disk")
    _upload_dir = tempfile.mkdtemp(prefix="tv-test-uploads-")
    os.environ["UPLOAD_DIR"] = _upload_dir

PASSWORD = "Zq7-test-passphrase-91"


class Mailbox:
    """Stands in for SMTP in database tests: nothing is ever sent, every message is kept."""

    def __init__(self):
        self.sent = []
        self.fail = None            # set to a mailer.MailError to simulate a delivery failure

    def __call__(self, to, subject, text, html=None):
        if self.fail:
            raise self.fail
        self.sent.append({"to": to, "subject": subject, "text": text, "html": html})

    def to(self, address):
        return [m for m in self.sent if m["to"] == address]

    def token_for(self, address):
        """The token in the newest link e-mailed to `address` (None if there is none)."""
        for m in reversed(self.sent):
            if m["to"] == address:
                found = re.search(r"token=([A-Za-z0-9_\-]+)", m["text"])
                if found:
                    return found.group(1)
        return None


@pytest.fixture(autouse=True)
def mailbox(request, monkeypatch):
    box = Mailbox()
    if request.node.get_closest_marker("db"):
        import mailer
        monkeypatch.setattr(mailer, "send_mail", box)
    return box


def pytest_collection_modifyitems(config, items):
    if TEST_URL:
        return
    skip = pytest.mark.skip(reason="set TEST_DATABASE_URL to run database tests")
    for item in items:
        if "db" in item.keywords:
            item.add_marker(skip)


def pytest_configure(config):
    config.addinivalue_line("markers", "db: needs a real PostgreSQL test database")


@pytest.fixture(scope="session")
def app():
    if not TEST_URL:
        pytest.skip("set TEST_DATABASE_URL to run database tests")
    import database
    conn = database.get_connection()
    try:
        with conn, conn.cursor() as cur:       # fresh start; DROP is allowed, row deletes are not
            cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    finally:
        conn.close()
    database.init_db()
    import app as app_module
    app_module.app.config.update(TESTING=True)
    yield app_module.app
    shutil.rmtree(os.environ["UPLOAD_DIR"], ignore_errors=True)


@pytest.fixture()
def client(app):
    c = app.test_client()
    c.environ_base["REMOTE_ADDR"] = "10.{}.{}.{}".format(*(random.randint(1, 254) for _ in range(3)))
    return c


def _unique(prefix):
    return f"{prefix}{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def make_user(app):
    import auth

    def make(role="viewer", prefix=None):
        name = _unique(prefix or role[:3])
        email = f"{name}@example.com"
        uid = auth.create_user(name, PASSWORD, role, email)
        assert uid
        return {"id": uid, "username": name, "role": role, "email": email}
    return make


@pytest.fixture()
def sign_up(app, mailbox, browser):
    """Do the whole verified sign-up through the real routes; returns the new account."""
    import database

    def go(email=None, username=None, password=PASSWORD):
        email = email or f"{_unique('new')}@example.com"
        username = username or _unique("usr")
        b = browser()
        assert b.post("/register", {"email": email}).status_code == 200
        token = mailbox.token_for(email)
        r = b.post("/register/complete", {"token": token, "username": username,
                                          "password": password, "confirm": password})
        assert r.status_code == 302, r.data
        row = database.fetch_one("SELECT id FROM users WHERE username = %s", (username,))
        return {"id": row["id"], "username": username, "email": email, "password": password}
    return go


class Browser:
    """A logged-in (or anonymous) test client that handles CSRF tokens for us."""

    def __init__(self, app, user=None, ip=None):
        self.c = app.test_client()
        # Every browser gets its own client IP, otherwise the per-IP throttles would make
        # unrelated tests interfere with each other (they all come from 127.0.0.1).
        self.ip = ip or "10.{}.{}.{}".format(*(random.randint(1, 254) for _ in range(3)))
        self.c.environ_base["REMOTE_ADDR"] = self.ip
        self.user = user
        if user:
            r = self.login(user["username"], PASSWORD)
            assert r.status_code == 302, "test login failed"

    def token(self):
        with self.c.session_transaction() as s:
            s.setdefault("_csrf", "test-csrf-token")
            return s["_csrf"]

    def login(self, username, password):
        return self.post("/login", {"username": username, "password": password})

    def get(self, url, **kw):
        return self.c.get(url, **kw)

    def post(self, url, data=None, csrf=True, **kw):
        data = dict(data or {})
        if csrf:
            data["csrf_token"] = self.token()
        return self.c.post(url, data=data, **kw)


@pytest.fixture()
def browser(app):
    def make(user=None, ip=None):
        return Browser(app, user, ip)
    return make


def make_pdf(text=b"secret salary letter"):
    return b"%PDF-1.7\n" + text + b"\n%%EOF"


@pytest.fixture()
def upload_doc(app):
    """Owner uploads a PDF through the real route; returns (doc_id, bytes)."""
    import database

    def up(owner_browser, name="Salary_Letter.pdf", content=None):
        content = content or make_pdf(uuid.uuid4().hex.encode())
        r = owner_browser.post("/documents/upload", {
            "file": (io.BytesIO(content), name)}, content_type="multipart/form-data")
        assert r.status_code == 302
        row = database.fetch_one(
            "SELECT id FROM documents WHERE owner_id = %s ORDER BY id DESC LIMIT 1",
            (owner_browser.user["id"],))
        return row["id"], content
    return up


@pytest.fixture()
def events(app):
    """Fetch audit rows for a user / document, newest first."""
    import database

    def fetch(username=None, document_id=None, action=None):
        sql, params = "SELECT * FROM audit_log WHERE true", []
        if username:
            sql += " AND username = %s"; params.append(username)
        if document_id is not None:
            sql += " AND document_id = %s"; params.append(document_id)
        if action:
            sql += " AND action = %s"; params.append(action)
        return database.fetch_all(sql + " ORDER BY id DESC", params)
    return fetch


def make_zip(member):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(member, "<x/>")
    return buf.getvalue()
