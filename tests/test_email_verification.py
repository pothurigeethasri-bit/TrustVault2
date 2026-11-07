"""E-mail verification: nobody gets an account (or a username) without proving the address.

Real app, real PostgreSQL (see conftest.py). Mail is captured by the `mailbox` fixture.
"""
import hashlib
import threading
import time

import pytest

import database
import mailer
import verification
from conftest import PASSWORD

pytestmark = pytest.mark.db


def unique(prefix="p"):
    import uuid
    return f"{prefix}{uuid.uuid4().hex[:8]}"


def user_row(**where):
    key, value = next(iter(where.items()))
    return database.fetch_one(f"SELECT * FROM users WHERE {key} = %s", (value,))


def request_link(browser, mailbox, email=None):
    email = email or f"{unique()}@example.com"
    b = browser()
    assert b.post("/register", {"email": email}).status_code == 200
    return b, email, mailbox.token_for(email)


def finish(b, token, username=None, password=PASSWORD, **extra):
    return b.post("/register/complete", {"token": token, "username": username or unique("u"),
                                         "password": password, "confirm": password, **extra})


def age_tokens(email, seconds=3600):
    database.execute("UPDATE email_tokens SET created_at = created_at - make_interval(secs => %s) "
                     "WHERE email = %s", (float(seconds), email))


# ---------------------------------------------------------------- the main promise
def test_no_account_and_no_username_exist_before_the_link_is_used(browser, mailbox):
    b, email, token = request_link(browser, mailbox)
    assert token and len(mailbox.to(email)) == 1
    assert user_row(email=email) is None                       # nothing created yet
    # The register page asks for the email only: no username/password fields to fill in.
    page = b.get("/register").data
    assert b'name="email"' in page and b'name="username"' not in page and b'name="password"' not in page
    # A username cannot be claimed without a valid link.
    assert finish(b, "", "sneaky").status_code == 400
    assert finish(b, "x" * 43, "sneaky").status_code == 400
    assert user_row(username="sneaky") is None


def test_full_flow_creates_a_verified_viewer_who_can_sign_in_with_the_email(browser, mailbox):
    b, email, token = request_link(browser, mailbox)
    page = b.get(f"/register/complete?token={token}")
    assert page.status_code == 200 and email.encode() in page.data
    assert page.headers["Cache-Control"] == "no-store"
    name = unique("u")
    r = finish(b, token, name, role="admin", is_admin="1")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")
    row = user_row(username=name)
    assert row["email"] == email and row["role"] == "viewer" and row["email_verified_at"] is not None
    assert browser().post("/login", {"email": email, "password": PASSWORD}).status_code == 302


def test_the_mail_contains_a_working_link_and_explains_itself(browser, mailbox):
    _, email, token = request_link(browser, mailbox)
    msg = mailbox.to(email)[0]
    assert "/register/complete?token=" + token in msg["text"]
    assert str(verification.TOKEN_MINUTES) in msg["text"] and msg["html"]
    assert token in msg["html"]


def test_links_are_built_from_app_base_url_not_the_host_header(browser, mailbox, monkeypatch):
    monkeypatch.setenv("APP_BASE_URL", "https://vault.example")
    email = f"{unique()}@example.com"
    b = browser()
    # The CSRF session cookie is host-bound, so set it up and post under the forged host itself;
    # otherwise the request is rejected by the CSRF check and no mail is ever sent.
    with b.c.session_transaction(base_url="http://evil.example") as s:
        s["_csrf"] = "test-csrf-token"
    r = b.c.post("/register", data={"email": email, "csrf_token": "test-csrf-token"},
                 base_url="http://evil.example")
    assert r.status_code == 200
    assert "https://vault.example/register/complete?token=" in mailbox.to(email)[0]["text"]
    assert "evil.example" not in mailbox.to(email)[0]["text"]


# --------------------------------------------------------------- token properties
def test_the_link_works_once(browser, mailbox):
    b, email, token = request_link(browser, mailbox)
    assert finish(b, token).status_code == 302
    assert finish(b, token, unique("u")).status_code == 400
    assert browser().get(f"/register/complete?token={token}").status_code == 400


def test_opening_the_link_does_not_use_it_up(browser, mailbox):
    b, email, token = request_link(browser, mailbox)
    for _ in range(3):                                         # e.g. a mail scanner pre-fetching it
        assert browser().get(f"/register/complete?token={token}").status_code == 200
    assert finish(b, token).status_code == 302


def test_expired_links_are_refused(browser, mailbox):
    b, email, token = request_link(browser, mailbox)
    database.execute("UPDATE email_tokens SET expires_at = now() - interval '1 second' "
                     "WHERE email = %s", (email,))
    assert b.get(f"/register/complete?token={token}").status_code == 400
    name = unique("u")
    assert finish(b, token, name).status_code == 400
    assert user_row(username=name) is None


def test_only_a_hash_of_the_token_is_stored(browser, mailbox):
    _, email, token = request_link(browser, mailbox)
    stored = database.fetch_one("SELECT token_hash FROM email_tokens WHERE email = %s", (email,))
    assert stored["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in stored["token_hash"]


@pytest.mark.parametrize("bad", ["", "abc", "A" * 43, "../../etc/passwd", "x" * 5000, "%00"])
def test_garbage_tokens_are_refused(browser, bad):
    b = browser()
    assert b.get("/register/complete", query_string={"token": bad}).status_code == 400
    assert finish(b, bad).status_code == 400


def test_a_new_link_cancels_the_older_one(browser, mailbox):
    b, email, first = request_link(browser, mailbox)
    age_tokens(email)                                           # get past the resend cooldown
    assert b.post("/register", {"email": email}).status_code == 200
    second = mailbox.token_for(email)
    assert second != first
    assert b.get(f"/register/complete?token={first}").status_code == 400
    assert finish(b, second).status_code == 302


def test_a_link_for_one_address_cannot_make_an_account_for_another(browser, mailbox):
    b, email, token = request_link(browser, mailbox)
    name = unique("u")
    finish(b, token, name, email="someone-else@example.com")    # extra field is ignored
    assert user_row(username=name)["email"] == email


def test_two_people_racing_for_one_link_get_one_account(browser, mailbox):
    b, email, token = request_link(browser, mailbox)
    results = []

    def go(name):
        results.append(verification.complete_registration(token, name, PASSWORD)[0])

    threads = [threading.Thread(target=go, args=(unique("u"),)) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(results).count(verification.OK) == 1
    assert database.fetch_one("SELECT count(*) AS n FROM users WHERE email = %s", (email,))["n"] == 1


# ---------------------------------------------- mistakes in step 2 do not burn the link
def test_a_taken_username_or_weak_password_keeps_the_link_alive(browser, mailbox, make_user):
    taken = make_user("viewer")
    b, email, token = request_link(browser, mailbox)
    r = finish(b, token, taken["username"])
    assert r.status_code == 400 and b"already taken" in r.data
    assert finish(b, token, unique("u"), password="short1").status_code == 400
    assert finish(b, token, "bad name!").status_code == 400
    assert user_row(email=email) is None
    assert finish(b, token, unique("u")).status_code == 302     # same link still works


# ------------------------------------------------------- existing / invalid addresses
def test_registering_an_existing_email_looks_the_same_and_creates_no_link(browser, mailbox, make_user):
    existing = make_user("viewer")
    new_email = f"{unique()}@example.com"
    br = browser()                                  # same browser: the CSRF token is part of the page
    a = br.post("/register", {"email": new_email})
    b = br.post("/register", {"email": existing["email"].upper()})
    assert a.status_code == b.status_code == 200
    assert a.data.replace(new_email.encode(), b"X") == b.data.replace(existing["email"].encode(), b"X")
    assert mailbox.token_for(existing["email"]) is None         # no link for a taken address
    notice = mailbox.to(existing["email"])
    assert len(notice) == 1 and "already" in notice[0]["subject"].lower()
    assert database.fetch_one("SELECT count(*) AS n FROM email_tokens WHERE email = %s",
                              (existing["email"],))["n"] == 0


@pytest.mark.parametrize("bad", ["not-an-email", "", "a@b", "a b@example.com", "x@example.com\nBcc: y@example.com"])
def test_invalid_addresses_send_nothing(browser, mailbox, bad):
    assert browser().post("/register", {"email": bad}).status_code == 400
    assert not mailbox.sent


def test_an_address_registered_while_the_link_was_waiting_cannot_be_reused(browser, mailbox):
    import auth
    b, email, token = request_link(browser, mailbox)
    assert auth.create_user(unique("u"), PASSWORD, "viewer", email)   # someone else got there first
    r = finish(b, token, unique("u"))
    assert r.status_code == 400 and b"already exists" in r.data


# --------------------------------------------------------------- abuse / delivery
def test_resending_is_limited_per_address(browser, mailbox):
    b, email, _ = request_link(browser, mailbox)
    assert b.post("/register", {"email": email}).status_code == 200      # inside the cooldown
    assert len(mailbox.to(email)) == 1                                   # ...so no second mail


def test_hourly_cap_per_address(browser, mailbox, monkeypatch):
    monkeypatch.setattr(verification, "RESEND_COOLDOWN_SECONDS", 0)
    monkeypatch.setattr(verification, "MAX_LINKS_PER_EMAIL_HOUR", 2)
    email = f"{unique()}@example.com"
    for _ in range(4):
        assert browser().post("/register", {"email": email}).status_code == 200
    assert len(mailbox.to(email)) == 2


def test_a_failed_send_leaves_no_token_and_allows_an_immediate_retry(browser, mailbox):
    email = f"{unique()}@example.com"
    mailbox.fail = mailer.MailError("down")
    b = browser()
    r = b.post("/register", {"email": email})
    assert r.status_code == 503 and b"could not send" in r.data
    assert database.fetch_one("SELECT count(*) AS n FROM email_tokens WHERE email = %s",
                              (email,))["n"] == 0
    mailbox.fail = None
    assert b.post("/register", {"email": email}).status_code == 200
    assert mailbox.token_for(email)


def test_an_address_the_mail_server_rejects_is_reported(browser, mailbox):
    mailbox.fail = mailer.MailError("no such user", rejected=True)
    r = browser().post("/register", {"email": f"{unique()}@example.com"})
    assert r.status_code == 400 and b"rejected by the mail server" in r.data


def test_the_verification_steps_are_audited(browser, mailbox, events):
    b, email, token = request_link(browser, mailbox)
    name = unique("u")
    finish(b, token, name)
    requested = events(username=email, action="EMAIL_VERIFY_REQUEST")
    assert requested and requested[0]["result"] == "SUCCESS" and requested[0]["ip_address"] == b.ip
    assert events(username=name, action="EMAIL_VERIFIED")[0]["result"] == "SUCCESS"
    assert events(username=name, action="REGISTER_USER")[0]["result"] == "SUCCESS"


def test_seeded_and_directly_created_accounts_count_as_verified(make_user):
    assert user_row(username=make_user("viewer")["username"])["email_verified_at"] is not None


def test_the_sign_up_pages_are_hidden_behind_the_pin_but_the_link_survives_it(browser, mailbox, monkeypatch):
    b, email, token = request_link(browser, mailbox)
    monkeypatch.setenv("ACCESS_PIN", "482913")
    fresh = browser()
    r = fresh.get(f"/register/complete?token={token}")
    assert r.status_code == 302 and "/pin?next=/register/complete" in r.headers["Location"]
    assert f"token={token}" in r.headers["Location"].replace("%3D", "=").replace("%3F", "?")


# ------------------------------------------------------------- changing the e-mail
def test_changing_email_needs_the_link_the_right_user_and_works_once(browser, mailbox, make_user):
    me, other = make_user("viewer"), make_user("viewer")
    b, o = browser(me), browser(other)
    new = f"{unique()}@example.com"
    assert b.post("/account/email", {"email": new, "current": PASSWORD}).status_code == 302
    token = mailbox.token_for(new)
    assert user_row(id=me["id"])["email"] == me["email"]                 # unchanged until confirmed
    assert o.get(f"/account/email/confirm?token={token}").status_code == 302   # wrong user: refused
    assert o.post("/account/email/confirm", {"token": token}).status_code == 302
    assert user_row(id=me["id"])["email"] == me["email"]
    assert browser().get(f"/account/email/confirm?token={token}").status_code == 302  # anonymous
    assert b.get(f"/account/email/confirm?token={token}").status_code == 200
    assert b.post("/account/email/confirm", {"token": token}).status_code == 302
    row = user_row(id=me["id"])
    assert row["email"] == new and row["email_verified_at"] is not None
    assert b.post("/account/email/confirm", {"token": token}).status_code == 302        # reuse: refused
    assert browser().post("/login", {"email": new, "password": PASSWORD}).status_code == 302
    assert browser().post("/login", {"email": me["email"], "password": PASSWORD}).status_code == 401


def test_change_email_link_expires_and_cannot_steal_a_newly_taken_address(browser, mailbox, make_user):
    import auth
    me = make_user("viewer")
    b = browser(me)
    new = f"{unique()}@example.com"
    b.post("/account/email", {"email": new, "current": PASSWORD})
    token = mailbox.token_for(new)
    auth.create_user(unique("u"), PASSWORD, "viewer", new)               # someone registers it first
    b.post("/account/email/confirm", {"token": token})
    assert user_row(id=me["id"])["email"] == me["email"]

    new2 = f"{unique()}@example.com"
    b.post("/account/email", {"email": new2, "current": PASSWORD})
    token2 = mailbox.token_for(new2)
    database.execute("UPDATE email_tokens SET expires_at = now() - interval '1 second' "
                     "WHERE email = %s", (new2,))
    b.post("/account/email/confirm", {"token": token2})
    assert user_row(id=me["id"])["email"] == me["email"]


def test_change_email_still_needs_the_current_password(browser, mailbox, make_user):
    me = make_user("viewer")
    r = browser(me).post("/account/email", {"email": f"{unique()}@example.com", "current": "wrong"})
    assert r.status_code == 401 and not mailbox.sent
