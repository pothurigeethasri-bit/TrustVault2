import pytest

from passwords import validate_password


@pytest.mark.parametrize("pw", [
    "short1",              # too short
    "abcdefghijkl",        # no number
    "1234567890123",       # no letter
    "password123",         # common
    "Password123!",        # common word + decoration
    "P@ssw0rd2026",        # leetspeak common word
    "Qwerty123",           # common (and short)
    "aaaaaaaaaa1",         # too few distinct characters
    "x" * 129 + "1",       # too long
])
def test_weak_passwords_rejected(pw):
    assert validate_password(pw, "someone") is not None


def test_password_containing_username_rejected():
    assert validate_password("geethaLovesCats99", "geetha") is not None


@pytest.mark.parametrize("pw", [
    "blue-Horse-battery-42",
    "Tr1ckyLongPassphrase",
    "9fK2mPq7vL4n",
])
def test_strong_passwords_accepted(pw):
    assert validate_password(pw, "someone") is None
