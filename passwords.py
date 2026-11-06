"""Password strength rules (NIST-style: length + block common/guessable passwords)."""
import re

MIN_LENGTH = 10
MAX_LENGTH = 128

# Small built-in blocklist of the most common passwords and root words.
COMMON = {
    "password", "passw0rd", "p@ssword", "p@ssw0rd", "qwerty", "qwertyuiop", "qwerty123",
    "letmein", "welcome", "admin", "administrator", "iloveyou", "monkey", "dragon",
    "football", "baseball", "basketball", "abc123", "trustno1", "sunshine", "princess",
    "master", "login", "changeme", "trustvault", "secret", "shadow", "superman",
    "batman", "michael", "jennifer", "jordan", "hunter", "freedom", "whatever",
    "starwars", "cheese", "computer", "internet", "service", "access", "flower",
    "hello", "hello123", "charlie", "donald", "mustang", "ashley", "bailey",
    "passw0rd1", "password1", "password123", "pass1234", "test1234", "guest",
    "root", "toor", "user", "demo", "welcome1", "welcome123", "summer", "winter",
    "spring", "autumn", "india", "krishna", "ganesh", "sairam", "geetha", "ravi", "sita",
    "123456", "12345678", "123456789", "1234567890", "0987654321", "111111",
    "000000", "abcdefg", "abcd1234", "1q2w3e4r", "1qaz2wsx", "zaq12wsx",
}

_LEET = str.maketrans({"@": "a", "0": "o", "$": "s", "3": "e", "4": "a", "1": "i", "!": "i"})


def _is_common(password):
    low = password.lower()
    if low in COMMON:
        return True
    # "Password123!" -> strip trailing digits/symbols -> "password"
    stripped = re.sub(r"[^a-z]+$", "", low)
    if stripped in COMMON:
        return True
    # "P@ssw0rd" style substitutions
    leet = low.translate(_LEET)
    return leet in COMMON or re.sub(r"[^a-z]+$", "", leet) in COMMON


def validate_password(password, username=""):
    """Return an error message, or None if the password is acceptable."""
    if len(password) < MIN_LENGTH:
        return f"Password must be at least {MIN_LENGTH} characters."
    if len(password) > MAX_LENGTH:
        return f"Password must be at most {MAX_LENGTH} characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain at least one letter and one number."
    if len(set(password)) < 5:
        return "Password uses too few different characters."
    username = (username or "").strip().lower()
    if len(username) >= 3 and username in password.lower():
        return "Password must not contain your username."
    if _is_common(password):
        return "That password is too common. Choose something less guessable."
    return None
