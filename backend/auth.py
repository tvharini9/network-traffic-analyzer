import base64
import hashlib
import hmac
import os
import secrets
import time

from itsdangerous import BadSignature, URLSafeTimedSerializer

SESSION_COOKIE = "nta_session"
SESSION_MAX_AGE = 7 * 24 * 60 * 60
SESSION_SECRET = os.environ.get("SESSION_SECRET", "dev-session-secret-change-me")
_serializer = URLSafeTimedSerializer(SESSION_SECRET)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return f"pbkdf2_sha256$210000${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, rounds, salt_b64, digest_b64 = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def create_session(user_id: int) -> str:
    return _serializer.dumps({"uid": int(user_id), "iat": int(time.time())})


def get_user_id(token: str | None) -> int | None:
    if not token:
        return None
    try:
        data = _serializer.loads(token, max_age=SESSION_MAX_AGE)
        return int(data["uid"])
    except (BadSignature, ValueError, TypeError, KeyError):
        return None
