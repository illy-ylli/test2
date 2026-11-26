from collections.abc import Mapping
from hashlib import pbkdf2_hmac
from hmac import compare_digest
from secrets import token_bytes


def _hash_password(password: str, salt: bytes) -> bytes:
    return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)


def create_password_record(password: str) -> tuple[bytes, bytes]:
    """Return the salt and password hash to store for a user."""
    salt = token_bytes(16)
    return salt, _hash_password(password, salt)


def login(
    username: str,
    password: str,
    users: Mapping[str, tuple[bytes, bytes]],
) -> bool:
    """Return True if the password matches the user's stored password hash."""
    record = users.get(username)
    salt, expected_hash = record if record is not None else (bytes(16), bytes(32))
    matches = compare_digest(_hash_password(password, salt), expected_hash)
    return matches and record is not None
