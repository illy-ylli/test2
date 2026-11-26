from collections.abc import MutableMapping

from login import create_password_record


def register(
    username: str,
    password: str,
    users: MutableMapping[str, tuple[bytes, bytes]],
) -> bool:
    """Create a user, returning False for empty credentials or an existing name."""
    if not username.strip() or not password or username in users:
        return False
    record = create_password_record(password)
    return users.setdefault(username, record) is record
