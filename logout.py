from collections.abc import Mapping, MutableMapping
from secrets import token_urlsafe

from login import login


def start_session(
    username: str,
    password: str,
    users: Mapping[str, tuple[bytes, bytes]],
    sessions: MutableMapping[str, str],
) -> str | None:
    """Issue a session token after a successful login."""
    if not login(username, password, users):
        return None
    token = token_urlsafe(32)
    sessions[token] = username
    return token


def logout(token: str, sessions: MutableMapping[str, str]) -> bool:
    """Revoke one session and report whether it was active."""
    return sessions.pop(token, None) is not None
