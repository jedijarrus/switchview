"""Verschluesselung der Zugangsdaten (Fernet, Schluessel aus SECRET_KEY)."""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from config import settings

_fernet: Fernet | None = None


def _f() -> Fernet:
    global _fernet
    if _fernet is None:
        if len(settings.secret_key) < 16:
            raise RuntimeError("SECRET_KEY fehlt oder ist zu kurz (mind. 16 Zeichen)")
        key = base64.urlsafe_b64encode(hashlib.sha256(settings.secret_key.encode()).digest())
        _fernet = Fernet(key)
    return _fernet


def encrypt(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    return _f().encrypt(value.encode()).decode()


def decrypt(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return _f().decrypt(value.encode()).decode()
    except InvalidToken:
        return None


def unreadable(value: str | None) -> bool:
    """Whether value is a stored secret (not empty) that decrypt cannot read (None): a token of another SECRET_KEY, or no token at all.
    No secret (None, "") is not unreadable, it is just not set."""
    return bool(value) and decrypt(value) is None
