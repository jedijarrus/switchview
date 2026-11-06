"""Verschluesselung der Zugangsdaten (Fernet, Schluessel aus SECRET_KEY)."""
import base64
import hashlib
import hmac

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


def keyed_digest(purpose: str, text: str) -> str:
    """The HMAC-SHA256 (hex) of text under a key derived from SECRET_KEY and purpose: a mark that tells two texts apart without being
    an oracle for them. A plain hash next to a masked text would let anyone holding a copy of the database test guesses of what the
    mask hides; this one needs SECRET_KEY. Another purpose gives another key, so a mark never stands in for one of another use.
    Never raises, not even on a lone surrogate in text."""
    key = hashlib.sha256(b"switchview:" + purpose.encode() + b":" + settings.secret_key.encode()).digest()
    return hmac.new(key, text.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()
