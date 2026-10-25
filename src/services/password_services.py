from pwdlib import PasswordHash

_password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Hash a plain-text password before storing it."""
    return _password_hash.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Check a password against its stored hash."""
    return _password_hash.verify(password, password_hash)
