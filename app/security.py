import hashlib

import bcrypt


def md5_hash(password: str) -> str:
    """Returns the MD5 hex digest of the password. Used for GameSpy challenge-response auth."""
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain-text password against a hashed one."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def hash_password(password: str) -> str:
    """Hashes a plain-text password."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")
