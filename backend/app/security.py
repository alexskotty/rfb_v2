import os
import time
import hashlib
import hmac
import jwt
from cryptography.fernet import Fernet

def _fernet():
    key = os.getenv("FERNET_KEY")
    if not key:
        raise RuntimeError("FERNET_KEY not set")
    return Fernet(key.encode() if isinstance(key, str) else key)

def encrypt_str(s: str) -> str:
    return _fernet().encrypt(s.encode()).decode()

def decrypt_str(s: str) -> str:
    return _fernet().decrypt(s.encode()).decode()

def hash_token(token: str) -> str:
    # stable hash for storage
    return hashlib.sha256(token.encode()).hexdigest()

def sign_jwt(payload: dict, ttl_seconds: int = 3600) -> str:
    secret = os.getenv("SECRET_KEY")
    if not secret:
        raise RuntimeError("SECRET_KEY not set")
    now = int(time.time())
    to_sign = {
        **payload,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(to_sign, secret, algorithm="HS256")

def verify_jwt(token: str) -> dict:
    secret = os.getenv("SECRET_KEY")
    return jwt.decode(token, secret, algorithms=["HS256"])

def safe_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
