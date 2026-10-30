import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt

from app.config import settings
from app.db import SessionLocal
from app.models.db_models import User, Role
from app.models.schemas import Token


# Precompute once for timing-equalized comparison of dummy vs real hashes.
_DUMMY_HASH = bcrypt.hashpw(b"x", bcrypt.gensalt()).decode()


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode()


def _verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": expire,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.effective_secret_key, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(
            token,
            settings.effective_secret_key,
            algorithms=[settings.ALGORITHM],
        )
    except Exception:
        return None


def get_user_by_username(db, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()


def authenticate(db, username: str, password: str) -> Optional[User]:
    # Constant-time-ish: always run a bcrypt check even if user missing,
    # so the response time doesn't leak whether the username exists.
    user = get_user_by_username(db, username)
    if user is not None:
        ok = _verify_password(password, user.password_hash)
    else:
        # Benchmark against a dummy hash so missing users take similar time.
        ok = _verify_password(password, _DUMMY_HASH)
        time.sleep(0.05)
    if not ok:
        return None
    return user


def seed_default_users(db) -> None:
    existing = {u.username for u in db.query(User).all()}
    to_create = []
    if "admin" not in existing:
        to_create.append(
            User(
                username="admin",
                password_hash=_hash_password(settings.SEED_ADMIN_PASSWORD),
                role=Role.ADMIN,
            )
        )
    if "analyst" not in existing:
        to_create.append(
            User(
                username="analyst",
                password_hash=_hash_password(settings.SEED_ANALYST_PASSWORD),
                role=Role.ANALYST,
            )
        )
    if to_create:
        db.add_all(to_create)
        db.commit()
