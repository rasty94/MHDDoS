"""Authentication, RBAC and multi-tenancy.

Provides local user accounts with salted PBKDF2 password hashing (stdlib only,
no external auth dependency), three roles with a permission matrix, and a
tenant on every user so audit data can be scoped per client (MSP use case).

Users live in the same SQLite database as assets and scans.
"""

import hashlib
import os
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel

from audit_platform.storage import DEFAULT_DB_PATH, _connect

PBKDF2_ITERATIONS = 240_000

# Role -> permissions. Permissions are checked by feature code.
ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "admin": ["audit", "manage_assets", "manage_users", "view", "configure"],
    "auditor": ["audit", "manage_assets", "view"],
    "viewer": ["view"],
}


class User(BaseModel):
    username: str
    role: str
    tenant: str


def init_auth(db_path: str = DEFAULT_DB_PATH) -> None:
    with closing(_connect(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                tenant TEXT NOT NULL DEFAULT 'default',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS).hex()


def create_user(
    username: str,
    password: str,
    role: str = "viewer",
    tenant: str = "default",
    db_path: str = DEFAULT_DB_PATH,
) -> User:
    if role not in ROLE_PERMISSIONS:
        raise ValueError(f"role must be one of {list(ROLE_PERMISSIONS)}")
    if not password:
        raise ValueError("password must not be empty")
    init_auth(db_path)
    salt = secrets.token_hex(16)
    password_hash = _hash_password(password, salt)
    created_at = datetime.now(timezone.utc).isoformat()
    with closing(_connect(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO users (username, salt, password_hash, role, tenant, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (username) DO UPDATE SET
                salt=excluded.salt, password_hash=excluded.password_hash,
                role=excluded.role, tenant=excluded.tenant
            """,
            (username, salt, password_hash, role, tenant, created_at),
        )
        conn.commit()
    return User(username=username, role=role, tenant=tenant)


def authenticate(username: str, password: str, db_path: str = DEFAULT_DB_PATH) -> Optional[User]:
    """Return the User on valid credentials, else None. Constant-time hash compare."""
    if not os.path.exists(db_path):
        return None
    init_auth(db_path)
    with closing(_connect(db_path)) as conn:
        row: Optional[sqlite3.Row] = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    if row is None:
        return None
    candidate = _hash_password(password, row["salt"])
    if not secrets.compare_digest(candidate, row["password_hash"]):
        return None
    return User(username=row["username"], role=row["role"], tenant=row["tenant"])


def has_permission(user: User, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(user.role, [])


def list_users(db_path: str = DEFAULT_DB_PATH) -> List[User]:
    if not os.path.exists(db_path):
        return []
    init_auth(db_path)
    with closing(_connect(db_path)) as conn:
        rows = conn.execute("SELECT username, role, tenant FROM users ORDER BY username").fetchall()
    return [User(username=r["username"], role=r["role"], tenant=r["tenant"]) for r in rows]


def bootstrap_admin(db_path: str = DEFAULT_DB_PATH) -> Optional[User]:
    """Create the initial admin from env vars if no users exist yet.

    Reads MHCHECK_ADMIN_USER / MHCHECK_ADMIN_PASSWORD. Returns the created user
    or None if users already exist or env is not set.
    """
    init_auth(db_path)
    if list_users(db_path=db_path):
        return None
    username = os.getenv("MHCHECK_ADMIN_USER")
    password = os.getenv("MHCHECK_ADMIN_PASSWORD")
    if not username or not password:
        return None
    return create_user(username, password, role="admin", tenant="default", db_path=db_path)


def sign_session(username: str, tenant: str, role: str) -> str:
    from itsdangerous import TimestampSigner
    secret = os.getenv("MHCHECK_SECRET_KEY", "default-secret-key-please-change-in-production")
    s = TimestampSigner(secret)
    payload = f"{username}:{tenant}:{role}"
    return s.sign(payload.encode()).decode()


def verify_session(token: str, max_age_seconds: int = 7 * 24 * 3600) -> Optional[User]:
    from itsdangerous import BadSignature, SignatureExpired, TimestampSigner
    secret = os.getenv("MHCHECK_SECRET_KEY", "default-secret-key-please-change-in-production")
    s = TimestampSigner(secret)
    try:
        payload = s.unsign(token.encode(), max_age=max_age_seconds).decode()
        parts = payload.split(":")
        if len(parts) == 3:
            return User(username=parts[0], tenant=parts[1], role=parts[2])
    except (SignatureExpired, BadSignature, ValueError):
        pass
    return None
