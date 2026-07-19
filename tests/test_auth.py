import os
import tempfile

import pytest

from audit_platform import auth


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_create_and_authenticate(db_path):
    auth.create_user("alice", "s3cret", role="auditor", tenant="acme", db_path=db_path)
    user = auth.authenticate("alice", "s3cret", db_path=db_path)
    assert user is not None
    assert user.role == "auditor"
    assert user.tenant == "acme"


def test_wrong_password_rejected(db_path):
    auth.create_user("bob", "rightpass", db_path=db_path)
    assert auth.authenticate("bob", "wrongpass", db_path=db_path) is None


def test_unknown_user_rejected(db_path):
    assert auth.authenticate("ghost", "x", db_path=db_path) is None


def test_password_is_hashed_not_stored_plaintext(db_path):
    auth.create_user("carol", "plaintextpw", db_path=db_path)
    from audit_platform.storage import _connect
    with _connect(db_path) as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE username='carol'").fetchone()
    assert "plaintextpw" not in row["password_hash"]


def test_rbac_permissions():
    admin = auth.User(username="a", role="admin", tenant="default")
    viewer = auth.User(username="v", role="viewer", tenant="default")
    assert auth.has_permission(admin, "manage_users")
    assert auth.has_permission(viewer, "view")
    assert not auth.has_permission(viewer, "audit")


def test_invalid_role_rejected(db_path):
    with pytest.raises(ValueError):
        auth.create_user("x", "pw", role="superuser", db_path=db_path)


def test_bootstrap_admin_from_env(db_path, monkeypatch):
    monkeypatch.setenv("MHCHECK_ADMIN_USER", "root")
    monkeypatch.setenv("MHCHECK_ADMIN_PASSWORD", "rootpass")
    created = auth.bootstrap_admin(db_path=db_path)
    assert created is not None and created.role == "admin"
    # second call is a no-op because users now exist
    assert auth.bootstrap_admin(db_path=db_path) is None
