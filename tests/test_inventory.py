import os
import tempfile

import pytest

from audit_platform import inventory


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_add_and_list_asset(db_path):
    inventory.add_asset("API", "api.example.com", asset_type="domain", group="prod", tags=["public"], db_path=db_path)
    assets = inventory.list_assets(db_path=db_path)
    assert len(assets) == 1
    assert assets[0]["target"] == "api.example.com"
    assert assets[0]["tags"] == ["public"]


def test_add_is_idempotent_per_tenant_target(db_path):
    inventory.add_asset("API", "api.example.com", db_path=db_path)
    inventory.add_asset("API renamed", "api.example.com", db_path=db_path)
    assets = inventory.list_assets(db_path=db_path)
    assert len(assets) == 1
    assert assets[0]["name"] == "API renamed"


def test_tenant_isolation(db_path):
    inventory.add_asset("A", "a.com", tenant="acme", db_path=db_path)
    inventory.add_asset("B", "b.com", tenant="globex", db_path=db_path)
    assert len(inventory.list_assets(tenant="acme", db_path=db_path)) == 1
    assert inventory.list_assets(tenant="acme", db_path=db_path)[0]["target"] == "a.com"


def test_invalid_asset_type_rejected(db_path):
    with pytest.raises(ValueError):
        inventory.add_asset("bad", "x.com", asset_type="banana", db_path=db_path)


def test_delete_asset(db_path):
    asset_id = inventory.add_asset("A", "a.com", db_path=db_path)
    assert inventory.delete_asset(asset_id, db_path=db_path) is True
    assert inventory.list_assets(db_path=db_path) == []
