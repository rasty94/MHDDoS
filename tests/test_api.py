import os
import tempfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)
    monkeypatch.setenv("MHCHECK_DB_PATH", path)
    # Re-import modules so they pick up the patched DB path at module load.
    import importlib

    from audit_platform import storage as storage_mod
    importlib.reload(storage_mod)
    from audit_platform import inventory as inventory_mod
    importlib.reload(inventory_mod)
    from audit_platform import scheduler as scheduler_mod
    importlib.reload(scheduler_mod)
    import api as api_mod
    importlib.reload(api_mod)

    yield TestClient(api_mod.app)

    if os.path.exists(path):
        os.remove(path)


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_asset_crud(client):
    resp = client.post("/assets", json={"name": "API", "target": "api.example.com"})
    assert resp.status_code == 200
    asset_id = resp.json()["id"]

    resp = client.get("/assets")
    assert any(a["target"] == "api.example.com" for a in resp.json()["assets"])

    resp = client.delete(f"/assets/{asset_id}")
    assert resp.status_code == 200


def test_gate_rejects_bad_grade(client):
    resp = client.get("/gate", params={"target": "example.com", "min_grade": "Z"})
    assert resp.status_code == 400


def test_diff_without_history_returns_404(client):
    resp = client.get("/diff", params={"target": "never-audited.example"})
    assert resp.status_code == 404
