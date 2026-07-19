import importlib
import os
import tempfile

import pytest
from typer.testing import CliRunner


@pytest.fixture
def cli(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)
    monkeypatch.setenv("MHCHECK_DB_PATH", path)
    # Reload storage/inventory/auth/scheduler and cli so they bind to the patched DB path.
    from utils import storage as storage_mod
    importlib.reload(storage_mod)
    from utils import inventory as inventory_mod
    importlib.reload(inventory_mod)
    from utils import auth as auth_mod
    importlib.reload(auth_mod)
    from utils import scheduler as scheduler_mod
    importlib.reload(scheduler_mod)
    import cli as cli_mod
    importlib.reload(cli_mod)
    yield cli_mod
    if os.path.exists(path):
        os.remove(path)


runner = CliRunner()


def test_asset_add_and_list(cli):
    result = runner.invoke(cli.app, ["asset", "add", "API", "api.example.com", "--group", "prod"])
    assert result.exit_code == 0
    assert "saved" in result.stdout.lower()

    result = runner.invoke(cli.app, ["asset", "list"])
    assert result.exit_code == 0
    assert "api.example.com" in result.stdout


def test_asset_remove_missing_fails(cli):
    result = runner.invoke(cli.app, ["asset", "remove", "9999"])
    assert result.exit_code == 1


def test_user_create_and_list(cli):
    result = runner.invoke(
        cli.app, ["user", "create", "alice", "--role", "auditor", "--password", "s3cret"]
    )
    assert result.exit_code == 0
    result = runner.invoke(cli.app, ["user", "list"])
    assert "alice" in result.stdout


def test_user_create_invalid_role_fails(cli):
    result = runner.invoke(
        cli.app, ["user", "create", "bob", "--role", "superuser", "--password", "x"]
    )
    assert result.exit_code == 2


def test_compliance_invalid_framework_fails(cli, monkeypatch):
    # Avoid network: stub the adapter to return an empty report.
    from utils.osint.cyber_analysis import CyberAnalysisAdapter, CyberAnalysisReport
    from utils.osint.model import OSINTMetadata

    def fake_analyze(self, target):
        return CyberAnalysisReport(
            metadata=OSINTMetadata(run_id="x", source="t", query=target),
            target=target,
            target_type="domain",
        )

    monkeypatch.setattr(CyberAnalysisAdapter, "analyze_target", fake_analyze)
    result = runner.invoke(cli.app, ["cyber", "compliance", "example.com", "--framework", "ISO-9001"])
    assert result.exit_code == 2
