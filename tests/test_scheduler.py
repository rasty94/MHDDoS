import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from audit_platform import inventory, scheduler, storage
from audit_platform.osint.cyber_analysis import CyberAnalysisReport
from audit_platform.osint.model import OSINTMetadata


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


@patch("audit_platform.scheduler.CyberAnalysisAdapter")
def test_run_fleet_audit_success(mock_adapter_class, db_path):
    mock_adapter = MagicMock()
    mock_adapter_class.return_value = mock_adapter

    mock_report = CyberAnalysisReport(
        target="example.com",
        target_type="domain",
        metadata=OSINTMetadata(run_id="test-run-id", source="cyber_analysis", query="example.com"),
        findings=[],
        resolved_ips=[],
        dns_records={},
    )
    mock_adapter.analyze_target.return_value = mock_report

    inventory.add_asset(
        name="Test Asset",
        target="example.com",
        asset_type="domain",
        tenant="default",
        db_path=db_path,
    )

    results = scheduler.run_fleet_audit(tenant="default", db_path=db_path)

    assert len(results) == 1
    assert results[0]["asset"] == "Test Asset"
    assert results[0]["target"] == "example.com"
    assert results[0]["score"] == 100
    assert results[0]["grade"] == "A"

    scans = storage.get_recent_scans("example.com", limit=10, db_path=db_path)
    assert len(scans) == 1
    assert scans[0]["score"] == 100


def test_fleet_scheduler_lifecycle():
    sched = scheduler.FleetScheduler(interval_seconds=10, tenant="default")
    def dummy_loop():
        sched._stop.wait(10)
    sched._loop = dummy_loop
    sched.start()
    assert sched._thread is not None
    assert sched._thread.is_alive()
    sched.stop()
    sched._thread.join(timeout=1)
    assert not sched._thread.is_alive()
