import os
import tempfile

import pytest

from utils import storage


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)  # let init_db create it fresh
    yield path
    if os.path.exists(path):
        os.remove(path)


def _save(path, target, score, grade, findings):
    storage.save_scan(
        target=target,
        source="cyber",
        score=score,
        grade=grade,
        findings=findings,
        report={"target": target},
        db_path=path,
    )


def test_diff_requires_two_scans(db_path):
    _save(db_path, "example.com", 90, "A", [])
    assert storage.diff_scans("example.com", db_path=db_path) is None


def test_diff_reports_new_and_resolved(db_path):
    _save(db_path, "example.com", 80, "B", [
        {"category": "SPF", "severity": "medium", "detail": "No SPF"},
        {"category": "CAA", "severity": "low", "detail": "No CAA"},
    ])
    _save(db_path, "example.com", 70, "C", [
        {"category": "CAA", "severity": "low", "detail": "No CAA"},
        {"category": "TLS", "severity": "high", "detail": "weak proto"},
    ])

    diff = storage.diff_scans("example.com", db_path=db_path)
    assert diff["score_delta"] == -10
    assert [f["category"] for f in diff["new_findings"]] == ["TLS"]
    assert [f["category"] for f in diff["resolved_findings"]] == ["SPF"]


def test_list_targets_returns_latest_score(db_path):
    _save(db_path, "a.com", 90, "A", [])
    _save(db_path, "a.com", 60, "D", [{"severity": "high"}])
    _save(db_path, "b.com", 80, "B", [])

    targets = {t["target"]: t for t in storage.list_targets(db_path=db_path)}
    assert targets["a.com"]["score"] == 60  # latest, not first
    assert targets["b.com"]["score"] == 80
