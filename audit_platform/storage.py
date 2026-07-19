"""Lightweight SQLite persistence for audit history.

Every audit run is stored so the tool can answer the question a one-shot
scanner cannot: "what changed since the last audit?". This powers drift
detection (new open ports, regressed headers, soon-to-expire certificates).
"""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DEFAULT_DB_PATH = os.getenv("MHCHECK_DB_PATH", "audit_history.db")


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    with closing(_connect(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                target TEXT NOT NULL,
                source TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_target ON scans (target, id)"
        )
        conn.commit()


def save_scan(
    target: str,
    source: str,
    score: int,
    grade: str,
    findings: List[Dict[str, Any]],
    report: Dict[str, Any],
    run_id: str = "",
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    init_db(db_path)
    timestamp = datetime.now(timezone.utc).isoformat()
    with closing(_connect(db_path)) as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans
                (run_id, target, source, timestamp, score, grade, findings_json, report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                target,
                source,
                timestamp,
                score,
                grade,
                json.dumps(findings),
                json.dumps(report),
            ),
        )
        conn.commit()
        return cursor.lastrowid or 0


def get_recent_scans(
    target: str, limit: int = 2, db_path: str = DEFAULT_DB_PATH
) -> List[Dict[str, Any]]:
    """Return the most recent scans for a target, newest first."""
    if not os.path.exists(db_path):
        return []
    with closing(_connect(db_path)) as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE target = ? ORDER BY id DESC LIMIT ?",
            (target, limit),
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


def list_targets(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Return each audited target with its latest score and timestamp."""
    if not os.path.exists(db_path):
        return []
    with closing(_connect(db_path)) as conn:
        rows = conn.execute(
            """
            SELECT s.target, s.score, s.grade, s.timestamp
            FROM scans s
            JOIN (SELECT target, MAX(id) AS max_id FROM scans GROUP BY target) latest
            ON s.id = latest.max_id
            ORDER BY s.score ASC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    data = dict(row)
    data["findings"] = json.loads(data.pop("findings_json"))
    data["report"] = json.loads(data.pop("report_json"))
    return data


def _finding_key(finding: Dict[str, Any]) -> str:
    return f"{finding.get('category', '')}|{finding.get('detail', '')}"


def diff_scans(
    target: str, db_path: str = DEFAULT_DB_PATH
) -> Optional[Dict[str, Any]]:
    """Compare the two most recent scans for a target.

    Returns None if there are fewer than two scans to compare.
    """
    recent = get_recent_scans(target, limit=2, db_path=db_path)
    if len(recent) < 2:
        return None

    current, previous = recent[0], recent[1]
    current_findings = {_finding_key(f): f for f in current["findings"]}
    previous_findings = {_finding_key(f): f for f in previous["findings"]}

    new_keys = current_findings.keys() - previous_findings.keys()
    resolved_keys = previous_findings.keys() - current_findings.keys()

    return {
        "target": target,
        "previous": {"timestamp": previous["timestamp"], "score": previous["score"], "grade": previous["grade"]},
        "current": {"timestamp": current["timestamp"], "score": current["score"], "grade": current["grade"]},
        "score_delta": current["score"] - previous["score"],
        "new_findings": [current_findings[k] for k in new_keys],
        "resolved_findings": [previous_findings[k] for k in resolved_keys],
    }
