"""Fleet audit scheduler.

Runs an audit across every asset in the inventory, persists each result,
detects drift against the previous run and fires alerts. Can be invoked once
(by cron / CLI / API) or run as a background thread for the dashboard.
"""

import logging
import threading
import time
from typing import Any, Dict, List, Optional

from utils import alerts, inventory, storage
from utils.osint.cyber_analysis import CyberAnalysisAdapter
from utils.scoring import score_findings

logger = logging.getLogger(__name__)


def audit_asset(asset: Dict[str, Any], db_path: str = storage.DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Audit a single inventory asset, persist it, and return a per-asset summary."""
    adapter = CyberAnalysisAdapter()
    report = adapter.analyze_target(asset["target"])
    posture = score_findings(report.findings)

    storage.save_scan(
        target=report.target,
        source=report.metadata.source,
        score=posture.score,
        grade=posture.grade,
        findings=[f.model_dump() for f in report.findings],
        report=report.model_dump(mode="json"),
        run_id=report.metadata.run_id,
        db_path=db_path,
    )

    diff = storage.diff_scans(report.target, db_path=db_path)
    fired = alerts.evaluate_drift(diff, report.model_dump(mode="json"))
    dispatch_result = alerts.dispatch(fired) if fired else {}

    return {
        "asset": asset["name"],
        "target": report.target,
        "score": posture.score,
        "grade": posture.grade,
        "alerts": [a.model_dump() for a in fired],
        "dispatched": dispatch_result,
    }


def run_fleet_audit(
    tenant: Optional[str] = None, db_path: str = storage.DEFAULT_DB_PATH
) -> List[Dict[str, Any]]:
    """Audit every asset in the inventory (optionally scoped to a tenant)."""
    assets = inventory.list_assets(tenant=tenant, db_path=db_path)
    summaries: List[Dict[str, Any]] = []
    for asset in assets:
        try:
            summaries.append(audit_asset(asset, db_path=db_path))
        except Exception as exc:  # noqa: BLE001 - one bad asset must not abort the fleet run
            logger.error("Audit failed for asset %s: %s", asset.get("target"), exc)
            summaries.append({"asset": asset["name"], "target": asset["target"], "error": str(exc)})
    return summaries


class FleetScheduler:
    """Background scheduler that re-audits the fleet on a fixed interval."""

    def __init__(self, interval_seconds: int = 3600, tenant: Optional[str] = None):
        self.interval_seconds = interval_seconds
        self.tenant = tenant
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                run_fleet_audit(tenant=self.tenant)
            except Exception as exc:  # noqa: BLE001
                logger.error("Scheduled fleet audit failed: %s", exc)
            self._stop.wait(self.interval_seconds)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="fleet-scheduler")
        self._thread.start()
        logger.info("Fleet scheduler started (interval=%ss)", self.interval_seconds)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)


def _cli() -> None:  # pragma: no cover - manual/cron entrypoint
    logging.basicConfig(level=logging.INFO)
    start = time.time()
    results = run_fleet_audit()
    logger.info("Fleet audit complete in %.1fs: %d assets", time.time() - start, len(results))


if __name__ == "__main__":  # pragma: no cover
    _cli()
