"""MHcheck Audit Platform.

The continuous security-posture auditing platform lives entirely in this
package (auth, scoring, storage, inventory, scheduler, compliance, alerts,
reporting, AI remediation and the ``osint`` adapters). It is kept deliberately
separate from the inherited offensive tooling (``start.py`` and the legacy
helpers still under ``utils/``): nothing here imports the attack code, so the
platform can be reasoned about, tested and distributed on its own. This module
re-exports the stable public surface.

Public surface::

    from audit_platform import (
        score_findings, save_scan, diff_scans,
        add_asset, run_fleet_audit, evaluate_drift,
        evaluate_compliance, generate_html_report,
        authenticate, generate_remediation,
        CyberAnalysisAdapter,
    )
"""

from audit_platform.alerts import Alert, dispatch, evaluate_drift
from audit_platform.auth import User, authenticate, create_user, has_permission
from audit_platform.compliance import ComplianceScorecard, evaluate_all, evaluate_compliance
from audit_platform.inventory import add_asset, delete_asset, list_assets
from audit_platform.osint.cyber_analysis import CyberAnalysisAdapter
from audit_platform.osint.vuln_intel import Vulnerability, enrich_cve
from audit_platform.reporting import generate_html_report, generate_pdf_report, save_html_report
from audit_platform.scheduler import FleetScheduler, run_fleet_audit
from audit_platform.scoring import PostureScore, score_findings
from audit_platform.storage import diff_scans, get_recent_scans, list_targets, save_scan

try:  # AI remediation is optional at runtime
    from audit_platform.ai_remediation import generate_remediation
except Exception:  # noqa: BLE001 - never block platform import on the optional AI dep
    generate_remediation = None  # type: ignore[assignment]

__all__ = [
    "score_findings",
    "PostureScore",
    "save_scan",
    "diff_scans",
    "get_recent_scans",
    "list_targets",
    "add_asset",
    "delete_asset",
    "list_assets",
    "run_fleet_audit",
    "FleetScheduler",
    "evaluate_drift",
    "dispatch",
    "Alert",
    "evaluate_compliance",
    "evaluate_all",
    "ComplianceScorecard",
    "generate_html_report",
    "save_html_report",
    "generate_pdf_report",
    "authenticate",
    "create_user",
    "has_permission",
    "User",
    "enrich_cve",
    "Vulnerability",
    "generate_remediation",
    "CyberAnalysisAdapter",
]

__version__ = "1.0.0"
