"""MHcheck Audit Platform.

A cohesive, importable namespace for the continuous security-posture auditing
platform, kept deliberately separate from the inherited offensive tooling
(``methods/``, ``start.py``). Nothing in this package imports the attack code,
so the platform can be reasoned about, tested and distributed on its own.

Public surface::

    from audit_platform import (
        score_findings, save_scan, diff_scans,
        add_asset, run_fleet_audit, evaluate_drift,
        evaluate_compliance, generate_html_report,
        authenticate, generate_remediation,
        CyberAnalysisAdapter,
    )
"""

from utils.alerts import Alert, dispatch, evaluate_drift
from utils.auth import User, authenticate, create_user, has_permission
from utils.compliance import ComplianceScorecard, evaluate_all, evaluate_compliance
from utils.inventory import add_asset, delete_asset, list_assets
from utils.osint.cyber_analysis import CyberAnalysisAdapter
from utils.osint.vuln_intel import Vulnerability, enrich_cve
from utils.reporting import generate_html_report, generate_pdf_report, save_html_report
from utils.scheduler import FleetScheduler, run_fleet_audit
from utils.scoring import PostureScore, score_findings
from utils.storage import diff_scans, get_recent_scans, list_targets, save_scan

try:  # AI remediation is optional at runtime
    from utils.ai_remediation import generate_remediation
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
