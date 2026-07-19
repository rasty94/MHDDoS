"""Vulnerability intelligence layer.

Promotes raw CVE strings (e.g. from the Nmap ``vulners`` script) into a
structured model carrying a CVSS score and severity, enriched from public
feeds (NVD, with OSV as a fallback). These severities then feed the posture
score so a host running vulnerable services is graded accordingly.

Network access is injected via a ``session`` object so the enrichment logic is
fully testable offline.
"""

from __future__ import annotations

import logging
import re
from contextlib import closing
from datetime import datetime, timezone
from typing import List, Optional

import requests
from pydantic import BaseModel

from utils.storage import DEFAULT_DB_PATH, _connect

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1/vulns/"


def init_cve_cache(db_path: str = DEFAULT_DB_PATH) -> None:
    with closing(_connect(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                cvss_score REAL,
                severity TEXT NOT NULL,
                summary TEXT,
                source TEXT,
                cached_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def _get_cached_cve(cve_id: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Vulnerability]:
    try:
        init_cve_cache(db_path)
        with closing(_connect(db_path)) as conn:
            row = conn.execute("SELECT * FROM cve_cache WHERE cve_id = ?", (cve_id,)).fetchone()
        if row:
            return Vulnerability(
                cve_id=row["cve_id"],
                cvss_score=row["cvss_score"],
                severity=row["severity"],
                summary=row["summary"],
                source=row["source"],
            )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Failed to read CVE cache: %s", exc)
    return None


def _set_cached_cve(vuln: Vulnerability, db_path: str = DEFAULT_DB_PATH) -> None:
    try:
        init_cve_cache(db_path)
        cached_at = datetime.now(timezone.utc).isoformat()
        with closing(_connect(db_path)) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cve_cache (cve_id, cvss_score, severity, summary, source, cached_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (vuln.cve_id, vuln.cvss_score, vuln.severity, vuln.summary, vuln.source, cached_at),
            )
            conn.commit()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Failed to write CVE cache: %s", exc)


class Vulnerability(BaseModel):
    cve_id: str
    cvss_score: Optional[float] = None
    severity: str = "unknown"
    summary: Optional[str] = None
    source: Optional[str] = None


def cvss_to_severity(score: Optional[float]) -> str:
    """Map a CVSS v3 base score to a severity band."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def extract_cve_ids(text: str) -> List[str]:
    """Pull unique, upper-cased CVE identifiers out of arbitrary text."""
    seen: List[str] = []
    for match in CVE_PATTERN.findall(text or ""):
        cve = match.upper()
        if cve not in seen:
            seen.append(cve)
    return seen


def _enrich_from_nvd(cve_id: str, session: requests.Session, timeout: float) -> Optional[Vulnerability]:
    resp = session.get(NVD_API, params={"cveId": cve_id}, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})
    metrics = cve.get("metrics", {})
    score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            score = metrics[key][0]["cvssData"]["baseScore"]
            break
    descriptions = cve.get("descriptions", [])
    summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
    return Vulnerability(
        cve_id=cve_id,
        cvss_score=score,
        severity=cvss_to_severity(score),
        summary=summary,
        source="nvd",
    )


def _enrich_from_osv(cve_id: str, session: requests.Session, timeout: float) -> Optional[Vulnerability]:
    resp = session.get(f"{OSV_API}{cve_id}", timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    score = None
    for sev in data.get("severity", []):
        raw = sev.get("score", "")
        match = re.search(r"/(\d+\.\d+)$", raw) or re.search(r"(\d+\.\d+)", raw)
        if match:
            score = float(match.group(1))
            break
    return Vulnerability(
        cve_id=cve_id,
        cvss_score=score,
        severity=cvss_to_severity(score),
        summary=data.get("summary") or data.get("details"),
        source="osv",
    )


def enrich_cve(
    cve_id: str, session: Optional[requests.Session] = None, timeout: float = 10.0, db_path: str = DEFAULT_DB_PATH
) -> Vulnerability:
    """Enrich a single CVE, trying NVD then OSV. Never raises; returns 'unknown' on failure."""
    cached = _get_cached_cve(cve_id, db_path)
    if cached is not None:
        return cached

    session = session or requests.Session()
    result = None
    for enricher in (_enrich_from_nvd, _enrich_from_osv):
        try:
            result = enricher(cve_id, session, timeout)
            if result is not None:
                break
        except Exception as exc:  # noqa: BLE001 - any feed error falls through to the next
            logger.debug("Enrichment via %s failed for %s: %s", enricher.__name__, cve_id, exc)

    if result is None:
        result = Vulnerability(cve_id=cve_id)

    _set_cached_cve(result, db_path)
    return result


def enrich_many(
    cve_ids: List[str], session: Optional[requests.Session] = None, timeout: float = 10.0, db_path: str = DEFAULT_DB_PATH
) -> List[Vulnerability]:
    session = session or requests.Session()
    return [enrich_cve(cve, session=session, timeout=timeout, db_path=db_path) for cve in cve_ids]


def enrich_osint_result(result, session: Optional[requests.Session] = None, db_path: str = DEFAULT_DB_PATH) -> List[Vulnerability]:
    """Extract every CVE referenced across an OSINTUnifiedResult's hosts and enrich them."""
    cve_ids: List[str] = []
    for host in getattr(result, "hosts", []):
        for raw in getattr(host, "vulnerabilities", []):
            for cve in extract_cve_ids(str(raw)):
                if cve not in cve_ids:
                    cve_ids.append(cve)
    return enrich_many(cve_ids, session=session, db_path=db_path)


def vulnerabilities_to_findings(vulns: List[Vulnerability]) -> List[dict]:
    """Convert vulnerabilities into finding dicts compatible with ``score_findings``."""
    findings = []
    for vuln in vulns:
        findings.append(
            {
                "category": "Vulnerability",
                "severity": vuln.severity if vuln.severity != "unknown" else "low",
                "detail": f"{vuln.cve_id} (CVSS {vuln.cvss_score})" + (f": {vuln.summary}" if vuln.summary else ""),
                "recommendation": "Patch or mitigate the affected service.",
            }
        )
    return findings
