"""Compliance mapping engine.

Maps the platform's finding categories onto controls of well-known frameworks
(OWASP ASVS, CIS, PCI-DSS, NIST CSF) and produces a per-framework scorecard.
A control is marked non-compliant when at least one finding maps to it, so the
scorecard answers "which controls are we currently failing?".

Frameworks are plain data, so adding one is just a dict entry.
"""

from typing import Any, Dict, List

from pydantic import BaseModel

# Each framework maps a control id -> (title, finding categories that, when
# present, indicate the control is not met).
FRAMEWORKS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "OWASP-ASVS": {
        "V9.1-TLS": {"title": "Communications: TLS everywhere", "categories": ["TLS", "Transport"]},
        "V14.4-Headers": {"title": "HTTP security headers", "categories": ["Security Header"]},
        "V14.5-InfoLeak": {"title": "Minimize information disclosure", "categories": ["Information Disclosure"]},
        "V1.14-Vulns": {"title": "Components free of known vulnerabilities", "categories": ["Vulnerability"]},
        "V2.1-Email": {"title": "Email authentication (SPF/DMARC)", "categories": ["SPF", "DMARC"]},
    },
    "CIS": {
        "3.10-Encryption": {"title": "Encrypt sensitive data in transit", "categories": ["TLS", "Transport"]},
        "7.1-Vuln-Mgmt": {"title": "Continuous vulnerability management", "categories": ["Vulnerability"]},
        "4.1-Secure-Config": {"title": "Secure configuration (headers)", "categories": ["Security Header", "Information Disclosure"]},
        "9.2-Email-Protections": {"title": "Email and DNS protections", "categories": ["SPF", "DMARC", "CAA"]},
    },
    "PCI-DSS": {
        "Req4-Transit": {"title": "Encrypt cardholder data across networks", "categories": ["TLS", "Transport"]},
        "Req6-Vulns": {"title": "Develop and maintain secure systems", "categories": ["Vulnerability"]},
        "Req2-Config": {"title": "Do not use vendor defaults / secure config", "categories": ["Security Header", "Information Disclosure"]},
    },
    "NIST-CSF": {
        "PR.DS-2": {"title": "Data-in-transit is protected", "categories": ["TLS", "Transport"]},
        "PR.IP-12": {"title": "Vulnerability management plan", "categories": ["Vulnerability"]},
        "PR.PT-3": {"title": "Least-functionality configuration", "categories": ["Security Header", "Information Disclosure"]},
        "PR.AC-5": {"title": "Network integrity (DNS/email)", "categories": ["SPF", "DMARC", "CAA"]},
    },
}


class ControlResult(BaseModel):
    control_id: str
    title: str
    compliant: bool
    related_findings: List[str] = []


class ComplianceScorecard(BaseModel):
    framework: str
    compliance_percent: int
    controls_total: int
    controls_compliant: int
    controls: List[ControlResult]


def available_frameworks() -> List[str]:
    return list(FRAMEWORKS.keys())


def _categories_of(findings: List[Any]) -> Dict[str, List[str]]:
    """Group finding details by category."""
    grouped: Dict[str, List[str]] = {}
    for f in findings:
        category = f.get("category") if isinstance(f, dict) else getattr(f, "category", "")
        detail = f.get("detail") if isinstance(f, dict) else getattr(f, "detail", "")
        grouped.setdefault(str(category or ""), []).append(str(detail or ""))
    return grouped


def evaluate_compliance(findings: List[Any], framework: str) -> ComplianceScorecard:
    if framework not in FRAMEWORKS:
        raise ValueError(f"Unknown framework '{framework}'. Available: {available_frameworks()}")

    grouped = _categories_of(findings)
    controls: List[ControlResult] = []
    compliant_count = 0

    for control_id, spec in FRAMEWORKS[framework].items():
        related: List[str] = []
        for category in spec["categories"]:
            related.extend(grouped.get(category, []))
        compliant = len(related) == 0
        if compliant:
            compliant_count += 1
        controls.append(
            ControlResult(control_id=control_id, title=spec["title"], compliant=compliant, related_findings=related)
        )

    total = len(controls)
    percent = round(100 * compliant_count / total) if total else 100
    return ComplianceScorecard(
        framework=framework,
        compliance_percent=percent,
        controls_total=total,
        controls_compliant=compliant_count,
        controls=controls,
    )


def evaluate_all(findings: List[Any]) -> Dict[str, ComplianceScorecard]:
    return {name: evaluate_compliance(findings, name) for name in available_frameworks()}
