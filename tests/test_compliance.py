import pytest

from utils import compliance
from utils.reporting import generate_html_report
from utils.scoring import score_findings


def test_clean_findings_full_compliance():
    scorecard = compliance.evaluate_compliance([], "OWASP-ASVS")
    assert scorecard.compliance_percent == 100
    assert scorecard.controls_compliant == scorecard.controls_total


def test_tls_finding_fails_tls_control():
    findings = [{"category": "TLS", "severity": "high", "detail": "weak proto"}]
    scorecard = compliance.evaluate_compliance(findings, "OWASP-ASVS")
    tls_control = next(c for c in scorecard.controls if c.control_id == "V9.1-TLS")
    assert tls_control.compliant is False
    assert scorecard.compliance_percent < 100


def test_unknown_framework_raises():
    with pytest.raises(ValueError):
        compliance.evaluate_compliance([], "ISO-9001")


def test_evaluate_all_covers_every_framework():
    result = compliance.evaluate_all([])
    assert set(result.keys()) == set(compliance.available_frameworks())


def test_html_report_contains_target_and_grade():
    findings = [{"category": "Security Header", "severity": "low", "detail": "CSP missing", "recommendation": "Add CSP"}]
    report = {"target": "example.com", "findings": findings}
    posture = score_findings(findings)
    html_out = generate_html_report(report, posture, history_scores=[90, 95, posture.score])
    assert "example.com" in html_out
    assert posture.grade in html_out
    assert "Compliance Scorecards" in html_out
    assert "<svg" in html_out  # trend sparkline rendered
