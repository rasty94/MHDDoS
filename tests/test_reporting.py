from audit_platform.reporting import (
    _sparkline,
    generate_html_report,
    generate_pdf_report,
    save_html_report,
)
from audit_platform.scoring import score_findings

FINDINGS = [
    {"severity": "high", "category": "TLS", "detail": "Weak cipher", "recommendation": "Disable it"},
    {"severity": "low", "category": "DNS", "detail": "No CAA record"},
]


def _report(findings):
    return {"target": "example.com", "findings": findings}


def test_html_report_with_findings():
    posture = score_findings(FINDINGS)
    out = generate_html_report(_report(FINDINGS), posture, history_scores=[90, 80, posture.score])
    assert "<!DOCTYPE html>" in out
    assert "example.com" in out
    assert "HIGH" in out and "Weak cipher" in out
    assert "<svg" in out  # sparkline rendered from multi-point history


def test_html_report_empty_findings_shows_clean_state():
    posture = score_findings([])
    out = generate_html_report(_report([]), posture)  # no history -> single-point sparkline
    assert "No issues detected" in out
    assert "<svg" in out


def test_save_html_report_writes_file(tmp_path):
    posture = score_findings(FINDINGS)
    path = tmp_path / "report.html"
    returned = save_html_report(_report(FINDINGS), posture, str(path))
    assert returned == str(path)
    assert path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_pdf_report_is_generated(tmp_path):
    posture = score_findings(FINDINGS)
    path = tmp_path / "report.pdf"
    generate_pdf_report(_report(FINDINGS), posture, str(path), history_scores=[70, 85, posture.score])
    assert path.exists()
    assert path.read_bytes()[:4] == b"%PDF"


def test_sparkline_edge_cases():
    assert _sparkline([]) == ""          # empty -> no svg
    assert "<svg" in _sparkline([50])    # single point is duplicated, still renders
