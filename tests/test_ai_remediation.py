from audit_platform import ai_remediation


def test_heuristic_orders_by_severity(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    findings = [
        {"category": "Header", "severity": "low", "detail": "x", "recommendation": "add header"},
        {"category": "TLS", "severity": "critical", "detail": "y", "recommendation": "fix tls"},
        {"category": "SPF", "severity": "medium", "detail": "z", "recommendation": "add spf"},
    ]
    plan = ai_remediation.generate_remediation(findings)
    assert [item.severity for item in plan] == ["critical", "medium", "low"]
    assert plan[0].priority == 1
    assert plan[0].category == "TLS"


def test_empty_findings_returns_empty(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert ai_remediation.generate_remediation([]) == []


def test_is_available_false_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert ai_remediation.is_available() is False


def test_heuristic_exploitability_mapping(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    plan = ai_remediation.generate_remediation([{"category": "TLS", "severity": "high", "detail": "d"}])
    assert plan[0].exploitability == "high"
