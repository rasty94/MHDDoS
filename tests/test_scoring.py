from audit_platform.scoring import grade_for_score, score_findings


def test_score_subtracts_severity_penalties():
    findings = [
        {"severity": "high", "category": "TLS", "detail": "weak"},
        {"severity": "low", "category": "Header", "detail": "missing"},
    ]
    posture = score_findings(findings)
    assert posture.score == 100 - 20 - 3
    assert posture.severity_counts == {"high": 1, "low": 1}
    assert posture.findings_total == 2


def test_score_never_goes_negative():
    findings = [{"severity": "critical"} for _ in range(10)]
    posture = score_findings(findings)
    assert posture.score == 0
    assert posture.grade == "F"


def test_clean_target_scores_perfect():
    posture = score_findings([])
    assert posture.score == 100
    assert posture.grade == "A"


def test_unknown_severity_is_treated_as_info():
    posture = score_findings([{"severity": "weird"}])
    assert posture.score == 100


def test_grade_thresholds():
    assert grade_for_score(90) == "A"
    assert grade_for_score(89) == "B"
    assert grade_for_score(70) == "C"
    assert grade_for_score(60) == "D"
    assert grade_for_score(59) == "F"
