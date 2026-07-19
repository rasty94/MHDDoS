"""Posture scoring engine.

Turns a flat list of findings into a normalized 0-100 posture score and an
A-F grade, so an audit answers "how exposed is this asset" rather than just
listing observations.
"""

from typing import Any, Dict, Iterable, List

from pydantic import BaseModel, Field

# Penalty (in points) applied to the 100-point baseline for each finding,
# keyed by severity. Unknown severities are treated as "info" (no penalty).
SEVERITY_PENALTIES: Dict[str, int] = {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 3,
    "info": 0,
}

# Lower bound (inclusive) of the score for each letter grade.
GRADE_THRESHOLDS = [
    ("A", 90),
    ("B", 80),
    ("C", 70),
    ("D", 60),
    ("F", 0),
]


class PostureScore(BaseModel):
    score: int = 100
    grade: str = "A"
    findings_total: int = 0
    severity_counts: Dict[str, int] = Field(default_factory=dict)


def _severity_of(finding: Any) -> str:
    if isinstance(finding, dict):
        severity = finding.get("severity", "info")
    else:
        severity = getattr(finding, "severity", "info")
    return str(severity).lower()


def grade_for_score(score: int) -> str:
    for grade, threshold in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def score_findings(findings: Iterable[Any]) -> PostureScore:
    """Compute a posture score from any iterable of findings exposing a severity."""
    findings_list: List[Any] = list(findings)
    severity_counts: Dict[str, int] = {}
    penalty_total = 0

    for finding in findings_list:
        severity = _severity_of(finding)
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        penalty_total += SEVERITY_PENALTIES.get(severity, 0)

    score = max(0, 100 - penalty_total)
    return PostureScore(
        score=score,
        grade=grade_for_score(score),
        findings_total=len(findings_list),
        severity_counts=severity_counts,
    )
