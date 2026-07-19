"""AI-assisted remediation and triage.

Turns a flat list of findings into a prioritized action plan with human-readable
remediation guidance, using Claude via the official Anthropic SDK. If no API key
(or SDK) is available it degrades gracefully to a deterministic heuristic, so the
platform never hard-depends on the LLM being configured.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Default to the most capable model; override with MHCHECK_AI_MODEL if desired.
DEFAULT_MODEL = os.getenv("MHCHECK_AI_MODEL", "claude-opus-4-8")

# Ordering used by the heuristic fallback when Claude is not configured.
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

SYSTEM_PROMPT = (
    "You are a senior application security engineer triaging the findings of an "
    "automated posture audit. For each finding, assess real-world exploitability "
    "and business impact, then produce concrete remediation steps. Prioritize the "
    "list so the most urgent, most exploitable issues come first. Be concise and "
    "actionable. Respond with a JSON array; each item must have the keys: "
    "category, severity, priority (1 = most urgent), exploitability "
    "(one of: low, medium, high), remediation (one or two sentences)."
)


class RemediationItem(BaseModel):
    category: str
    severity: str
    priority: int
    exploitability: str
    remediation: str


def is_available() -> bool:
    """True when the Anthropic SDK is importable and an API key is configured."""
    if not os.getenv("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def _heuristic(findings: List[Dict[str, Any]]) -> List[RemediationItem]:
    """Deterministic fallback: order by severity and reuse the finding's own advice."""
    ordered = sorted(
        findings, key=lambda f: SEVERITY_RANK.get(str(f.get("severity", "info")).lower(), 5)
    )
    items: List[RemediationItem] = []
    for i, f in enumerate(ordered, start=1):
        severity = str(f.get("severity", "info")).lower()
        exploitability = "high" if severity in ("critical", "high") else "medium" if severity == "medium" else "low"
        items.append(
            RemediationItem(
                category=str(f.get("category", "")),
                severity=severity,
                priority=i,
                exploitability=exploitability,
                remediation=str(f.get("recommendation") or "Review and remediate this finding."),
            )
        )
    return items


def generate_remediation(
    findings: List[Dict[str, Any]], model: Optional[str] = None
) -> List[RemediationItem]:
    """Return a prioritized remediation plan, using Claude when available."""
    if not findings:
        return []
    if not is_available():
        logger.info("Anthropic API not configured; using heuristic remediation.")
        return _heuristic(findings)

    import anthropic

    client = anthropic.Anthropic()
    payload = json.dumps(
        [
            {
                "category": f.get("category"),
                "severity": f.get("severity"),
                "detail": f.get("detail"),
                "recommendation": f.get("recommendation"),
            }
            for f in findings
        ],
        indent=2,
    )

    try:
        response = client.messages.create(
            model=model or DEFAULT_MODEL,
            max_tokens=4000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Findings:\n{payload}\n\nReturn only the JSON array."}],
        )
        text = next((b.text for b in response.content if b.type == "text"), "")
        parsed = json.loads(_extract_json_array(text))
        return [RemediationItem(**item) for item in parsed]
    except Exception as exc:  # noqa: BLE001 - any LLM/parse failure falls back to the heuristic
        logger.error("AI remediation failed (%s); falling back to heuristic.", exc)
        return _heuristic(findings)


def _extract_json_array(text: str) -> str:
    """Best-effort extraction of the first JSON array from model output."""
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return text
