"""Alerting engine.

Turns drift into push notifications. Rule evaluation is pure and testable;
delivery is handled by pluggable channels configured through environment
variables, so the same alert can fan out to a webhook, Slack, Telegram or email.
"""

import logging
import os
import smtplib
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

import requests
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Severity ordering used to decide what counts as a "serious" new finding.
SERIOUS_SEVERITIES = {"critical", "high"}
SCORE_DROP_THRESHOLD = int(os.getenv("MHCHECK_ALERT_SCORE_DROP", "10"))
CERT_EXPIRY_ALERT_DAYS = int(os.getenv("MHCHECK_ALERT_CERT_DAYS", "21"))


class Alert(BaseModel):
    target: str
    rule: str
    severity: str
    title: str
    detail: str


def evaluate_drift(
    diff: Optional[Dict[str, Any]], report: Optional[Dict[str, Any]] = None
) -> List[Alert]:
    """Evaluate alert rules against a drift result and (optionally) a fresh report."""
    alerts: List[Alert] = []
    if diff:
        target = diff.get("target", "")
        delta = diff.get("score_delta", 0)
        if delta <= -SCORE_DROP_THRESHOLD:
            alerts.append(
                Alert(
                    target=target,
                    rule="score_regression",
                    severity="high",
                    title=f"Posture score dropped {abs(delta)} points",
                    detail=f"{target}: {diff['previous']['score']} -> {diff['current']['score']}",
                )
            )
        for finding in diff.get("new_findings", []):
            if str(finding.get("severity", "")).lower() in SERIOUS_SEVERITIES:
                alerts.append(
                    Alert(
                        target=target,
                        rule="new_serious_finding",
                        severity=str(finding.get("severity")),
                        title=f"New {finding.get('severity')} finding: {finding.get('category')}",
                        detail=str(finding.get("detail", "")),
                    )
                )

    if report:
        target = report.get("target", "")
        tls = report.get("tls") or {}
        days_remaining = tls.get("days_remaining")
        if days_remaining is not None and 0 <= days_remaining <= CERT_EXPIRY_ALERT_DAYS:
            alerts.append(
                Alert(
                    target=target,
                    rule="cert_expiry",
                    severity="medium",
                    title=f"TLS certificate expires in {days_remaining} day(s)",
                    detail=f"{target}: renew before expiry to avoid an outage.",
                )
            )

    return alerts


# --- Notification channels ---------------------------------------------------


def _format_message(alert: Alert) -> str:
    return f"[{alert.severity.upper()}] {alert.title}\n{alert.detail}\n(target: {alert.target}, rule: {alert.rule})"


def _send_webhook(alert: Alert) -> bool:
    url = os.getenv("MHCHECK_ALERT_WEBHOOK_URL")
    if not url:
        return False
    try:
        requests.post(url, json=alert.model_dump(), timeout=10)
        return True
    except requests.RequestException as exc:
        logger.error("Webhook alert failed: %s", exc)
        return False


def _send_slack(alert: Alert) -> bool:
    url = os.getenv("MHCHECK_ALERT_SLACK_WEBHOOK")
    if not url:
        return False
    try:
        requests.post(url, json={"text": _format_message(alert)}, timeout=10)
        return True
    except requests.RequestException as exc:
        logger.error("Slack alert failed: %s", exc)
        return False


def _send_telegram(alert: Alert) -> bool:
    token = os.getenv("MHCHECK_ALERT_TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("MHCHECK_ALERT_TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return False
    try:
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": _format_message(alert)},
            timeout=10,
        )
        return True
    except requests.RequestException as exc:
        logger.error("Telegram alert failed: %s", exc)
        return False


def _send_email(alert: Alert) -> bool:
    host = os.getenv("MHCHECK_ALERT_SMTP_HOST")
    to_addr = os.getenv("MHCHECK_ALERT_EMAIL_TO")
    if not host or not to_addr:
        return False
    port = int(os.getenv("MHCHECK_ALERT_SMTP_PORT", "587"))
    user = os.getenv("MHCHECK_ALERT_SMTP_USER", "")
    password = os.getenv("MHCHECK_ALERT_SMTP_PASSWORD", "")
    from_addr = os.getenv("MHCHECK_ALERT_EMAIL_FROM", user or "mhcheck@localhost")
    try:
        msg = MIMEText(_format_message(alert))
        msg["Subject"] = f"[MHcheck] {alert.title}"
        msg["From"] = from_addr
        msg["To"] = to_addr
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls()
            if user:
                server.login(user, password)
            server.sendmail(from_addr, [to_addr], msg.as_string())
        return True
    except Exception as exc:  # noqa: BLE001 - SMTP raises many exception types
        logger.error("Email alert failed: %s", exc)
        return False


CHANNELS = {
    "webhook": _send_webhook,
    "slack": _send_slack,
    "telegram": _send_telegram,
    "email": _send_email,
}


def dispatch(alerts: List[Alert]) -> Dict[str, List[str]]:
    """Send each alert through every configured channel. Returns channels used per alert."""
    results: Dict[str, List[str]] = {}
    for alert in alerts:
        sent_via = [name for name, sender in CHANNELS.items() if sender(alert)]
        results[alert.title] = sent_via
        if not sent_via:
            logger.info("No alert channel configured; alert not delivered: %s", alert.title)
    return results
