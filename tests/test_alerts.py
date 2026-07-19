from audit_platform import alerts


def _diff(delta, new_findings):
    return {
        "target": "example.com",
        "previous": {"score": 90, "grade": "A", "timestamp": "t0"},
        "current": {"score": 90 + delta, "grade": "A", "timestamp": "t1"},
        "score_delta": delta,
        "new_findings": new_findings,
        "resolved_findings": [],
    }


def test_score_regression_triggers_alert():
    fired = alerts.evaluate_drift(_diff(-15, []))
    assert any(a.rule == "score_regression" for a in fired)


def test_small_score_drop_does_not_alert():
    fired = alerts.evaluate_drift(_diff(-2, []))
    assert fired == []


def test_new_high_finding_triggers_alert():
    fired = alerts.evaluate_drift(_diff(0, [{"severity": "high", "category": "TLS", "detail": "weak"}]))
    assert any(a.rule == "new_serious_finding" for a in fired)


def test_new_low_finding_does_not_alert():
    fired = alerts.evaluate_drift(_diff(0, [{"severity": "low", "category": "Header", "detail": "missing"}]))
    assert fired == []


def test_cert_expiry_alert_from_report():
    report = {"target": "example.com", "tls": {"days_remaining": 5}}
    fired = alerts.evaluate_drift(None, report)
    assert any(a.rule == "cert_expiry" for a in fired)


def test_no_channels_configured_dispatch_is_safe(monkeypatch):
    for var in ("MHCHECK_ALERT_WEBHOOK_URL", "MHCHECK_ALERT_SLACK_WEBHOOK",
                "MHCHECK_ALERT_TELEGRAM_BOT_TOKEN", "MHCHECK_ALERT_SMTP_HOST"):
        monkeypatch.delenv(var, raising=False)
    fired = alerts.evaluate_drift(_diff(-20, []))
    result = alerts.dispatch(fired)
    assert all(sent == [] for sent in result.values())


def test_all_channels_dispatched_successfully(monkeypatch):
    import requests_mock
    with requests_mock.Mocker() as m:
        m.post("http://fake-webhook.com", json={})
        m.post("http://fake-slack.com", json={})
        m.post("https://api.telegram.org/botfake-token/sendMessage", json={})

        monkeypatch.setenv("MHCHECK_ALERT_WEBHOOK_URL", "http://fake-webhook.com")
        monkeypatch.setenv("MHCHECK_ALERT_SLACK_WEBHOOK", "http://fake-slack.com")
        monkeypatch.setenv("MHCHECK_ALERT_TELEGRAM_BOT_TOKEN", "fake-token")
        monkeypatch.setenv("MHCHECK_ALERT_TELEGRAM_CHAT_ID", "12345")

        from unittest.mock import MagicMock
        smtp_mock = MagicMock()
        monkeypatch.setattr("smtplib.SMTP", MagicMock(return_value=smtp_mock))
        monkeypatch.setenv("MHCHECK_ALERT_SMTP_HOST", "localhost")
        monkeypatch.setenv("MHCHECK_ALERT_EMAIL_TO", "admin@example.com")

        fired = alerts.evaluate_drift(_diff(-20, []))
        result = alerts.dispatch(fired)

        sent_channels = result[list(result.keys())[0]]
        assert "webhook" in sent_channels
        assert "slack" in sent_channels
        assert "telegram" in sent_channels
        assert "email" in sent_channels

        assert m.called
        assert len(m.request_history) == 3
        assert smtp_mock.__enter__.return_value.sendmail.called
