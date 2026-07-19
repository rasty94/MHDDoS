from unittest.mock import MagicMock

from utils.osint.cyber_analysis import CyberAnalysisAdapter, TLSCertificateInfo


class FakeAnswer:
    def __init__(self, value):
        self.value = value

    def to_text(self):
        return self.value


def test_cyber_analysis_domain_parses_dns_and_flags_missing_controls():
    resolver = MagicMock()

    def resolve_side_effect(name, record_type):
        if name == "example.com" and record_type == "A":
            return [FakeAnswer("93.184.216.34")]
        if name == "example.com" and record_type == "AAAA":
            return []
        if name == "example.com" and record_type == "TXT":
            return [FakeAnswer('"v=spf1 include:_spf.example.com -all"')]
        if name == "example.com" and record_type == "MX":
            return [FakeAnswer("10 mail.example.com.")]
        if name == "example.com" and record_type == "NS":
            return [FakeAnswer("ns1.example.com.")]
        if name == "example.com" and record_type == "CAA":
            raise Exception("no answer")
        if name == "_dmarc.example.com" and record_type == "TXT":
            raise Exception("no answer")
        raise Exception(f"unexpected query: {name} {record_type}")

    resolver.resolve.side_effect = resolve_side_effect

    adapter = CyberAnalysisAdapter(resolver=resolver, session=MagicMock())
    report = adapter.analyze_domain("example.com")

    assert report.target_type == "domain"
    assert report.resolved_ips == ["93.184.216.34"]
    assert report.dns_records["MX"] == ["10 mail.example.com."]
    assert any(finding.category == "DMARC" for finding in report.findings)
    assert any(finding.category == "CAA" for finding in report.findings)


def test_cyber_analysis_url_collects_headers_and_tls():
    resolver = MagicMock()

    def resolve_side_effect(name, record_type):
        if name == "example.com" and record_type in {"A", "AAAA"}:
            return [FakeAnswer("93.184.216.34")] if record_type == "A" else []
        raise Exception(f"unexpected query: {name} {record_type}")

    resolver.resolve.side_effect = resolve_side_effect

    response = MagicMock()
    response.headers = {
        "Server": "nginx",
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=31536000",
    }
    response.status_code = 200
    response.url = "https://example.com"

    session = MagicMock()
    session.head.return_value = response

    adapter = CyberAnalysisAdapter(resolver=resolver, session=session)
    adapter._inspect_tls = MagicMock(
        return_value=TLSCertificateInfo(enabled=True, subject="CN=example.com")
    )

    report = adapter.analyze_url("https://example.com")

    assert report.target_type == "url"
    assert report.web is not None
    assert report.web.status_code == 200
    assert report.web.server == "nginx"
    assert "Content-Security-Policy" in report.web.missing_headers
    assert report.tls is not None and report.tls.enabled is True
