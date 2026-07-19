from utils.osint import vuln_intel


class _FakeResp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, mapping):
        self._mapping = mapping

    def get(self, url, params=None, timeout=None, **kwargs):
        key = "nvd" if "nvd" in url else "osv"
        status, payload = self._mapping[key]
        return _FakeResp(status, payload)


def test_cvss_to_severity_bands():
    assert vuln_intel.cvss_to_severity(9.8) == "critical"
    assert vuln_intel.cvss_to_severity(7.5) == "high"
    assert vuln_intel.cvss_to_severity(5.0) == "medium"
    assert vuln_intel.cvss_to_severity(2.0) == "low"
    assert vuln_intel.cvss_to_severity(None) == "unknown"


def test_extract_cve_ids_dedupes_and_uppercases():
    text = "found cve-2021-44228 and CVE-2021-44228 plus CVE-2014-0160"
    assert vuln_intel.extract_cve_ids(text) == ["CVE-2021-44228", "CVE-2014-0160"]


def test_enrich_cve_from_nvd():
    nvd_payload = {
        "vulnerabilities": [
            {"cve": {
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]},
                "descriptions": [{"lang": "en", "value": "Log4Shell"}],
            }}
        ]
    }
    session = _FakeSession({"nvd": (200, nvd_payload), "osv": (404, {})})
    vuln = vuln_intel.enrich_cve("CVE-2021-44228", session=session)
    assert vuln.cvss_score == 10.0
    assert vuln.severity == "critical"
    assert vuln.source == "nvd"


def test_enrich_cve_falls_back_to_osv():
    osv_payload = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/.../7.5"}], "summary": "x"}
    session = _FakeSession({"nvd": (200, {"vulnerabilities": []}), "osv": (200, osv_payload)})
    vuln = vuln_intel.enrich_cve("CVE-2014-0160", session=session)
    assert vuln.cvss_score == 7.5
    assert vuln.source == "osv"


def test_enrich_cve_handles_total_failure():
    session = _FakeSession({"nvd": (500, {}), "osv": (500, {})})
    vuln = vuln_intel.enrich_cve("CVE-2000-0001", session=session)
    assert vuln.severity == "unknown"
    assert vuln.cvss_score is None


def test_vulnerabilities_to_findings_maps_severity():
    vulns = [vuln_intel.Vulnerability(cve_id="CVE-2021-44228", cvss_score=10.0, severity="critical")]
    findings = vuln_intel.vulnerabilities_to_findings(vulns)
    assert findings[0]["severity"] == "critical"
    assert "CVE-2021-44228" in findings[0]["detail"]
