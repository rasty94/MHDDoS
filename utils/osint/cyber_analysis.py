import datetime
import ipaddress
import logging
import socket
import ssl
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from dns import resolver as dns_resolver
from pydantic import BaseModel, Field

from .model import OSINTMetadata

logger = logging.getLogger(__name__)


SECURITY_HEADERS = {
    "Content-Security-Policy": "Restricts where browsers can load content from.",
    "Strict-Transport-Security": "Forces HTTPS usage for future requests.",
    "X-Frame-Options": "Reduces clickjacking exposure.",
    "X-Content-Type-Options": "Prevents MIME type sniffing.",
    "Referrer-Policy": "Controls how much referrer data is leaked.",
    "Permissions-Policy": "Limits browser feature access.",
}


class AnalysisFinding(BaseModel):
    category: str
    severity: str = "info"
    detail: str
    recommendation: Optional[str] = None


class TLSCertificateInfo(BaseModel):
    enabled: bool = False
    subject: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[datetime.datetime] = None
    valid_to: Optional[datetime.datetime] = None
    days_remaining: Optional[int] = None
    expired: bool = False
    sans: List[str] = Field(default_factory=list)


class WebEndpointInfo(BaseModel):
    url: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    server: Optional[str] = None
    content_type: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    security_headers: Dict[str, Optional[str]] = Field(default_factory=dict)
    missing_headers: List[str] = Field(default_factory=list)


class CyberAnalysisReport(BaseModel):
    metadata: OSINTMetadata
    target: str
    target_type: str
    resolved_ips: List[str] = Field(default_factory=list)
    dns_records: Dict[str, List[str]] = Field(default_factory=dict)
    web: Optional[WebEndpointInfo] = None
    tls: Optional[TLSCertificateInfo] = None
    findings: List[AnalysisFinding] = Field(default_factory=list)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class CyberAnalysisAdapter:
    def __init__(
        self,
        resolver: Optional[dns_resolver.Resolver] = None,
        session: Optional[requests.Session] = None,
        timeout: float = 5.0,
    ):
        self.resolver = resolver or dns_resolver.Resolver()
        self.session = session or requests.Session()
        self.timeout = timeout

    def analyze_target(self, target: str) -> CyberAnalysisReport:
        normalized = self._normalize_target(target)

        if normalized.startswith(("http://", "https://")):
            return self.analyze_url(normalized)

        host = self._strip_path(normalized)
        if self._looks_like_ip(host):
            return self.analyze_host(host)

        return self.analyze_domain(host)

    def analyze_domain(self, domain: str) -> CyberAnalysisReport:
        domain = self._strip_path(domain)
        metadata = OSINTMetadata(
            run_id=str(uuid.uuid4()),
            source="cyber-analysis-domain",
            query=domain,
        )
        report = CyberAnalysisReport(metadata=metadata, target=domain, target_type="domain")

        record_types = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
        for record_type in record_types:
            values = self._resolve_dns_records(domain, record_type)
            report.dns_records[record_type] = values
            if record_type in {"A", "AAAA"}:
                for value in values:
                    if value not in report.resolved_ips:
                        report.resolved_ips.append(value)

        txt_blob = " ".join(report.dns_records.get("TXT", [])).lower()
        if "v=spf1" not in txt_blob:
            report.findings.append(
                AnalysisFinding(
                    category="SPF",
                    severity="medium",
                    detail="No SPF policy was detected in TXT records.",
                    recommendation="Publish a TXT record with a v=spf1 policy for authorized mail senders.",
                )
            )

        dmarc_records = self._resolve_dns_records(f"_dmarc.{domain}", "TXT")
        if not any("v=dmarc1" in value.lower() for value in dmarc_records):
            report.findings.append(
                AnalysisFinding(
                    category="DMARC",
                    severity="medium",
                    detail="No DMARC policy was detected for the domain.",
                    recommendation="Add a _dmarc TXT record with a reporting and enforcement policy.",
                )
            )

        if not report.dns_records.get("CAA"):
            report.findings.append(
                AnalysisFinding(
                    category="CAA",
                    severity="low",
                    detail="No CAA record was detected.",
                    recommendation="Publish a CAA record to limit which certificate authorities may issue certificates.",
                )
            )

        report.raw_data = {"dns_records": report.dns_records}
        return report

    def analyze_host(self, host: str) -> CyberAnalysisReport:
        host = self._strip_path(host)
        metadata = OSINTMetadata(
            run_id=str(uuid.uuid4()),
            source="cyber-analysis-host",
            query=host,
        )
        report = CyberAnalysisReport(metadata=metadata, target=host, target_type="host")

        try:
            reverse_name, aliases, addresses = socket.gethostbyaddr(host)
            report.raw_data["reverse_dns"] = {
                "hostname": reverse_name,
                "aliases": aliases,
                "addresses": addresses,
            }
            for address in addresses:
                if address not in report.resolved_ips:
                    report.resolved_ips.append(address)
            report.findings.append(
                AnalysisFinding(
                    category="Reverse DNS",
                    severity="info",
                    detail=f"Reverse DNS resolved to {reverse_name}.",
                )
            )
        except (socket.herror, socket.gaierror):
            report.raw_data["reverse_dns"] = None

        return report

    def analyze_url(self, url: str) -> CyberAnalysisReport:
        url = self._normalize_url(url)
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        metadata = OSINTMetadata(
            run_id=str(uuid.uuid4()),
            source="cyber-analysis-url",
            query=url,
        )
        report = CyberAnalysisReport(metadata=metadata, target=url, target_type="url")

        if hostname:
            for record_type in ("A", "AAAA"):
                for value in self._resolve_dns_records(hostname, record_type):
                    if value not in report.resolved_ips:
                        report.resolved_ips.append(value)

        response = self._fetch_endpoint(url)
        if response is not None:
            headers = {str(key): str(value) for key, value in response.headers.items()}
            security_headers = {name: headers.get(name) for name in SECURITY_HEADERS}
            missing_headers = [name for name, value in security_headers.items() if not value]

            report.web = WebEndpointInfo(
                url=url,
                final_url=getattr(response, "url", url),
                status_code=getattr(response, "status_code", None),
                server=headers.get("Server"),
                content_type=headers.get("Content-Type"),
                headers=headers,
                security_headers=security_headers,
                missing_headers=missing_headers,
            )

            if parsed.scheme == "http":
                report.findings.append(
                    AnalysisFinding(
                        category="Transport",
                        severity="medium",
                        detail="The endpoint is using plain HTTP.",
                        recommendation="Redirect all traffic to HTTPS and enable HSTS.",
                    )
                )

            for header_name in missing_headers:
                report.findings.append(
                    AnalysisFinding(
                        category="Security Header",
                        severity="low",
                        detail=f"{header_name} is missing.",
                        recommendation=SECURITY_HEADERS[header_name],
                    )
                )

            if headers.get("Server"):
                report.findings.append(
                    AnalysisFinding(
                        category="Information Disclosure",
                        severity="info",
                        detail=f"Server header is exposed as {headers.get('Server') }.",
                        recommendation="Consider minimizing version disclosure in server headers.",
                    )
                )

        if parsed.scheme == "https" and hostname:
            report.tls = self._inspect_tls(hostname, parsed.port or 443)
            if report.tls and not report.tls.enabled:
                report.findings.append(
                    AnalysisFinding(
                        category="TLS",
                        severity="high",
                        detail="TLS inspection did not complete successfully.",
                        recommendation="Verify the certificate chain and target availability.",
                    )
                )

        report.raw_data = {
            "final_url": getattr(response, "url", url) if response is not None else url,
            "status_code": getattr(response, "status_code", None) if response is not None else None,
        }
        return report

    def _resolve_dns_records(self, name: str, record_type: str) -> List[str]:
        try:
            answers = self.resolver.resolve(name, record_type)
        except Exception as exc:
            logger.debug("DNS resolution failed for %s %s: %s", name, record_type, exc)
            return []

        values: List[str] = []
        for answer in answers:
            value = answer.to_text().strip().strip('"')

            if value and value not in values:
                values.append(value)

        return values

    def _fetch_endpoint(self, url: str) -> Optional[requests.Response]:
        try:
            response = self.session.head(url, allow_redirects=True, timeout=self.timeout)
            if response.status_code == 405 or not response.headers:
                response.close()
                response = self.session.get(url, allow_redirects=True, timeout=self.timeout, stream=True)
            return response
        except requests.RequestException:
            try:
                return self.session.get(url, allow_redirects=True, timeout=self.timeout, stream=True)
            except requests.RequestException as exc:
                logger.debug("HTTP analysis failed for %s: %s", url, exc)
                return None

    def _inspect_tls(self, hostname: str, port: int) -> Optional[TLSCertificateInfo]:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    certificate = secure_sock.getpeercert()

            valid_from = self._parse_tls_datetime(certificate.get("notBefore"))
            valid_to = self._parse_tls_datetime(certificate.get("notAfter"))
            days_remaining = None
            expired = False
            if valid_to is not None:
                delta = valid_to - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                days_remaining = delta.days
                expired = delta.total_seconds() < 0

            sans = [value for _, value in certificate.get("subjectAltName", []) if value]
            subject = self._flatten_tls_name(certificate.get("subject", []))
            issuer = self._flatten_tls_name(certificate.get("issuer", []))

            return TLSCertificateInfo(
                enabled=True,
                subject=subject,
                issuer=issuer,
                valid_from=valid_from,
                valid_to=valid_to,
                days_remaining=days_remaining,
                expired=expired,
                sans=sans,
            )
        except Exception as exc:
            logger.debug("TLS inspection failed for %s:%s: %s", hostname, port, exc)
            return TLSCertificateInfo(enabled=False)

    @staticmethod
    def _flatten_tls_name(name_parts: List[Any]) -> Optional[str]:
        flattened: List[str] = []
        for part in name_parts:
            for key, value in part:
                flattened.append(f"{key}={value}")
        return ", ".join(flattened) if flattened else None

    @staticmethod
    def _parse_tls_datetime(value: Optional[str]) -> Optional[datetime.datetime]:
        if not value:
            return None
        try:
            return datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            return None

    @staticmethod
    def _strip_path(target: str) -> str:
        return target.split("/")[0].strip()

    @staticmethod
    def _normalize_target(target: str) -> str:
        cleaned = target.strip()
        if not cleaned:
            return cleaned

        parsed = urlparse(cleaned)
        if parsed.scheme:
            return cleaned
        if "://" in cleaned:
            return cleaned
        return cleaned

    @staticmethod
    def _normalize_url(url: str) -> str:
        cleaned = url.strip()
        if not cleaned.startswith(("http://", "https://")):
            cleaned = f"https://{cleaned}"
        return cleaned

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False