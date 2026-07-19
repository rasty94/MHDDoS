import logging
import uuid

import nmap

from utils.osint.model import HostInfo, OSINTMetadata, OSINTUnifiedResult, PortInfo

logger = logging.getLogger(__name__)

class NmapAdapter:
    def __init__(self):
        try:
            self.scanner = nmap.PortScanner()
            self.available = True
        except nmap.PortScannerError:
            self.available = False
            logger.error("Nmap not found in system path.")

    def vuln_scan(self, target: str) -> OSINTUnifiedResult:
        """Service/version scan enriched with the 'vulners' NSE script for CVE detection."""
        return self.scan(target, arguments="-sV -T4 -F --script vulners")

    @staticmethod
    def _extract_vulnerabilities(port_num, port_info: dict) -> list:
        """Pull CVE/vuln identifiers out of NSE script output (e.g. the vulners script)."""
        scripts = port_info.get("script") or {}
        findings = []
        for script_name, output in scripts.items():
            for line in str(output).splitlines():
                stripped = line.strip()
                if "CVE-" in stripped or "EXPLOIT" in stripped.upper():
                    findings.append(f"{port_num}/{script_name}: {stripped}")
        return findings

    def scan(self, target: str, arguments: str = "-sV -T4 -F") -> OSINTUnifiedResult:
        metadata = OSINTMetadata(
            run_id=str(uuid.uuid4()),
            source="nmap",
            query=target
        )

        result = OSINTUnifiedResult(metadata=metadata)

        if not self.available:
            result.raw_data = {"error": "nmap executable not found on the system. Please install nmap."}
            return result

        try:
            scan_data = self.scanner.scan(hosts=target, arguments=arguments)
            result.raw_data = scan_data

            for host, host_data in scan_data.get("scan", {}).items():
                hostnames = [name["name"] for name in host_data.get("hostnames", []) if name.get("name")]
                ports = []
                vulnerabilities = []

                for proto in host_data.get("all_protocols", []):
                    for port_num, port_info in host_data[proto].items():
                        ports.append(PortInfo(
                            port=int(port_num),
                            protocol=proto,
                            service=port_info.get("name"),
                            banner=f"{port_info.get('product', '')} {port_info.get('version', '')}".strip()
                        ))
                        vulnerabilities.extend(self._extract_vulnerabilities(port_num, port_info))

                result.hosts.append(HostInfo(
                    ip=host,
                    hostnames=hostnames,
                    ports=ports,
                    vulnerabilities=vulnerabilities
                ))

        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            result.raw_data = {"error": str(e)}

        return result
