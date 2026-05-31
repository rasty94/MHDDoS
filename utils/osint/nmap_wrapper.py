import nmap
import uuid
import logging
from typing import Optional
from utils.osint.model import OSINTUnifiedResult, OSINTMetadata, HostInfo, PortInfo

logger = logging.getLogger(__name__)

class NmapAdapter:
    def __init__(self):
        try:
            self.scanner = nmap.PortScanner()
            self.available = True
        except nmap.PortScannerError:
            self.available = False
            logger.error("Nmap not found in system path.")

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
                
                for proto in host_data.get("all_protocols", []):
                    for port_num, port_info in host_data[proto].items():
                        ports.append(PortInfo(
                            port=int(port_num),
                            protocol=proto,
                            service=port_info.get("name"),
                            banner=f"{port_info.get('product', '')} {port_info.get('version', '')}".strip()
                        ))
                        
                result.hosts.append(HostInfo(
                    ip=host,
                    hostnames=hostnames,
                    ports=ports
                ))
                
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            result.raw_data = {"error": str(e)}

        return result
