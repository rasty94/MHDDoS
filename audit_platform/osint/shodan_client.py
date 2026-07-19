import logging
import uuid
from typing import Optional

import shodan

from .model import HostInfo, OSINTMetadata, OSINTUnifiedResult, PortInfo

logger = logging.getLogger(__name__)

class ShodanAdapter:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.api = shodan.Shodan(self.api_key)

    def lookup_ip(self, ip_address: str) -> Optional[HostInfo]:
        """Look up information about a specific IP address."""
        if not self.api_key:
            logger.error("Shodan API key is missing.")
            return None

        try:
            host_data = self.api.host(ip_address)

            ports = []
            for item in host_data.get('data', []):
                ports.append(PortInfo(
                    port=item.get('port'),
                    protocol=item.get('transport', 'tcp'),
                    service=item.get('_shodan', {}).get('module'),
                    banner=item.get('data', '')
                ))

            geo = {
                "country_code": host_data.get('country_code'),
                "country_name": host_data.get('country_name'),
                "city": host_data.get('city'),
                "latitude": host_data.get('latitude'),
                "longitude": host_data.get('longitude')
            }

            vulnerabilities = list(host_data.get('vulns', []))

            host_info = HostInfo(
                ip=ip_address,
                hostnames=host_data.get('hostnames', []),
                ports=ports,
                geo_location=geo,
                organization=host_data.get('org'),
                vulnerabilities=vulnerabilities
            )
            return host_info

        except shodan.APIError as e:
            logger.error(f"Shodan API error for IP {ip_address}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error querying Shodan for {ip_address}: {e}")
            return None

    def search(self, query: str) -> OSINTUnifiedResult:
        """Search Shodan using a query string."""
        metadata = OSINTMetadata(
            run_id=str(uuid.uuid4()),
            source="shodan",
            query=query
        )

        result = OSINTUnifiedResult(metadata=metadata)

        if not self.api_key:
            logger.error("Shodan API key is missing.")
            return result

        try:
            search_results = self.api.search(query, limit=100) # limiting for safety

            # Simple parsing of results
            hosts_dict = {}
            for item in search_results.get('matches', []):
                ip = item.get('ip_str')
                if ip not in hosts_dict:
                    hosts_dict[ip] = HostInfo(
                        ip=ip,
                        hostnames=item.get('hostnames', []),
                        geo_location={"country": item.get('location', {}).get('country_name')},
                        organization=item.get('org'),
                        ports=[]
                    )

                hosts_dict[ip].ports.append(PortInfo(
                    port=item.get('port'),
                    protocol=item.get('transport', 'tcp'),
                    service=item.get('_shodan', {}).get('module'),
                    banner=item.get('data', '')
                ))

            result.hosts = list(hosts_dict.values())
            result.raw_data = {"shodan_search_total": search_results.get('total')}

        except shodan.APIError as e:
            logger.error(f"Shodan API error for query '{query}': {e}")

        return result
