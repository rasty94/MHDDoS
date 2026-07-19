import json
import logging
import os
import subprocess
import tempfile
import uuid

from .model import DomainInfo, EmailInfo, OSINTMetadata, OSINTUnifiedResult

logger = logging.getLogger(__name__)

# Free sources that need no API key.
FREE_SOURCES = ("crtsh", "duckduckgo", "bing", "anubis", "hackertarget", "rapiddns", "threatminer")
# Premium sources that require API keys configured in theHarvester's api-keys.yaml.
PREMIUM_SOURCES = ("hunter", "censys", "shodan", "securityTrails", "virustotal", "github-code")


class TheHarvesterAdapter:
    def __init__(self, executable_path: str = "theHarvester"):
        """
        Wrapper for theHarvester.
        Requires theHarvester to be installed and available in PATH or via uv (e.g. 'uv run theHarvester')
        """
        self.executable_path = executable_path.split()

    @staticmethod
    def known_sources() -> dict:
        """Return the catalogue of supported sources split by whether they need an API key."""
        return {"free": list(FREE_SOURCES), "premium": list(PREMIUM_SOURCES)}

    @staticmethod
    def validate_sources(sources: str) -> tuple:
        """Split a comma-separated source list into (supported, needs_api_key) buckets.

        'all' is always considered supported. Helps the UI warn when a premium
        source (Hunter.io, Censys, ...) is requested without configured keys.
        """
        if sources.strip().lower() == "all":
            return (["all"], [])
        requested = [s.strip() for s in sources.split(",") if s.strip()]
        needs_key = [s for s in requested if s in PREMIUM_SOURCES]
        return (requested, needs_key)

    def search_domain(self, domain: str, sources: str = "all", limit: int = 500) -> OSINTUnifiedResult:
        """
        Run theHarvester against a domain and parse the JSON output.
        """
        metadata = OSINTMetadata(
            run_id=str(uuid.uuid4()),
            source="theHarvester",
            query=domain
        )

        result = OSINTUnifiedResult(metadata=metadata)

        # Use a temporary file for JSON output
        fd, temp_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)

        try:
            # Command: theHarvester -d {domain} -b {sources} -l {limit} -f {temp_path}
            cmd = self.executable_path + [
                "-d", domain,
                "-b", sources,
                "-l", str(limit),
                "-f", temp_path
            ]

            logger.info(f"Running theHarvester: {' '.join(cmd)}")
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if process.returncode != 0 and not os.path.exists(temp_path):
                logger.error(f"theHarvester execution failed: {process.stderr}")
                return result

            # theHarvester appends .json to the filename if not present, but since we gave it .json,
            # sometimes it makes it file.json.json or just file.json. Let's find the correct file.
            expected_json_path = temp_path
            if not os.path.exists(expected_json_path) and os.path.exists(temp_path + ".json"):
                expected_json_path = temp_path + ".json"

            if not os.path.exists(expected_json_path):
                logger.error("theHarvester did not produce a JSON output file.")
                return result

            with open(expected_json_path, 'r') as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    logger.error("Failed to parse theHarvester JSON output.")
                    return result

            # Parse interesting data
            # theHarvester JSON structure: { "hosts": ["sub.domain.com:ip"], "emails": ["x@y.com"], "ips": ["1.1.1.1"] }
            domain_info = DomainInfo(name=domain)

            hosts = data.get("hosts", [])
            for h in hosts:
                if ":" in h:
                    sub, ip = h.split(":", 1)
                    if sub not in domain_info.subdomains:
                        domain_info.subdomains.append(sub)
                    if ip and ip not in domain_info.ips:
                        domain_info.ips.append(ip)
                else:
                    if h not in domain_info.subdomains:
                        domain_info.subdomains.append(h)

            emails = data.get("emails", [])
            for e in emails:
                result.emails.append(EmailInfo(address=e, sources=["theHarvester"]))

            ips = data.get("ips", [])
            for ip in ips:
                if ip not in domain_info.ips:
                    domain_info.ips.append(ip)

            result.domains.append(domain_info)
            result.raw_data = data

        except Exception as e:
            logger.error(f"Error running theHarvester wrapper: {e}")
        finally:
            # Cleanup temp files
            if os.path.exists(temp_path):
                os.remove(temp_path)
            if os.path.exists(temp_path + ".json"):
                os.remove(temp_path + ".json")

        return result
