import json
import logging
import subprocess
import uuid
from typing import Optional

from utils.osint.model import HostInfo, OSINTMetadata, OSINTUnifiedResult

logger = logging.getLogger(__name__)

class WPScanAdapter:
    def __init__(self, api_token: Optional[str] = None):
        self.api_token = api_token

    def scan(self, target_url: str) -> OSINTUnifiedResult:
        metadata = OSINTMetadata(
            run_id=str(uuid.uuid4()),
            source="wpscan",
            query=target_url
        )

        result = OSINTUnifiedResult(metadata=metadata)

        # Build command
        # wpscan --url <target> --format json --no-update
        cmd = ["wpscan", "--url", target_url, "--format", "json", "--no-update", "--disable-tls-checks"]
        if self.api_token:
            cmd.extend(["--api-token", self.api_token])

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            # WPScan sometimes returns non-zero even on successful scans if vulnerabilities are found
            if process.stdout:
                try:
                    data = json.loads(process.stdout)
                    result.raw_data = data

                    # Extract vulnerabilities
                    vulns = []

                    # Core vulns
                    core_vulns = data.get("version", {}).get("vulnerabilities", [])
                    if core_vulns:
                        for v in core_vulns:
                            vulns.append(f"Core: {v.get('title')}")

                    # Plugin vulns
                    plugins = data.get("plugins", {})
                    for plugin_name, plugin_info in plugins.items():
                        for v in plugin_info.get("vulnerabilities", []):
                            vulns.append(f"Plugin ({plugin_name}): {v.get('title')}")

                    # Theme vulns
                    themes = data.get("themes", {})
                    for theme_name, theme_info in themes.items():
                        for v in theme_info.get("vulnerabilities", []):
                            vulns.append(f"Theme ({theme_name}): {v.get('title')}")

                    result.hosts.append(HostInfo(
                        ip=target_url,
                        vulnerabilities=vulns
                    ))

                except json.JSONDecodeError:
                    result.raw_data = {"error": "Failed to parse WPScan JSON output", "stdout": process.stdout}
            else:
                result.raw_data = {"error": "WPScan returned empty output", "stderr": process.stderr}

        except FileNotFoundError:
            result.raw_data = {"error": "wpscan command not found. Ensure ruby wpscan is installed natively or via docker."}
        except subprocess.TimeoutExpired:
            result.raw_data = {"error": "WPScan timed out after 300 seconds."}
        except Exception as e:
            logger.error(f"WPScan execution failed: {e}")
            result.raw_data = {"error": str(e)}

        return result
