"""HaveIBeenPwned (HIBP) breach intelligence.

Checks whether an email account appears in known breaches. The account lookup
requires an HIBP API key (set ``HIBP_API_KEY``); without it the adapter degrades
gracefully and reports that the lookup was skipped rather than failing.
"""

import logging
import os
import time
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
USER_AGENT = "MHcheck-AuditPlatform"


class HIBPAdapter:
    def __init__(self, api_key: Optional[str] = None, session: Optional[requests.Session] = None):
        self.api_key = api_key or os.getenv("HIBP_API_KEY", "")
        self.session = session or requests.Session()

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def check_account(self, email: str, timeout: float = 15.0) -> Dict[str, Any]:
        """Return breach information for an email account."""
        if not self.available:
            return {"email": email, "skipped": True, "reason": "HIBP_API_KEY not configured", "breaches": []}

        headers = {"hibp-api-key": self.api_key, "User-Agent": USER_AGENT}
        url = f"{HIBP_BASE}/breachedaccount/{email}"
        try:
            resp = self.session.get(url, headers=headers, params={"truncateResponse": "false"}, timeout=timeout)
        except requests.RequestException as exc:
            logger.error("HIBP request failed for %s: %s", email, exc)
            return {"email": email, "error": str(exc), "breaches": []}

        if resp.status_code == 404:
            return {"email": email, "breached": False, "breaches": []}
        if resp.status_code == 429:
            retry = resp.headers.get("Retry-After", "?")
            return {"email": email, "error": f"rate limited (retry after {retry}s)", "breaches": []}
        if resp.status_code != 200:
            return {"email": email, "error": f"HTTP {resp.status_code}", "breaches": []}

        breaches = resp.json()
        return {
            "email": email,
            "breached": True,
            "breach_count": len(breaches),
            "breaches": [
                {"name": b.get("Name"), "domain": b.get("Domain"), "date": b.get("BreachDate"), "data": b.get("DataClasses", [])}
                for b in breaches
            ],
        }

    def check_accounts(self, emails: List[str], rate_limit_seconds: float = 1.6) -> List[Dict[str, Any]]:
        """Check several accounts, respecting HIBP's rate limit between calls."""
        results = []
        for i, email in enumerate(emails):
            results.append(self.check_account(email))
            if self.available and i < len(emails) - 1:
                time.sleep(rate_limit_seconds)
        return results
