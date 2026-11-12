"""CSRF detection — Cross-Site Request Forgery in forms."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.web.csrf")

CSRF_TOKEN_PATTERNS = [
    "csrf",
    "xsrf",
    "token",
    "nonce",
    "_token",
    "csrf_token",
    "__RequestVerificationToken",
    "authenticity_token",
    "_csrf",
]


class CSIRAuditor(BasePlugin):
    name = "csrf"
    version = "1.0.0"
    description = "Detect missing CSRF protections in forms"
    category = "web"

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        http = AsyncHTTPClient(timeout=10, retries=1)
        try:
            for scheme in ["https", "http"]:
                try:
                    resp = await http.get(f"{scheme}://{target.host}")
                    base_url = f"{scheme}://{target.host}"
                    break
                except Exception:
                    continue
            else:
                return

            soup = BeautifulSoup(resp.body, "lxml")
            forms = soup.find_all("form")
            insecure_forms = 0

            for form in forms:
                action = urljoin(base_url, form.get("action", ""))
                method = form.get("method", "GET").upper()
                if method == "GET":
                    continue

                inputs = form.find_all("input")
                has_csrf = False
                for inp in inputs:
                    name = (inp.get("name", "") or "").lower()
                    if any(pattern in name for pattern in CSRF_TOKEN_PATTERNS):
                        has_csrf = True
                        break

                hidden_fields = [inp.get("name", "") for inp in inputs if inp.get("type", "") == "hidden"]
                has_hidden_unique = any(
                    any(pattern in (h or "").lower() for pattern in CSRF_TOKEN_PATTERNS) for h in hidden_fields
                )

                if not has_csrf and not has_hidden_unique and method != "GET":
                    insecure_forms += 1
                    yield self.create_finding(
                        title="Missing CSRF protection in form",
                        description=f"Form at {action} (method: {method}) does not appear to have CSRF token protection.",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        endpoint=action,
                        target_host=target.host,
                        evidence={"action": action, "method": method, "inputs": [inp.get("name") for inp in inputs]},
                        remediation=(
                            "1. Add unique CSRF tokens to all state-changing forms\n"
                            "2. Use the SameSite cookie attribute (Strict or Lax)\n"
                            "3. Verify the Origin/Referer header on sensitive endpoints\n"
                            "4. Require re-authentication for critical actions\n"
                            "5. Use framework CSRF protection (Django, Rails, etc.)"
                        ),
                    )

            if insecure_forms > 0:
                yield self.create_finding(
                    title=f"{insecure_forms} form(s) without CSRF protection",
                    description=f"Found {insecure_forms} form(s) lacking CSRF token protection on {target.host}.",
                    severity=Severity.MEDIUM,
                    cvss_score=6.5,
                    endpoint=base_url,
                    target_host=target.host,
                    category=self.category,
                    evidence={"insecure_form_count": insecure_forms},
                )
        finally:
            await http.close()
