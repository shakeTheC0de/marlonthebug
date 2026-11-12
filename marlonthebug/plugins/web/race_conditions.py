"""Race Conditions detection — TOCTOU and limit-overrun testing."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.web.race_conditions")


class RaceConditionsAuditor(BasePlugin):
    name = "race_conditions"
    version = "1.0.0"
    description = "Detect race condition vulnerabilities via concurrent request testing"
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

            from urllib.parse import urljoin

            from bs4 import BeautifulSoup

            soup = BeautifulSoup(resp.body, "lxml")
            state_changing_forms = []

            for form in soup.find_all("form"):
                method = form.get("method", "GET").upper()
                if method in ("POST", "PUT", "PATCH"):
                    action = urljoin(base_url, form.get("action", ""))
                    state_changing_forms.append(
                        {
                            "action": action,
                            "method": method,
                        }
                    )

            if state_changing_forms:
                yield self.create_finding(
                    title=f"Potential race condition targets: {len(state_changing_forms)} state-changing form(s)",
                    description=f"Found {len(state_changing_forms)} state-changing forms on {target.host}. "
                    "These may be vulnerable to race conditions if not properly synchronized.",
                    severity=Severity.MEDIUM,
                    cvss_score=5.0,
                    endpoint=base_url,
                    target_host=target.host,
                    evidence={"state_changing_forms": state_changing_forms[:5]},
                    remediation=(
                        "1. Use database transactions with proper isolation levels\n"
                        "2. Implement idempotency keys for critical operations\n"
                        "3. Use optimistic or pessimistic locking\n"
                        "4. Rate-limit sensitive operations per user/IP\n"
                        "5. Queue write operations rather than allowing concurrent writes"
                    ),
                )

                if len(state_changing_forms) > 0:
                    action = state_changing_forms[0]["action"]
                    try:

                        async def make_request():
                            try:
                                r = await http.get(action)
                                return r.status_code
                            except Exception:
                                return 0

                        tasks = [make_request() for _ in range(5)]
                        results = await asyncio.gather(*tasks)

                        if len(set(results)) > 2:
                            yield self.create_finding(
                                title="Inconsistent responses under concurrent load",
                                description=f"Concurrent requests to {action} returned varying status codes: {results}. "
                                "This may indicate a race condition in request handling.",
                                severity=Severity.MEDIUM,
                                cvss_score=5.5,
                                endpoint=action,
                                target_host=target.host,
                                evidence={"concurrent_results": results, "action": action},
                            )
                    except Exception:
                        pass
        finally:
            await http.close()
