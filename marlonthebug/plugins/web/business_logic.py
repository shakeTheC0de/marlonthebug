"""Business Logic vulnerability detection — workflow analysis and state manipulation."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, AsyncIterator

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace, TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.business_logic")


class BusinessLogicAuditor(BasePlugin):
    name = "business_logic"
    version = "1.0.0"
    description = "Detect business logic vulnerabilities: workflow bypasses, parameter tampering, and state manipulation"
    category = "web"

    NEGATIVE_PRICE_INPUTS = [
        ("price", "-1"),
        ("amount", "-100"),
        ("quantity", "-999"),
        ("total", "0"),
        ("cost", "0.01"),
    ]

    WORKFLOW_PATTERNS = [
        (r"(?i)(step|stage|page|wizard)\s*=\s*(\d+)", "multi-step workflow"),
        (r"(?i)csrf", "CSRF token"),
        (r"(?i)order_id|invoice_id|transaction_id", "transaction ID"),
        (r"(?i)role|permission|admin", "role-based parameter"),
    ]

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

            body = resp.body
            content_type = resp.headers.get("content-type", "")

            for pattern, label in self.WORKFLOW_PATTERNS:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    yield self.create_finding(
                        title=f"Business logic indicator: {label}",
                        description=f"Found {label} pattern in response from {target.host}. "
                                    "Multi-step workflows may be vulnerable to step-skipping attacks.",
                        severity=Severity.LOW,
                        cvss_score=3.5,
                        endpoint=base_url,
                        target_host=target.host,
                        evidence={"pattern": label, "matches_count": len(matches)},
                        remediation=(
                            "1. Enforce server-side workflow state validation\n"
                            "2. Never trust client-side workflow progression\n"
                            "3. Use server-side state machines for multi-step processes\n"
                            "4. Validate business rules on the server (prices, discounts, quantities)\n"
                            "5. Implement proper access controls for each workflow step"
                        ),
                    )

            from bs4 import BeautifulSoup
            from urllib.parse import urljoin, urlparse, parse_qs

            soup = BeautifulSoup(body, "lxml")
            shop_forms = []

            for form in soup.find_all("form"):
                action = urljoin(base_url, form.get("action", ""))
                inputs = []
                for inp in form.find_all("input"):
                    inputs.append({
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })

                input_names = [i["name"] for i in inputs if i["name"]]
                price_indicators = any(
                    any(pn in name.lower() for pn in ["price", "amount", "total", "cost", "quantity"])
                    for name in input_names
                )

                if price_indicators:
                    shop_forms.append({"action": action, "inputs": input_names})

            if shop_forms:
                for form in shop_forms:
                    yield self.create_finding(
                        title=f"Price/quantity tampering surface found: {form['action']}",
                        description=f"Form at {form['action']} contains price-related fields ({', '.join(form['inputs'][:5])}). "
                                    "These may be vulnerable to parameter tampering.",
                        severity=Severity.MEDIUM,
                        cvss_score=6.0,
                        endpoint=form["action"],
                        target_host=target.host,
                        evidence={"action": form["action"], "inputs": form["inputs"]},
                        remediation=(
                            "1. Never trust client-supplied prices or quantities\n"
                            "2. Validate prices against server-side data (catalog, inventory)\n"
                            "3. Use signed or tamper-proof transaction parameters\n"
                            "4. Log all price modifications for auditing\n"
                            "5. Implement order total verification before processing payment"
                        ),
                    )
        finally:
            await http.close()
