"""WAF Bypass detection — identifies WAF presence and tests evasion techniques."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, AsyncIterator

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.http.waf import WAFFingerprinter
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace, TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.waf_bypass")


class WAFBypassAuditor(BasePlugin):
    name = "waf_bypass"
    version = "1.0.0"
    description = "Detect WAF presence and test common bypass techniques"
    category = "web"

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace

    async def run(self, target: TargetInfo, options: dict | None = None) -> AsyncIterator[Finding]:
        http = AsyncHTTPClient(timeout=10, retries=1)
        waf_fp = WAFFingerprinter()
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

            waf_result = waf_fp.detect(
                resp.status_code,
                resp.headers,
                resp.body,
            )

            if waf_result.detected:
                yield self.create_finding(
                    title=f"WAF detected: {waf_result.name}",
                    description=f"Web Application Firewall ({waf_result.name}) detected on {target.host} "
                                f"with confidence {waf_result.confidence:.0%}. "
                                f"Evidence: {', '.join(waf_result.evidence[:3])}.",
                    severity=Severity.INFO,
                    cvss_score=0.0,
                    endpoint=base_url,
                    target_host=target.host,
                    evidence={
                        "waf_name": waf_result.name,
                        "confidence": waf_result.confidence,
                        "evidence": waf_result.evidence,
                    },
                    remediation="The WAF itself is a security measure. Ensure rules are properly tuned and updated.",
                )

                for bypass_payload in [
                    "/?q=<script>alert(1)</script>",
                    "/?q=1' OR '1'='1",
                    "/?q=../../etc/passwd",
                ]:
                    try:
                        test_url = f"{base_url}{bypass_payload}"
                        test_resp = await http.get(test_url)
                        if test_resp.status_code in (403, 406, 429):
                            yield self.create_finding(
                                title="WAF blocking potential attack payloads",
                                description=f"WAF is actively blocking requests at {test_url}.",
                                severity=Severity.INFO,
                                cvss_score=0.0,
                                endpoint=base_url,
                                target_host=target.host,
                                evidence={"payload": bypass_payload, "status": test_resp.status_code},
                            )
                            break
                    except Exception:
                        pass
        finally:
            await http.close()
