"""RCE detection — Remote Code Execution via known vulnerabilities."""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.web.rce")

RCE_INDICATORS = [
    (r"(?i)org\.apache\.struts2", "Apache Struts"),
    (r"(?i)ognl\.NoSuchPropertyException", "OGNL Injection"),
    (r"(?i)ognl\.MethodFailedException", "OGNL Injection"),
    (r"(?i)ExpressionException", "Expression Language (EL)"),
    (r"(?i)javax\.el\.ELException", "Java EL Injection"),
    (r"(?i)freemarker\.core", "Freemarker"),
    (r"(?i)org\.springframework\.expression", "Spring Expression Language"),
    (r"(?i)SpelEvaluationException", "SpEL Injection"),
    (r"(?i)syntax error.*unexpected.*token", "Code Injection"),
    (r"(?i)parse error.*unexpected", "PHP Code Injection"),
    (r"(?i)eval\(\)", "eval() Injection"),
    (r"(?i)assert\(\)", "PHP assert()"),
    (r"(?i)preg_replace.*\/e", "PHP preg_replace /e"),
    (r"(?i)create_function", "PHP create_function"),
]

RCE_TEST_ENDPOINTS = [
    "/cgi-bin/",
    "/cgi-bin/status",
    "/cgi-bin/test.cgi",
    "/invoker/JMXInvokerServlet",
    "/invoker/EJBInvokerServlet",
    "/jmx-console/",
    "/web-console/",
    "/admin-console/",
    "/struts/",
    "/struts2/",
    ".action",
    ".do",
    "/api/v1/execute",
    "/api/v1/run",
    "/wp-admin/admin-ajax.php",
]


class RCEAuditor(BasePlugin):
    name = "rce"
    version = "1.0.0"
    description = "Detect Remote Code Execution (RCE) vulnerabilities via known CVEs and framework endpoints"
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

            headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            combined = headers_text + "\n" + resp.body

            for pattern, vuln_name in RCE_INDICATORS:
                if re.search(pattern, combined):
                    yield self.create_finding(
                        title=f"Potential RCE ({vuln_name})",
                        description=f"Response contains indicators of {vuln_name}, which may indicate an exploitable RCE vulnerability.",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        endpoint=base_url,
                        target_host=target.host,
                        evidence={"vulnerability": vuln_name, "pattern": pattern},
                        remediation=(
                            "1. Update the affected framework/library to the latest version\n"
                            "2. Apply vendor security patches immediately\n"
                            "3. Implement WAF rules for known attack patterns\n"
                            "4. Disable unnecessary endpoints and features\n"
                            "5. Use runtime application self-protection (RASP)"
                        ),
                    )

            for endpoint in RCE_TEST_ENDPOINTS[:8]:
                url = f"{base_url}{endpoint}"
                try:
                    ep_resp = await http.get(url)
                    if ep_resp.status_code not in (404, 400):
                        for pattern, vuln_name in RCE_INDICATORS:
                            if re.search(pattern, ep_resp.body):
                                yield self.create_finding(
                                    title=f"RCE endpoint exposed: {endpoint}",
                                    description=f"Endpoint {endpoint} on {target.host} may be vulnerable to {vuln_name}.",
                                    severity=Severity.CRITICAL,
                                    cvss_score=9.5,
                                    endpoint=url,
                                    target_host=target.host,
                                    evidence={
                                        "endpoint": endpoint,
                                        "vulnerability": vuln_name,
                                        "status": ep_resp.status_code,
                                    },
                                )
                except Exception:
                    pass
        finally:
            await http.close()
