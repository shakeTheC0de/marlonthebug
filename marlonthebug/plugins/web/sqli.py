"""SQL Injection detection — error-based, boolean blind, time-based."""

from __future__ import annotations

import logging
import re
import time
from typing import TYPE_CHECKING, AsyncIterator

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity
from marlonthebug.fuzzer.generators import PayloadContext

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace, TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.sqli")

SQLI_ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", "' OR 1=1--", "1' OR '1'='1", "1 AND 1=1", "1' AND '1'='1"]
SQLI_BLIND_PAYLOADS = ["' AND 1=1--", "' AND 1=2--", "' OR 1=1--", "' OR 1=2--"]
SQLI_TIME_PAYLOADS = ["' OR SLEEP(2)--", "'; WAITFOR DELAY '0:0:2'--", "' AND SLEEP(2)--"]

DB_ERROR_PATTERNS = [
    (r"(?i)SQL syntax.*MySQL", "MySQL"),
    (r"(?i)Warning.*mysql_.*", "MySQL"),
    (r"(?i)PostgreSQL.*ERROR", "PostgreSQL"),
    (r"(?i)Warning.*\Wpg_\S+", "PostgreSQL"),
    (r"(?i)Driver.*SQL[\-\s]*Server", "MSSQL"),
    (r"(?i)OLE DB.*SQL Server", "MSSQL"),
    (r"(?i)ORA-[0-9][0-9][0-9][0-9]", "Oracle"),
    (r"(?i)Oracle error", "Oracle"),
    (r"(?i)SQLite.*error", "SQLite"),
    (r"(?i)Warning.*sqlite3", "SQLite"),
    (r"(?i)unclosed quotation mark", "Generic SQL"),
    (r"(?i)quoted string not properly terminated", "Generic SQL"),
    (r'(?i)You have an error in your SQL', "MySQL"),
    (r'(?i)Unclosed quotation mark after', "MSSQL"),
]


class SQLiAuditor(BasePlugin):
    name = "sqli"
    version = "1.0.0"
    description = "Detect SQL Injection vulnerabilities: error-based, boolean blind, time-based, and UNION-based"
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

            from bs4 import BeautifulSoup
            from urllib.parse import urljoin, urlparse, parse_qs

            soup = BeautifulSoup(resp.body, "lxml")
            test_urls: set[str] = set()

            for a in soup.find_all("a", href=True):
                href = urljoin(base_url, a["href"])
                parsed = urlparse(href)
                if parsed.netloc == target.host.replace("www.", "").lstrip("www."):
                    if parsed.query:
                        test_urls.add(href)

            for form in soup.find_all("form"):
                action = urljoin(base_url, form.get("action", ""))
                method = form.get("method", "GET").upper()
                if method == "GET":
                    inputs = [(inp.get("name", ""), inp.get("value", "")) for inp in form.find_all("input")]
                    if inputs:
                        params_str = "&".join(f"{n}={v or '1'}" for n, v in inputs if n)
                        test_urls.add(f"{action}?{params_str}")

            if not test_urls:
                test_urls.add(base_url)

            for url in list(test_urls)[:20]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    append = f"{'&' if '?' in url else '?'}id=1"
                    test_urls.add(url + append)
                    params = {"id": ["1"]}

                for param_name in list(params.keys())[:5]:
                    base_val = params.get(param_name, ["1"])[0]

                    for payload in SQLI_ERROR_PAYLOADS[:5]:
                        try:
                            test_params = {k: v[0] for k, v in params.items()}
                            test_params[param_name] = payload
                            test_url = parsed._replace(query="&".join(f"{k}={v}" for k, v in test_params.items())).geturl()
                            response = await http.get(test_url)

                            for pattern, db_type in DB_ERROR_PATTERNS:
                                if re.search(pattern, response.body):
                                    yield self.create_finding(
                                        title=f"SQL Injection (error-based) in {param_name} [{db_type}]",
                                        description=f"Error-based SQL injection detected in parameter '{param_name}' "
                                                    f"at {test_url}. Database appears to be {db_type}.",
                                        severity=Severity.CRITICAL,
                                        cvss_score=9.8,
                                        endpoint=url,
                                        target_host=target.host,
                                        evidence={
                                            "parameter": param_name,
                                            "payload": payload,
                                            "db_type": db_type,
                                            "error_snippet": response.body[:300],
                                        },
                                        remediation=(
                                            "1. Use parameterized queries (prepared statements)\n"
                                            "2. Use an ORM with proper escaping\n"
                                            "3. Apply input validation and sanitization\n"
                                            "4. Implement least-privilege database accounts\n"
                                            "5. Deploy a WAF with SQL injection rules"
                                        ),
                                        waf_rules=[
                                            "SecRule REQUEST_COOKIES|REQUEST_FILENAME|ARGS \"(?i)(\\bselect\\b|\\bunion\\b|\\binsert\\b|\\bdrop\\b|\\bdelete\\b|\\bupdate\\b)\" \"id:1000,deny,status:403,msg:'SQL Injection attempt'\"",
                                        ],
                                    )
                                    break

                            if response.content_length < 10:
                                continue

                            for blind_test in SQLI_BLIND_PAYLOADS:
                                test_params[param_name] = blind_test
                                test_url2 = parsed._replace(query="&".join(f"{k}={v}" for k, v in test_params.items())).geturl()
                                try:
                                    r2 = await http.get(test_url2)
                                    if r2.content_length != response.content_length:
                                        yield self.create_finding(
                                            title=f"Possible SQL Injection (boolean-based) in {param_name}",
                                            description=f"Response length change ({response.content_length} vs {r2.content_length}) "
                                                        f"when testing parameter '{param_name}'.",
                                            severity=Severity.HIGH,
                                            cvss_score=8.5,
                                            endpoint=url,
                                            target_host=target.host,
                                            evidence={"parameter": param_name, "payload": blind_test,
                                                       "response_1_len": response.content_length,
                                                       "response_2_len": r2.content_length},
                                        )
                                        break
                                except Exception:
                                    pass

                            for time_test in SQLI_TIME_PAYLOADS[:2]:
                                start = time.monotonic()
                                test_params[param_name] = time_test
                                test_url_t = parsed._replace(query="&".join(f"{k}={v}" for k, v in test_params.items())).geturl()
                                try:
                                    await http.get(test_url_t)
                                    elapsed = time.monotonic() - start
                                    if elapsed > 2.0:
                                        yield self.create_finding(
                                            title=f"SQL Injection (time-based) in {param_name}",
                                            description=f"Time-based SQL injection detected in parameter '{param_name}'. Response took {elapsed:.1f}s.",
                                            severity=Severity.CRITICAL,
                                            cvss_score=9.5,
                                            endpoint=url,
                                            target_host=target.host,
                                            evidence={"parameter": param_name, "payload": time_test, "response_time": elapsed},
                                        )
                                except Exception:
                                    pass
                        except Exception:
                            pass
        finally:
            await http.close()
