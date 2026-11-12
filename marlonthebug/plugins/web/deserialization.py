"""Insecure Deserialization detection — Python, PHP, Java, .NET."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, AsyncIterator

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace, TargetInfo

logger = logging.getLogger("marlonthebug.plugins.web.deserialization")

DESERIALIZATION_INDICATORS = [
    (r"(?i)java\.io\.ObjectInputStream", "Java"),
    (r"(?i)java\.io\.InvalidClassException", "Java"),
    (r"(?i)cannot deserialize", "Java"),
    (r"(?i)pickle", "Python"),
    (r"(?i)pickle\.loads", "Python"),
    (r"(?i)__pickle", "Python"),
    (r"(?i)unserialize\(\)", "PHP"),
    (r"(?i)__php_incomplete_class", "PHP"),
    (r"(?i)Deserialization of", ".NET"),
    (r"(?i)BinaryFormatter", ".NET"),
    (r"(?i)ruby.*marshal", "Ruby"),
    (r"(?i)YAML\.load", "Ruby/Python"),
    (r"(?i)unsafe YAML", "Ruby/Python"),
    (r"(?i)castor.*unmarshall", "Java"),
    (r"(?i)xstream", "Java"),
]

YSO_PAYLOADS = [
    "rO0AB",  # Java serialized object header (base64)
    "aced0005",  # Java serialized stream magic bytes (hex)
    "Tzo0Oi",  # PHP serialized object "O:4:" (base64)
    "O:4:\"User\"",  # PHP serialized object
    "gASV",  # Python pickle proto 4 (base64)
]


class DeserializationAuditor(BasePlugin):
    name = "deserialization"
    version = "1.0.0"
    description = "Detect insecure deserialization vulnerabilities in Python, PHP, Java, .NET, and Ruby"
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
                if parsed.netloc in (target.host, f"www.{target.host}"):
                    test_urls.add(href)

            test_urls.add(f"{base_url}?data=test")

            for url in list(test_urls)[:10]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                for param_name in list(params.keys())[:5]:
                    for payload_header in YSO_PAYLOADS:
                        test_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                        test_params[param_name] = payload_header
                        query_str = "&".join(f"{k}={v}" for k, v in test_params.items())
                        test_url = parsed._replace(query=query_str).geturl()

                        try:
                            response = await http.get(test_url)
                            for pattern, lang in DESERIALIZATION_INDICATORS:
                                if re.search(pattern, response.body):
                                    yield self.create_finding(
                                        title=f"Insecure Deserialization ({lang}) in '{param_name}'",
                                        description=f"Potential insecure deserialization vulnerability in "
                                                    f"parameter '{param_name}'. {lang} deserialization error exposed.",
                                        severity=Severity.HIGH,
                                        cvss_score=8.5,
                                        endpoint=url,
                                        target_host=target.host,
                                        evidence={"parameter": param_name, "language": lang,
                                                   "error_snippet": response.body[:200]},
                                        remediation=(
                                            "1. Never deserialize untrusted data\n"
                                            "2. Use safe serialization formats (JSON, Protocol Buffers)\n"
                                            "3. Implement strict type checking during deserialization\n"
                                            "4. Use signing/encryption for serialized objects\n"
                                            "5. Keep deserialization libraries updated"
                                        ),
                                    )
                                    break
                        except Exception:
                            pass
        finally:
            await http.close()
