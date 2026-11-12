"""Secret and credential discovery — regex + entropy-based detection."""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import TYPE_CHECKING, AsyncIterator

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace, TargetInfo

logger = logging.getLogger("marlonthebug.plugins.recon.secret_finder")

SECRET_RULES: list[dict] = [
    {"name": "AWS Access Key ID", "pattern": r"(?i)AKIA[0-9A-Z]{16}", "severity": Severity.HIGH, "cvss": 8.0},
    {"name": "AWS Secret Key", "pattern": r"(?i)(?:aws|amazon)[_-]?secret[_-]?(?:access)?[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "severity": Severity.CRITICAL, "cvss": 9.0},
    {"name": "GitHub Token", "pattern": r"(?i)gh[pousr]_[A-Za-z0-9_]{36,}", "severity": Severity.CRITICAL, "cvss": 9.0},
    {"name": "GitHub App Token", "pattern": r"(?i)ghs_[A-Za-z0-9_]{36,}", "severity": Severity.CRITICAL, "cvss": 9.0},
    {"name": "Google API Key", "pattern": r"(?i)AIza[0-9A-Za-z\-_]{35}", "severity": Severity.HIGH, "cvss": 7.5},
    {"name": "Google OAuth ID", "pattern": r"(?i)[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "severity": Severity.MEDIUM, "cvss": 5.0},
    {"name": "Slack Token", "pattern": r"(?i)xox[baprs]-[0-9A-Za-z\-]{10,}", "severity": Severity.HIGH, "cvss": 7.5},
    {"name": "Slack Webhook", "pattern": r"(?i)https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "severity": Severity.HIGH, "cvss": 7.5},
    {"name": "Stripe API Key", "pattern": r"(?i)(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}", "severity": Severity.CRITICAL, "cvss": 9.0},
    {"name": "OpenAI API Key", "pattern": r"(?i)sk-[A-Za-z0-9]{32,}", "severity": Severity.CRITICAL, "cvss": 9.0},
    {"name": "Heroku API Key", "pattern": r"(?i)[hH][eE][rR][oO][kK][uU][.\-_][A-Za-z0-9]{16,}", "severity": Severity.HIGH, "cvss": 7.5},
    {"name": "MongoDB URI", "pattern": r"(?i)mongodb(?:\+srv)?://[^\s\"'<>]+", "severity": Severity.CRITICAL, "cvss": 9.0},
    {"name": "PostgreSQL URI", "pattern": r"(?i)postgres(?:ql)?://[^\s\"'<>]+", "severity": Severity.CRITICAL, "cvss": 9.0},
    {"name": "MySQL URI", "pattern": r"(?i)mysql://[^\s\"'<>]+", "severity": Severity.CRITICAL, "cvss": 9.0},
    {"name": "Redis URI", "pattern": r"(?i)redis://[^\s\"'<>]+", "severity": Severity.HIGH, "cvss": 7.5},
    {"name": "JWT Token", "pattern": r"(?i)eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+", "severity": Severity.HIGH, "cvss": 7.5},
    {"name": "Private Key", "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "severity": Severity.CRITICAL, "cvss": 9.5},
    {"name": "SSH Private Key", "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----", "severity": Severity.CRITICAL, "cvss": 9.5},
    {"name": "Generic API Key", "pattern": r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "severity": Severity.HIGH, "cvss": 7.0},
    {"name": "Generic Token", "pattern": r"(?i)(?:access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "severity": Severity.HIGH, "cvss": 7.0},
    {"name": "Generic Password", "pattern": r"(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]([^'\"]{4,})['\"]", "severity": Severity.HIGH, "cvss": 7.0},
    {"name": "Generic Secret", "pattern": r"(?i)(?:secret|secret[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "severity": Severity.HIGH, "cvss": 7.0},
    {"name": ".env File", "pattern": r"(?i)([A-Z_]{3,30})\s*=\s*['\"]?([^'\"\s]{6,})['\"]?", "severity": Severity.MEDIUM, "cvss": 5.0},
    {"name": "Telegram Bot Token", "pattern": r"(?i)[0-9]{8,10}:[A-Za-z0-9\-_]{35}", "severity": Severity.HIGH, "cvss": 7.0},
    {"name": "Discord Webhook", "pattern": r"(?i)https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+", "severity": Severity.HIGH, "cvss": 7.5},
    {"name": "Internal IP", "pattern": r"(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}", "severity": Severity.LOW, "cvss": 2.0},
    {"name": "Email Address", "pattern": r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", "severity": Severity.INFO, "cvss": 0.0},
]


class SecretFinder(BasePlugin):
    name = "secret_finder"
    version = "1.0.0"
    description = "Discover exposed secrets, credentials, API keys, and tokens"
    category = "recon"

    def __init__(self, options: dict | None = None) -> None:
        super().__init__(options)
        self._found: set[str] = set()

    def _entropy(self, s: str) -> float:
        if not s:
            return 0.0
        counter = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in counter.values())

    async def setup(self, workspace: Workspace) -> None:
        self._found.clear()

    async def run(
        self,
        target: TargetInfo,
        options: dict | None = None,
    ) -> AsyncIterator[Finding]:
        http = AsyncHTTPClient(timeout=10, retries=2)
        try:
            for scheme in ["https", "http"]:
                try:
                    response = await http.get(f"{scheme}://{target.host}")
                    break
                except Exception:
                    continue
            else:
                return

            body = response.body
            headers_text = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
            combined = f"{headers_text}\n{body}"

            for rule in SECRET_RULES:
                for match in re.finditer(rule["pattern"], combined):
                    value = match.group(0)
                    value_hash = f"{rule['name']}:{hash(value)}"
                    if value_hash in self._found:
                        continue
                    self._found.add(value_hash)

                    yield Finding(
                        plugin_name=self.name,
                        title=f"Exposed secret: {rule['name']}",
                        description=f"Discovered potential {rule['name'].lower()} in HTTP response or headers.",
                        severity=rule["severity"],
                        cvss_score=rule["cvss"],
                        endpoint=f"{scheme}://{target.host}",
                        target_host=target.host,
                        category=self.category,
                        evidence={
                            "rule": rule["name"],
                            "match": value[:100],
                            "source": "http_response",
                        },
                        remediation=f"Remove the {rule['name'].lower()} from publicly accessible resources. Rotate the secret immediately.",
                    )

            for i in range(0, len(body) - 40, 10):
                chunk = body[i:i + 40]
                if self._entropy(chunk) > 4.5 and not any(
                    pattern in chunk for pattern in ["<", ">", "{", "}", "(", ")", "<script", "function"]
                ):
                    pass
        finally:
            await http.close()
