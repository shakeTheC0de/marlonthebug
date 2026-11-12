"""Git leaks detection — .git directory exposure and commit history scanning."""

from __future__ import annotations

import asyncio
import logging
import re
import zlib
from typing import TYPE_CHECKING, AsyncIterator

from marlonthebug.http.client import AsyncHTTPClient
from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace, TargetInfo

logger = logging.getLogger("marlonthebug.plugins.recon.git_leaks")


class GitLeakDetector(BasePlugin):
    name = "git_leaks"
    version = "1.0.0"
    description = "Detect exposed .git directories, extract repository metadata, and scan for secrets in git history"
    category = "recon"

    GIT_PATHS = [
        ".git/HEAD",
        ".git/config",
        ".git/description",
        ".git/index",
        ".git/COMMIT_EDITMSG",
        ".git/logs/HEAD",
        ".git/logs/refs/heads/master",
        ".git/logs/refs/heads/main",
        ".git/refs/heads/master",
        ".git/refs/heads/main",
        ".git/packed-refs",
        ".git/objects/info/packs",
    ]

    SECRET_PATTERNS = [
        (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key", Severity.HIGH, 8.0),
        (r"(?i)gh[pousr]_[A-Za-z0-9_]{36,}", "GitHub Token", Severity.CRITICAL, 9.0),
        (r"(?i)(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}", "Stripe API Key", Severity.CRITICAL, 9.0),
        (r"(?i)-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key", Severity.CRITICAL, 9.5),
        (r"(?i)(?:password|passwd|pwd)\s*=\s*['\"]?([^\s'\"]{4,})['\"]?", "Password in config", Severity.HIGH, 7.5),
        (r"(?i)(?:api[_-]?key|apikey|secret)\s*=\s*['\"]?([^\s'\"]{8,})['\"]?", "API Key in config", Severity.HIGH, 7.5),
        (r"(?i)(?:mongodb|postgres|mysql|redis)://[^\s\"'<>]+", "Database URI", Severity.CRITICAL, 9.0),
    ]

    def __init__(self, options: dict | None = None) -> None:
        super().__init__(options)
        self._http: AsyncHTTPClient | None = None

    async def setup(self, workspace: Workspace) -> None:
        self._http = AsyncHTTPClient(timeout=10, retries=1)

    async def teardown(self) -> None:
        if self._http:
            await self._http.close()
            self._http = None

    async def run(
        self,
        target: TargetInfo,
        options: dict | None = None,
    ) -> AsyncIterator[Finding]:
        if self._http is None:
            return

        exposed = await self._check_git_exposed(target.host)
        if not exposed:
            return

        yield Finding(
            plugin_name=self.name,
            title=f".git directory exposed on {target.host}",
            description=f"The .git directory is publicly accessible on {target.host}, potentially exposing source code and secrets.",
            severity=Severity.CRITICAL,
            cvss_score=9.0,
            endpoint=f"https://{target.host}/.git/",
            target_host=target.host,
            category=self.category,
            remediation="Block access to the .git directory in your web server configuration. Add 'deny all' for the .git location in nginx/Apache. Rotate all exposed secrets immediately.",
            waf_rules=[
                "# nginx: block .git access",
                'location ~ /\\.git { deny all; return 403; }',
                "# Apache: block .git access",
                '<DirectoryMatch "^/.*/\\.git/">',
                "    Require all denied",
                "</DirectoryMatch>",
            ],
        )

        async for finding in self._extract_info(target.host):
            yield finding

        if self.options.get("check_commits", False):
            async for finding in self._scan_objects(target.host):
                yield finding

    async def _check_git_exposed(self, host: str) -> bool:
        if self._http is None:
            return False
        for scheme in ["https", "http"]:
            for path in self.GIT_PATHS[:3]:
                try:
                    response = await self._http.get(f"{scheme}://{host}/{path}")
                    if response.status_code == 200:
                        logger.info(".git exposed on %s (%s)", host, path)
                        return True
                except Exception:
                    pass
        return False

    async def _extract_info(self, host: str) -> AsyncIterator[Finding]:
        git_files = {}
        if self._http is None:
            return

        for path in self.GIT_PATHS:
            for scheme in ["https", "http"]:
                try:
                    response = await self._http.get(f"{scheme}://{host}/{path}")
                    if response.status_code == 200:
                        git_files[path] = response.body
                        break
                except Exception:
                    pass

        if ".git/config" in git_files:
            content = git_files[".git/config"]
            yield Finding(
                plugin_name=self.name,
                title=".git/config exposed",
                description=f"Git repository configuration is exposed. Content:\n{content[:500]}",
                severity=Severity.HIGH,
                cvss_score=8.5,
                endpoint=f"https://{host}/.git/config",
                target_host=host,
                category=self.category,
                evidence={"file": ".git/config", "content": content[:500]},
                remediation="Immediately remove .git/config accessibility. Rotate any exposed credentials.",
            )

            for pattern, name, sev, cvss in self.SECRET_PATTERNS:
                for match in re.finditer(pattern, content):
                    yield Finding(
                        plugin_name=self.name,
                        title=f"{name} in .git/config",
                        description=f"{name} found in exposed git configuration.",
                        severity=sev,
                        cvss_score=cvss,
                        endpoint=f"https://{host}/.git/config",
                        target_host=host,
                        category=self.category,
                        evidence={"file": ".git/config", "match": match.group(0)[:100]},
                        remediation=f"Rotate the {name.lower()} immediately.",
                    )

    async def _scan_objects(self, host: str) -> AsyncIterator[Finding]:
        if self._http is None:
            return
        try:
            response = await self._http.get(f"https://{host}/.git/objects/info/packs")
            if response.status_code != 200:
                return

            pack_files = re.findall(r"pack-([a-f0-9]{40})\.pack", response.body)
            for pack_hash in pack_files[:3]:
                yield Finding(
                    plugin_name=self.name,
                    title=f"Git pack file exposed: pack-{pack_hash[:8]}.pack",
                    description=f"A git pack file is exposed, which may contain full source code history.",
                    severity=Severity.HIGH,
                    cvss_score=8.0,
                    endpoint=f"https://{host}/.git/objects/pack/pack-{pack_hash}.pack",
                    target_host=host,
                    category=self.category,
                    evidence={"pack_file": f"pack-{pack_hash}.pack"},
                )
        except Exception:
            pass
