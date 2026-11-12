"""Subdomain enumeration — Certificate Transparency, passive DNS, brute force."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

import httpx
from dns.asyncresolver import resolve as dns_resolve
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers

from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.recon.subdomain_enum")


class SubdomainEnumerator(BasePlugin):
    name = "subdomain_enum"
    version = "1.0.0"
    description = "Enumerate subdomains via Certificate Transparency, passive DNS, and brute force"
    category = "recon"

    CRT_SH_URL = "https://crt.sh/?q=%25.{}&output=json"

    def __init__(self, options: dict | None = None) -> None:
        super().__init__(options)
        self._found: set[str] = set()
        self._workspace: Workspace | None = None
        self._wordlist: list[str] = []

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace
        self._found.clear()

        wordlist_name = self.options.get("wordlist", "small")
        if wordlist_name == "small":
            self._wordlist = [
                "www",
                "mail",
                "ftp",
                "api",
                "dev",
                "staging",
                "admin",
                "blog",
                "shop",
                "vpn",
                "remote",
                "portal",
                "cdn",
                "m",
                "app",
                "docs",
                "status",
                "test",
                "demo",
                "auth",
                "sso",
                "secure",
                "support",
                "help",
                "wiki",
            ]
        else:
            self._wordlist = self._load_wordlist()

    def _load_wordlist(self) -> list[str]:
        try:
            path = self.options.get("wordlist_path")
            if path:
                import os

                if os.path.exists(path):
                    with open(path) as f:
                        return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception:
            pass
        return ["www", "mail", "api", "dev", "staging", "admin"]

    async def run(
        self,
        target: TargetInfo,
        options: dict | None = None,
    ) -> AsyncIterator[Finding]:
        domain = target.host

        async for sub in self._certificate_transparency(domain):
            yield sub

        async for sub in self._dns_brute_force(domain):
            yield sub

    async def _certificate_transparency(self, domain: str) -> AsyncIterator[Finding]:
        logger.info("CT enumeration for %s", domain)
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(self.CRT_SH_URL.format(domain))
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name = entry.get("name_value", "").lower()
                        for raw_sub in name.split("\n"):
                            sub = raw_sub.strip().lstrip("*.")
                            if sub.endswith(f".{domain}") and sub not in self._found:
                                if self._context and not self._context.scope.is_domain_allowed(sub):
                                    continue
                                self._found.add(sub)
                                if self._context:
                                    self._context.discovered_hosts.add(sub)
                                if self._workspace:
                                    self._workspace.add_target(sub, type="web")
                                yield Finding(
                                    plugin_name=self.name,
                                    title=f"Subdomain discovered via CT: {sub}",
                                    description=f"Subdomain {sub} discovered through Certificate Transparency logs.",
                                    severity=Severity.INFO,
                                    cvss_score=0.0,
                                    endpoint=sub,
                                    target_host=domain,
                                    category=self.category,
                                    evidence={"source": "certificate_transparency", "domain": sub},
                                )
        except Exception as e:
            logger.warning("CT enumeration failed for %s: %s", domain, e)

    async def _dns_brute_force(self, domain: str) -> AsyncIterator[Finding]:
        logger.info("DNS brute force for %s with %d names", domain, len(self._wordlist))

        async def check(sub: str) -> str | None:
            full = f"{sub}.{domain}"
            if full in self._found:
                return None
            if self._context and not self._context.scope.is_domain_allowed(full):
                return None
            try:
                answers = await dns_resolve(full, "A")
                if answers:
                    self._found.add(full)
                    if self._context:
                        self._context.discovered_hosts.add(full)
                    return full
            except (NXDOMAIN, NoAnswer, NoNameservers):
                pass
            except Exception:
                pass
            return None

        tasks = [check(sub) for sub in self._wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, str):
                if self._workspace:
                    self._workspace.add_target(result, type="web")
                yield Finding(
                    plugin_name=self.name,
                    title=f"Subdomain discovered via DNS: {result}",
                    description=f"Subdomain {result} discovered through DNS brute force.",
                    severity=Severity.INFO,
                    cvss_score=0.0,
                    endpoint=result,
                    target_host=domain,
                    category=self.category,
                    evidence={"source": "dns_bruteforce", "domain": result},
                )
