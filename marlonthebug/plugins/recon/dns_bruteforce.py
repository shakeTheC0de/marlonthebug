"""DNS brute force with async resolver and wildcard detection."""

from __future__ import annotations

import logging
import random
import string
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from dns.asyncresolver import resolve as dns_resolve
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers

from marlonthebug.plugins.base import BasePlugin, Finding, Severity

if TYPE_CHECKING:
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins.recon.dns_bruteforce")


class DNSBruteForce(BasePlugin):
    name = "dns_bruteforce"
    version = "1.0.0"
    description = "DNS brute force with wildcard detection and configurable record types"
    category = "recon"

    def __init__(self, options: dict | None = None) -> None:
        super().__init__(options)
        self._workspace: Workspace | None = None
        self._wordlist: list[str] = []
        self._wildcard_ips: set[str] = set()

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace
        self._wildcard_ips.clear()
        self._wordlist = self._load_wordlist()

    def _load_wordlist(self) -> list[str]:
        wordlist_name = self.options.get("wordlist", "small")
        if wordlist_name == "small":
            return [
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
                "mobile",
                "webmail",
                "pop",
                "smtp",
                "ns1",
                "ns2",
                "dns",
                "dns1",
                "monitor",
                "metrics",
                "prometheus",
                "grafana",
                "jenkins",
                "gitlab",
                "registry",
            ]
        return ["www", "mail", "api", "dev", "staging", "admin"]

    async def run(
        self,
        target: TargetInfo,
        options: dict | None = None,
    ) -> AsyncIterator[Finding]:
        domain = target.host
        record_types = self.options.get("record_types", ["A", "AAAA", "CNAME"])

        await self._detect_wildcard(domain)

        for subdomain in self._wordlist:
            full = f"{subdomain}.{domain}"
            if full in getattr(self, "_checked", set()):
                continue
            for rtype in record_types:
                try:
                    answers = await dns_resolve(full, rtype)
                    ips = {str(a) for a in answers}
                    if self._wildcard_ips and ips.issubset(self._wildcard_ips):
                        continue
                    if self._workspace:
                        self._workspace.add_target(full, type="web")
                    yield Finding(
                        plugin_name=self.name,
                        title=f"DNS record found: {full} ({rtype})",
                        description=f"Resolved {full} to {', '.join(ips)} (type {rtype}).",
                        severity=Severity.INFO,
                        cvss_score=0.0,
                        endpoint=full,
                        target_host=domain,
                        category=self.category,
                        evidence={"record_type": rtype, "ips": list(ips), "full_domain": full},
                    )
                    break
                except (NXDOMAIN, NoAnswer, NoNameservers):
                    pass
                except Exception:
                    pass

    async def _detect_wildcard(self, domain: str) -> None:
        random_sub = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        full = f"{random_sub}.{domain}"
        for rtype in ["A", "AAAA"]:
            try:
                answers = await dns_resolve(full, rtype)
                ips = {str(a) for a in answers}
                if ips:
                    self._wildcard_ips.update(ips)
                    logger.info("Wildcard DNS detected for %s: %s", domain, ips)
                    break
            except Exception:
                pass
