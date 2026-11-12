"""Scope guard — every outbound request must pass through here."""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger("marlonthebug.scope")


class ScopeViolation(RuntimeError):  # noqa: N818
    """Raised when a URL or host is outside the authorized scope."""


def _compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        value = pattern.strip().lower()
        if not value:
            continue
        escaped = re.escape(value).replace(r"\*", ".*")
        compiled.append(re.compile(rf"^{escaped}$", re.IGNORECASE))
    return compiled


@dataclass
class ScopeConfig:
    allowed_domains: list[str] = field(default_factory=list)
    allowed_ip_ranges: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    require_confirmation: bool = True
    allow_exploitation: bool = False

    def __post_init__(self) -> None:
        self._allowed_domain_patterns = _compile_patterns(self.allowed_domains)
        self._excluded_patterns = _compile_patterns(self.excluded)
        self._allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in self.allowed_ip_ranges:
            try:
                self._allowed_networks.append(ipaddress.ip_network(cidr.strip(), strict=False))
            except ValueError:
                logger.warning("Invalid IP range in scope: %s", cidr)

    @property
    def is_empty(self) -> bool:
        return not self.allowed_domains and not self.allowed_ip_ranges

    def is_domain_allowed(self, domain: str) -> bool:
        domain = domain.strip().lower().rstrip(".")
        if any(pattern.match(domain) for pattern in self._excluded_patterns):
            return False
        # Fail closed: an empty scope does not authorize anything implicitly.
        return any(pattern.match(domain) for pattern in self._allowed_domain_patterns)

    def is_ip_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if any(pattern.match(str(addr)) for pattern in self._excluded_patterns):
            return False
        return any(addr in network for network in self._allowed_networks)

    def is_target_allowed(self, target: str) -> bool:
        target = target.strip().lower().rstrip(".")
        try:
            ipaddress.ip_address(target)
            return self.is_ip_allowed(target)
        except ValueError:
            return self.is_domain_allowed(target)

    def is_url_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().strip(".")
        if not host:
            return False
        try:
            ipaddress.ip_address(host)
            return self.is_ip_allowed(host)
        except ValueError:
            return self.is_domain_allowed(host)

    def explain(self) -> dict[str, list[str]]:
        return {
            "allowed_domains": list(self.allowed_domains),
            "allowed_ip_ranges": list(self.allowed_ip_ranges),
            "excluded": list(self.excluded),
        }


@dataclass
class ScopeGuard:
    config: ScopeConfig

    def check(self, target: str, action: str = "scan") -> bool:
        allowed = self.config.is_target_allowed(target)
        if not allowed:
            logger.warning("Out-of-scope target blocked: %s (%s)", target, action)
        return allowed

    def check_url(self, url: str, action: str = "scan") -> bool:
        allowed = self.config.is_url_allowed(url)
        if not allowed:
            logger.warning("Out-of-scope URL blocked: %s (%s)", url, action)
        return allowed

    def require(self, url: str, action: str = "scan") -> None:
        if not self.check_url(url, action):
            raise ScopeViolation(f"Target out of scope: {url}")

    def check_exploitation(self, target: str) -> bool:
        if not self.config.allow_exploitation:
            logger.warning("Exploitation is disabled in the workspace scope")
            return False
        return self.check(target, action="exploit")

    def confirm(self, target: str, action: str) -> bool:
        if not self.config.require_confirmation:
            return True
        response = input(f"[!] Confirm {action} against {target}? [y/N] ").lower()
        return response in ("y", "yes")


def scope_from_workspace(scope: dict, allow_exploitation: bool, require_confirmation: bool) -> ScopeConfig:
    domains = list(scope.get("allowed_domains", []))
    ranges = list(scope.get("allowed_ip_ranges", []))
    return ScopeConfig(
        allowed_domains=domains,
        allowed_ip_ranges=ranges,
        excluded=list(scope.get("excluded", [])),
        allow_exploitation=allow_exploitation,
        require_confirmation=require_confirmation,
    )
