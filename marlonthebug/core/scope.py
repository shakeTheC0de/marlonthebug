"""Scope guard — prevents exploitation of out-of-scope targets."""

import ipaddress
from dataclasses import dataclass, field
from typing import Pattern


@dataclass
class ScopeConfig:
    allowed_domains: list[str] = field(default_factory=list)
    allowed_ip_ranges: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    require_confirmation: bool = True
    allow_exploitation: bool = False

    def __post_init__(self) -> None:
        self._allowed_domain_patterns: list[Pattern[str]] = self._compile_patterns(self.allowed_domains)
        self._excluded_patterns: list[Pattern[str]] = self._compile_patterns(self.excluded)
        self._allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in self.allowed_ip_ranges:
            try:
                self._allowed_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

    @staticmethod
    def _compile_patterns(patterns: list[str]) -> list[Pattern[str]]:
        import re

        result: list[Pattern[str]] = []
        for pattern in patterns:
            regex = "^" + pattern.replace(".", r"\.").replace("*", ".*") + "$"
            result.append(re.compile(regex, re.IGNORECASE))
        return result

    def is_domain_allowed(self, domain: str) -> bool:
        for pattern in self._excluded_patterns:
            if pattern.match(domain):
                return False
        if not self._allowed_domain_patterns:
            return True
        for pattern in self._allowed_domain_patterns:
            if pattern.match(domain):
                return True
        return False

    def is_ip_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if not self._allowed_networks:
            return True
        for network in self._allowed_networks:
            if addr in network:
                return True
        return False

    def is_target_allowed(self, target: str) -> bool:
        target = target.lower().strip()
        try:
            ipaddress.ip_address(target)
            return self.is_ip_allowed(target)
        except ValueError:
            return self.is_domain_allowed(target)


@dataclass
class ScopeGuard:
    config: ScopeConfig

    def check(self, target: str, action: str = "scan") -> bool:
        if not self.config.is_target_allowed(target):
            import logging

            logging.getLogger("marlonthebug").warning(
                "Target %s is out of scope for action %s", target, action
            )
            return False
        return True

    def check_exploitation(self, target: str) -> bool:
        if not self.config.allow_exploitation:
            import logging

            logging.getLogger("marlonthebug").warning(
                "Exploitation is disabled in scope config"
            )
            return False
        return self.check(target, action="exploit")

    def confirm(self, target: str, action: str) -> bool:
        if not self.config.require_confirmation:
            return True
        import sys

        response = input(f"[!] Confirm {action} against {target}? [y/N] ").lower()
        return response in ("y", "yes")
