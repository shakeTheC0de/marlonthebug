"""Base plugin system — abstract base class and finding data structures."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, AsyncIterator

if TYPE_CHECKING:
    from marlonthebug.core.workspace import Workspace

logger = logging.getLogger("marlonthebug.plugins")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    plugin_name: str
    title: str
    description: str
    severity: Severity
    cvss_score: float = 0.0
    cvss_vector: str = ""
    endpoint: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    waf_rules: list[str] = field(default_factory=list)
    target_host: str = ""
    category: str = "web"

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin_name": self.plugin_name,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "waf_rules": self.waf_rules,
            "target_host": self.target_host,
            "category": self.category,
        }


class BasePlugin(ABC):
    name: str = "base"
    version: str = "1.0.0"
    author: str = "MarlonTheBug"
    description: str = ""
    category: str = "general"
    requires_confirmation: bool = False

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self.options = options or {}
        self.logger = logging.getLogger(f"marlonthebug.plugins.{self.category}.{self.name}")

    async def setup(self, workspace: Workspace) -> None:
        pass

    @abstractmethod
    async def run(
        self,
        target: Any,
        options: dict[str, Any] | None = None,
    ) -> AsyncIterator[Finding]:
        if False:
            yield

    async def teardown(self) -> None:
        pass

    def create_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        cvss_score: float = 0.0,
        **kwargs: Any,
    ) -> Finding:
        return Finding(
            plugin_name=self.name,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            category=self.category,
            **kwargs,
        )

    def info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "category": self.category,
            "options": self.options,
        }
