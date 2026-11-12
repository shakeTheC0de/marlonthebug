"""Base plugin system — finding model, severity/confidence and plugin contract."""

from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from marlonthebug.core.context import ScanContext
    from marlonthebug.core.workspace import TargetInfo, Workspace

logger = logging.getLogger("marlonthebug.plugins")


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    plugin_name: str
    title: str
    description: str
    severity: Severity
    cvss_score: float = 0.0
    cvss_vector: str = ""
    confidence: Confidence = Confidence.MEDIUM
    cwe: str = ""
    owasp: str = ""
    endpoint: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    waf_rules: list[str] = field(default_factory=list)
    target_host: str = ""
    target_id: str = ""
    scan_id: str = ""
    category: str = "web"
    status: str = "open"
    notes: str = ""
    verified: bool = False
    intel: dict[str, Any] = field(default_factory=dict)
    kev: bool = False
    epss: float = 0.0

    @property
    def fingerprint(self) -> str:
        parameter = str(self.evidence.get("parameter", ""))
        normalized = "|".join(
            part.strip().lower() for part in (self.plugin_name, self.title, self.endpoint, self.target_host, parameter)
        )
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin_name": self.plugin_name,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "confidence": self.confidence.value,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "waf_rules": self.waf_rules,
            "target_host": self.target_host,
            "target_id": self.target_id,
            "scan_id": self.scan_id,
            "category": self.category,
            "status": self.status,
            "notes": self.notes,
            "verified": self.verified,
            "intel": self.intel,
            "kev": self.kev,
            "epss": self.epss,
            "fingerprint": self.fingerprint,
        }


class BasePlugin(ABC):
    name: str = "base"
    version: str = "2.0.0"
    author: str = "MarlonTheBug"
    description: str = ""
    category: str = "general"
    requires_confirmation: bool = False
    beta: bool = False

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self.options = options or {}
        self.logger = logging.getLogger(f"marlonthebug.plugins.{self.category}.{self.name}")
        self._context: ScanContext | None = None

    @property
    def context(self) -> ScanContext | None:
        return self._context

    async def setup(self, workspace: Workspace) -> None:
        self._workspace = workspace

    @abstractmethod
    async def run(
        self,
        target: TargetInfo,
        options: dict[str, Any] | None = None,
    ) -> AsyncIterator[Finding]:
        if False:  # type: ignore[unreachable]
            yield  # type: ignore[unreachable]

    async def teardown(self) -> None:  # noqa: B027
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
            "beta": self.beta,
            "options": self.options,
        }
