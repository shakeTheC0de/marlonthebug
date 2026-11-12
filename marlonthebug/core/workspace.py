"""Workspace manager for multi-target scoping and session management."""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from marlonthebug.core.scope import ScopeConfig

if TYPE_CHECKING:
    from marlonthebug.core.events import EventBus

logger = logging.getLogger("marlonthebug.workspace")


@dataclass
class TargetInfo:
    host: str
    type: str = "unknown"
    technologies: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class Workspace:
    name: str
    path: Path
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    targets: dict[str, TargetInfo] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_target(self, host: str, target_type: str = "unknown", **kwargs: object) -> TargetInfo:
        host = host.lower().strip()
        if host in self.targets:
            existing = self.targets[host]
            if target_type != "unknown":
                existing.type = target_type
            existing.metadata.update(kwargs)
            self.updated_at = datetime.now(timezone.utc)
            return existing
        target = TargetInfo(host=host, type=target_type, metadata=dict(kwargs))
        self.targets[host] = target
        self.updated_at = datetime.now(timezone.utc)
        return target

    def get_target(self, host: str) -> TargetInfo | None:
        return self.targets.get(host.lower().strip())

    def remove_target(self, host: str) -> bool:
        host = host.lower().strip()
        if host in self.targets:
            del self.targets[host]
            self.updated_at = datetime.now(timezone.utc)
            return True
        return False

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "scope": {
                "allowed_domains": self.scope.allowed_domains,
                "allowed_ip_ranges": self.scope.allowed_ip_ranges,
                "excluded": self.scope.excluded,
                "allow_exploitation": self.scope.allow_exploitation,
                "require_confirmation": self.scope.require_confirmation,
            },
            "targets": {
                host: {
                    "type": t.type,
                    "technologies": t.technologies,
                    "ports": t.ports,
                    "metadata": t.metadata,
                }
                for host, t in self.targets.items()
            },
        }

    def save(self) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        data = self.to_dict()
        (self.path / "workspace.yaml").write_text(yaml.safe_dump(data, default_flow_style=False))
        logger.info("Saved workspace '%s' to %s", self.name, self.path)

    @classmethod
    def load(cls, path: Path) -> "Workspace":
        ws_file = path / "workspace.yaml"
        if not ws_file.exists():
            raise FileNotFoundError(f"Workspace not found at {path}")
        data = yaml.safe_load(ws_file.read_text())
        scope_data = data.get("scope", {})
        scope = ScopeConfig(
            allowed_domains=scope_data.get("allowed_domains", []),
            allowed_ip_ranges=scope_data.get("allowed_ip_ranges", []),
            excluded=scope_data.get("excluded", []),
            allow_exploitation=scope_data.get("allow_exploitation", False),
            require_confirmation=scope_data.get("require_confirmation", True),
        )
        ws = cls(
            name=data["name"],
            path=path,
            scope=scope,
            created_at=datetime.fromisoformat(data["created_at"]),
        )
        for host, tdata in data.get("targets", {}).items():
            ws.targets[host] = TargetInfo(
                host=host,
                type=tdata.get("type", "unknown"),
                technologies=tdata.get("technologies", []),
                ports=tdata.get("ports", []),
                metadata=tdata.get("metadata", {}),
            )
        return ws


class WorkspaceManager:
    def __init__(self, base_dir: Path, event_bus: "EventBus | None" = None) -> None:
        self.base_dir = base_dir
        self.event_bus = event_bus
        self._current: Workspace | None = None
        base_dir.mkdir(parents=True, exist_ok=True)
        self._restore_current()

    def _state_file(self) -> Path:
        return self.base_dir / ".current"

    def _restore_current(self) -> None:
        sf = self._state_file()
        if sf.exists():
            name = sf.read_text().strip()
            ws_path = self.base_dir / name
            if (ws_path / "workspace.yaml").exists():
                try:
                    self._current = Workspace.load(ws_path)
                except Exception:
                    pass

    def _save_current(self) -> None:
        if self._current:
            self._state_file().write_text(self._current.name)

    @property
    def current(self) -> Workspace | None:
        return self._current

    def list_workspaces(self) -> list[str]:
        return [p.name for p in self.base_dir.iterdir() if p.is_dir() and (p / "workspace.yaml").exists()]

    def create(self, name: str, scope: ScopeConfig | None = None) -> Workspace:
        ws_path = self.base_dir / name
        if ws_path.exists():
            raise ValueError(f"Workspace '{name}' already exists")
        ws = Workspace(name=name, path=ws_path, scope=scope or ScopeConfig())
        ws.save()
        self._current = ws
        self._save_current()
        logger.info("Created workspace '%s'", name)
        return ws

    def switch(self, name: str) -> Workspace:
        ws_path = self.base_dir / name
        ws = Workspace.load(ws_path)
        self._current = ws
        self._save_current()
        logger.info("Switched to workspace '%s'", name)
        return ws

    def delete(self, name: str) -> None:
        import shutil

        ws_path = self.base_dir / name
        if ws_path.exists():
            shutil.rmtree(ws_path)
        if self._current and self._current.name == name:
            self._current = None
            self._state_file().unlink(missing_ok=True)
        logger.info("Deleted workspace '%s'", name)

    def add_targets(self, domains: list[str] | None = None, ips: list[str] | None = None) -> None:
        if not self._current:
            raise RuntimeError("No active workspace")
        for domain in (domains or []):
            self._current.scope.allowed_domains.append(domain.lower().strip())
            self._current.add_target(domain.lower().strip(), type="web")
        for ip in (ips or []):
            self._current.scope.allowed_ip_ranges.append(ip.strip())
        self._current.save()

    def add_ip_range(self, cidr: str) -> None:
        if not self._current:
            raise RuntimeError("No active workspace")
        self._current.scope.allowed_ip_ranges.append(cidr.strip())
        self._current.save()
