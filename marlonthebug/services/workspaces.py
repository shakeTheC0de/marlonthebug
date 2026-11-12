"""Convert persisted workspaces into the in-memory model used by plugins."""

from __future__ import annotations

from pathlib import Path

from marlonthebug.core.scope import scope_from_workspace
from marlonthebug.core.workspace import TargetInfo, Workspace
from marlonthebug.db.models import TargetModel, WorkspaceModel


def workspace_from_model(model: WorkspaceModel, targets: list[TargetModel] | None = None) -> Workspace:
    scope = scope_from_workspace(
        model.scope or {},
        allow_exploitation=model.allow_exploitation,
        require_confirmation=model.require_confirmation,
    )
    workspace = Workspace(name=model.name, path=Path("."), scope=scope)
    workspace.created_at = model.created_at
    workspace.updated_at = model.updated_at
    for target in targets if targets is not None else model.targets:
        workspace.targets[target.host] = TargetInfo(
            host=target.host,
            type=target.kind,
            technologies=list(target.technologies or []),
            ports=list(target.ports or []),
            metadata=dict(target.metadata_ or {}),
        )
    return workspace


def target_info(target: TargetModel) -> TargetInfo:
    return TargetInfo(
        host=target.host,
        type=target.kind,
        technologies=list(target.technologies or []),
        ports=list(target.ports or []),
        metadata=dict(target.metadata_ or {}),
    )
