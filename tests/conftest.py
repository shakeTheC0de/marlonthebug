"""Test fixtures and configuration."""

from pathlib import Path

import pytest


@pytest.fixture
def data_dir() -> Path:
    return Path("data")


@pytest.fixture
def temp_workspace_dir(tmp_path: Path) -> Path:
    ws_dir = tmp_path / "workspaces"
    ws_dir.mkdir()
    return ws_dir
