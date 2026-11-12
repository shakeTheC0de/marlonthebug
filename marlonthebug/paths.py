"""Portable filesystem layout for MarlonTheBug.

All runtime data (database, reports, logs, cached feeds and the panel token)
lives outside the source tree by default.  ``--portable`` keeps everything in a
``data/`` directory next to the executable, which makes a USB stick deployment
possible on macOS, Linux and Windows.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_config_dir, user_data_dir

APP_NAME = "MarlonTheBug"
APP_AUTHOR = "MarlonTheBug"


@dataclass(frozen=True, slots=True)
class AppPaths:
    """Resolved directories used by the application."""

    root: Path
    config_dir: Path
    reports_dir: Path
    logs_dir: Path
    cache_dir: Path
    feeds_dir: Path
    db_path: Path
    token_path: Path
    portable: bool = False

    @classmethod
    def resolve(
        cls,
        data_dir: str | Path | None = None,
        portable: bool = False,
    ) -> AppPaths:
        env_dir = os.environ.get("MARLONTHEBUG_DATA_DIR")
        if data_dir:
            root = Path(data_dir).expanduser().resolve()
        elif env_dir:
            root = Path(env_dir).expanduser().resolve()
        elif portable:
            if getattr(sys, "frozen", False):
                root = Path(sys.executable).resolve().parent / "data"
            else:
                root = Path.cwd().resolve() / "data"
        else:
            root = Path(user_data_dir(APP_NAME, APP_AUTHOR)).expanduser().resolve()

        config_dir = (
            root / "config"
            if (portable or data_dir or env_dir)
            else Path(user_config_dir(APP_NAME, APP_AUTHOR)).expanduser().resolve()
        )
        return cls(
            root=root,
            config_dir=config_dir,
            reports_dir=root / "reports",
            logs_dir=root / "logs",
            cache_dir=root / "cache",
            feeds_dir=root / "feeds",
            db_path=root / "marlonthebug.db",
            token_path=root / "panel.token",
            portable=portable or bool(data_dir) or bool(env_dir),
        )

    def ensure(self) -> None:
        for directory in (
            self.root,
            self.config_dir,
            self.reports_dir,
            self.logs_dir,
            self.cache_dir,
            self.feeds_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.yaml"


def package_dir() -> Path:
    """Return the installed package directory (works with PyInstaller)."""
    return Path(__file__).resolve().parent


def resource_path(*parts: str) -> Path:
    """Locate a bundled resource both in development and in frozen builds."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        candidate = Path(base) / "marlonthebug" / Path(*parts)
        if candidate.exists():
            return candidate
        return Path(base) / Path(*parts)
    return package_dir().joinpath(*parts)
