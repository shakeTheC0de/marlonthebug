"""Create and restore portable backups of the MarlonTheBug data directory."""

from __future__ import annotations

import json
import shutil
import sqlite3
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from marlonthebug import __version__
from marlonthebug.paths import AppPaths

MAX_ARCHIVE_BYTES = 5 * 1024 * 1024 * 1024
MAX_MEMBERS = 100_000
MANIFEST_NAME = "mtb-backup-manifest.json"


class BackupError(RuntimeError):
    """Raised when a backup cannot be created or restored safely."""


def create_backup(
    paths: AppPaths,
    destination: Path | None = None,
    *,
    include_logs: bool = False,
) -> Path:
    """Package the database, reports, configuration, feeds and panel token.

    The SQLite file is copied through the backup API so the archive is
    consistent even if the panel is running.
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = destination or (Path.cwd() / f"marlonthebug-backup-{timestamp}.tar.gz")
    target = target.expanduser().resolve()
    if target.exists():
        raise BackupError(f"El destino ya existe: {target}")
    if target.suffixes[-2:] != [".tar", ".gz"] and target.suffix != ".tgz":
        raise BackupError("El backup debe terminar en .tar.gz o .tgz")
    target.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="mtb-backup-") as temp:
        staging = Path(temp) / "marlonthebug"
        staging.mkdir()
        file_count = 0
        if paths.db_path.exists():
            _copy_sqlite(paths.db_path, staging / paths.db_path.name)
            file_count += 1
        for name in ("config", "reports", "feeds"):
            source = paths.root / name
            if source.exists():
                shutil.copytree(source, staging / name, dirs_exist_ok=True)
                file_count += _count_files(source)
        if paths.token_path.exists():
            shutil.copy2(paths.token_path, staging / paths.token_path.name)
            file_count += 1
        if include_logs and paths.logs_dir.exists():
            shutil.copytree(paths.logs_dir, staging / "logs", dirs_exist_ok=True)
            file_count += _count_files(paths.logs_dir)

        manifest: dict[str, Any] = {
            "application": "MarlonTheBug",
            "version": __version__,
            "created_at": datetime.now(UTC).isoformat(),
            "include_logs": include_logs,
            "files": file_count,
        }
        (staging / MANIFEST_NAME).write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        with tarfile.open(target, "w:gz") as archive:
            for item in sorted(staging.iterdir()):
                archive.add(item, arcname=item.name, recursive=True)
    return target


def restore_backup(archive_path: Path, paths: AppPaths, *, force: bool = False) -> dict[str, int]:
    """Restore a backup into the configured data directory.

    Existing data is preserved unless ``force`` is true. Archive members are
    validated before extraction to prevent path traversal and link attacks.
    """
    archive_path = archive_path.expanduser().resolve()
    if not archive_path.is_file():
        raise BackupError(f"No existe el archivo: {archive_path}")
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise BackupError("El archivo supera el tamaño máximo admitido")

    with tempfile.TemporaryDirectory(prefix="mtb-restore-") as temp:
        staging = Path(temp) / "restore"
        staging.mkdir()
        try:
            with tarfile.open(archive_path, "r:*") as archive:
                members = archive.getmembers()
                if len(members) > MAX_MEMBERS:
                    raise BackupError("El archivo contiene demasiados elementos")
                for member in members:
                    _validate_member(member)
                archive.extractall(staging, members=members, filter="data")
        except (tarfile.TarError, OSError) as exc:
            raise BackupError(f"Archivo inválido o corrupto: {exc}") from exc

        if not _looks_like_backup(staging):
            raise BackupError("El archivo no parece un backup de MarlonTheBug")
        if not force and _has_existing_data(paths):
            raise BackupError("El directorio de datos ya contiene información. Repite con --force para sobrescribir.")

        paths.ensure()
        restored = 0
        for item in sorted(staging.iterdir()):
            if item.name == MANIFEST_NAME:
                continue
            destination = paths.root / item.name
            if item.is_dir():
                shutil.copytree(item, destination, dirs_exist_ok=True)
                restored += _count_files(item)
            else:
                shutil.copy2(item, destination)
                restored += 1
    return {"files": restored}


def _copy_sqlite(source_path: Path, destination_path: Path) -> None:
    source = sqlite3.connect(str(source_path), timeout=30)
    try:
        destination = sqlite3.connect(str(destination_path))
        try:
            with destination:
                source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()


def _count_files(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return 1
    return sum(1 for item in path.rglob("*") if item.is_file())


def _validate_member(member: tarfile.TarInfo) -> None:
    name = PurePosixPath(member.name)
    if name.is_absolute() or ".." in name.parts:
        raise BackupError(f"Ruta insegura en el backup: {member.name}")
    if member.issym() or member.islnk() or member.isdev():
        raise BackupError(f"Enlace o dispositivo no permitido en el backup: {member.name}")
    if member.size > MAX_ARCHIVE_BYTES:
        raise BackupError(f"Elemento demasiado grande en el backup: {member.name}")


def _looks_like_backup(staging: Path) -> bool:
    return any((staging / name).exists() for name in (MANIFEST_NAME, "marlonthebug.db", "config", "reports", "feeds"))


def _has_existing_data(paths: AppPaths) -> bool:
    return any(
        (paths.root / name).exists() for name in ("marlonthebug.db", "config", "reports", "feeds", "panel.token")
    )
