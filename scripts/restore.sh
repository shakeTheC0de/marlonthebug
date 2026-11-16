#!/usr/bin/env bash
# Restaura un backup creado por scripts/backup.sh.
# Uso: ./scripts/restore.sh backups/marlonthebug-backup-YYYYmmdd-HHMMSS.tar.gz [--force]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ $# -lt 1 ]; then
  echo "Uso: $0 <backup.tar.gz> [--force]" >&2
  exit 1
fi

ARCHIVE="$1"
FORCE="${2:-}"
if [ ! -f "$ARCHIVE" ]; then
  echo "Error: no existe el archivo $ARCHIVE" >&2
  exit 1
fi
ARCHIVE_ABS="$(cd "$(dirname "$ARCHIVE")" && pwd)/$(basename "$ARCHIVE")"

if [ ! -f .env ]; then
  echo "Error: falta .env. Ejecuta primero ./scripts/install.sh" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
. ./.env
set +a

DATA_DIR="${MTB_DATA_DIR:-./mtb-data}"
PANEL_IMAGE="${MTB_PANEL_IMAGE:-ghcr.io/shakethec0de/marlonthebug:latest}"
UID_VALUE="${MTB_UID:-10001}"
GID_VALUE="${MTB_GID:-10001}"

mkdir -p "$DATA_DIR"
DATA_ABS="$(cd "$DATA_DIR" && pwd)"

echo "Deteniendo el panel…"
docker compose stop panel

restore_args=(restore /tmp/restore.tar.gz --data-dir /data --yes)
if [ "$FORCE" = "--force" ]; then
  restore_args+=(--force)
fi

echo "Restaurando ${ARCHIVE}…"
docker run --rm --read-only \
  --tmpfs /tmp:size=256m \
  --user "${UID_VALUE}:${GID_VALUE}" \
  -v "${DATA_ABS}:/data" \
  -v "${ARCHIVE_ABS}:/tmp/restore.tar.gz:ro" \
  --entrypoint marlonthebug \
  "$PANEL_IMAGE" \
  "${restore_args[@]}"

echo "Arrancando el panel…"
docker compose up -d panel

echo "Restauración completada. Revisa: docker compose logs --tail=50 panel"
