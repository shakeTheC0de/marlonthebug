#!/usr/bin/env bash
# Crea un backup consistente de mtb-data sin detener el panel.
# Uso: ./scripts/backup.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -f .env ]; then
  echo "Error: falta .env. Ejecuta primero ./scripts/install.sh" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
. ./.env
set +a

DATA_DIR="${MTB_DATA_DIR:-./mtb-data}"
KEEP="${MTB_BACKUP_KEEP:-14}"
STAMP="$(date +%Y%m%d-%H%M%S)"
NAME="marlonthebug-backup-${STAMP}.tar.gz"

mkdir -p "${DATA_DIR}/backups"

# La copia de SQLite se hace con la API de backup dentro del contenedor, de
# modo que el archivo es consistente aunque el panel esté escribiendo.
docker compose run --rm --no-deps \
  --name "mtb-backup-${STAMP}" \
  --entrypoint marlonthebug \
  panel backup --data-dir /data --output "/data/backups/${NAME}"

BACKUP_PATH="${DATA_DIR}/backups/${NAME}"
echo "Backup creado: ${BACKUP_PATH}"

# Retención local de los últimos N backups.
if [ "$KEEP" -gt 0 ]; then
  ls -1t "${DATA_DIR}"/backups/marlonthebug-backup-*.tar.gz 2>/dev/null \
    | tail -n +"$((KEEP + 1))" \
    | while IFS= read -r old; do
        rm -f "$old"
      done
fi

echo "Copia este archivo fuera del equipo y protégelo: contiene el token del panel."
