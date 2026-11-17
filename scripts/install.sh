#!/usr/bin/env bash
# Instalación de MarlonTheBug con Docker Compose.
# Uso: ./scripts/install.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: Docker no está instalado o no está en PATH." >&2
  echo "Instala Docker Engine: https://docs.docker.com/engine/install/" >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Error: falta el plugin 'docker compose' (Docker Compose v2)." >&2
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Creado .env a partir de .env.example"
fi

# Ajusta UID/GID al usuario del host en Linux para que ./mtb-data sea escribible.
if [ "$(uname -s)" = "Linux" ]; then
  sed -i.bak "s/^MTB_UID=.*/MTB_UID=$(id -u)/" .env
  sed -i.bak "s/^MTB_GID=.*/MTB_GID=$(id -g)/" .env
  rm -f .env.bak
fi

generate_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import secrets; print(secrets.token_hex(32))'
  else
    echo "Error: necesitas openssl o python3 para generar tokens." >&2
    exit 1
  fi
}

ensure_token() {
  local key="$1"
  local existing
  existing="$(grep -E "^${key}=" .env | cut -d= -f2- || true)"
  if [ -z "${existing}" ]; then
    local token
    token="$(generate_token)"
    sed -i.bak "s/^${key}=.*/${key}=${token}/" .env
    rm -f .env.bak
    echo "Token ${key} generado."
  fi
}

ensure_token MTB_TOOLS_TOKEN
ensure_token MTB_EXPLOIT_TOKEN
chmod 600 .env

set -a
# shellcheck disable=SC1091
. ./.env
set +a

DATA_DIR="${MTB_DATA_DIR:-./mtb-data}"
PANEL_PORT="${MTB_PANEL_PORT:-8765}"
mkdir -p "$DATA_DIR"
if [ "$(uname -s)" = "Linux" ]; then
  chown -R "$(id -u):$(id -g)" "$DATA_DIR" 2>/dev/null || true
fi

echo "Descargando imágenes (si están publicadas) o construyendo localmente…"
if ! docker compose pull panel tools-runner exploit-runner 2>/dev/null; then
  echo "No se pudieron descargar las imágenes; construyendo desde el código…"
  docker compose build
fi

docker compose up -d

echo "Esperando a que el panel esté listo…"
ready=0
for _ in $(seq 1 90); do
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS "http://127.0.0.1:${PANEL_PORT}/healthz" >/dev/null 2>&1; then
      ready=1
      break
    fi
  elif docker compose exec -T panel python -c \
    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${PANEL_PORT}/healthz', timeout=3)" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done

if [ "$ready" -ne 1 ]; then
  echo "El panel no respondió. Revisa: docker compose logs --tail=80 panel" >&2
  exit 1
fi

token="$(cat "${DATA_DIR}/panel.token" 2>/dev/null | tr -d '\r\n' || true)"
if [ -z "$token" ]; then
  token="$(docker compose exec -T panel cat /data/panel.token 2>/dev/null | tr -d '\r\n' || true)"
fi

echo
echo "MarlonTheBug está listo."
echo "Panel:  http://127.0.0.1:${PANEL_PORT}/"
if [ -n "$token" ]; then
  echo "Acceso: http://127.0.0.1:${PANEL_PORT}/?token=${token}"
fi
echo "Datos:  ${DATA_DIR}"
echo "Logs:   docker compose logs -f panel"
echo "Backup: ./scripts/backup.sh"
