#!/usr/bin/env bash
# Preflight for building MarlonTheBug Live on a Debian/Kali host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ok() { printf '\033[32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[WARN]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[FALTA]\033[0m %s\n' "$*"; }

echo "MarlonTheBug Live — preflight"
echo "==============================="
echo "Sistema: $(uname -s) $(uname -m)"
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  echo "Distro:  ${PRETTY_NAME:-desconocida}"
fi
echo "Kernel:  $(uname -r)"
echo "CPUs:    $(nproc 2>/dev/null || echo '?')"
echo "RAM:     $(awk '/MemTotal/ {printf "%.1f GB", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo '?')"
echo "Disco:"
df -h "$ROOT" | tail -1
echo

if [ "$(uname -s)" = "Linux" ]; then ok "Host Linux"; else fail "El build de ISO requiere Linux; usa el workflow de GitHub Actions"; fi
command -v git >/dev/null 2>&1 && ok "git" || fail "git (sudo apt install git)"
command -v curl >/dev/null 2>&1 && ok "curl" || warn "curl (sudo apt install curl)"
command -v uv >/dev/null 2>&1 && ok "uv" || warn "uv no instalado; se usará python3 -m build"
command -v python3 >/dev/null 2>&1 && ok "python3" || fail "python3"
command -v sudo >/dev/null 2>&1 && ok "sudo" || fail "sudo"
command -v docker >/dev/null 2>&1 && ok "docker" || warn "docker (recomendado para USE_CONTAINER=1)"
command -v live-build >/dev/null 2>&1 && ok "live-build" || warn "live-build (solo necesario para build en host)"
command -v qemu-user-binfmt >/dev/null 2>&1 && ok "qemu-user-binfmt" || warn "qemu-user-binfmt (solo cross-build arm64)"
command -v qemu-system-x86_64 >/dev/null 2>&1 && ok "qemu-system-x86_64 (para probar la ISO)" || warn "qemu-system-x86_64 (recomendado para probar en VM)"

if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    ok "Docker daemon accesible"
  else
    warn "Docker instalado pero el daemon no responde; arranca Docker o usa el grupo docker"
  fi
fi

free_gb=$(df -Pk "$ROOT" | awk 'NR==2 {printf "%d", $4/1024/1024}')
if [ "${free_gb:-0}" -ge 20 ]; then
  ok "Espacio libre: ${free_gb} GB"
else
  warn "Espacio libre: ${free_gb} GB; se recomiendan 20 GB"
fi

echo
echo "Siguiente paso en Debian:"
echo "  ./distro/preflight.sh"
echo "  sudo apt update"
echo "  sudo apt install -y git curl docker.io"
echo "  sudo usermod -aG docker \$USER   # cierra y abre sesión"
echo "  USE_CONTAINER=1 ./distro/build.sh"
echo "  # o, si ya tienes live-build de Kali: ./distro/build.sh"
echo
echo "La ISO queda en distro/output/. Antes de grabarla, pruébala en QEMU/VirtualBox."
