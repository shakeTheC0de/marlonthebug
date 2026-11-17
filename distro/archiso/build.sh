#!/usr/bin/env bash
# Build the MarlonTheBug Arch Linux live images with archiso.
#
# Two independent profiles are produced:
#   privacy : Xfce, Tor-only, amnesic, no offensive tooling.
#   audit   : Xfce + KDE, direct network, panel and auditing tools.
#
# Recommended hosts:
#   - Arch Linux with `archiso` installed (fastest and easiest to learn).
#   - Any Linux with Docker/podman (the script runs an Arch container).
#   - GitHub Actions (.github/workflows/arch-iso.yml).
#
# macOS cannot build a reliable live ISO. Use the container engine or CI.
set -euo pipefail

ARCHISO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$ARCHISO_DIR/../.." && pwd)"
WORK_DIR="${WORK_DIR:-$ARCHISO_DIR/.build}"
OUT_DIR="${OUT_DIR:-$ARCHISO_DIR/out}"
CACHE_DIR="${CACHE_DIR:-$ARCHISO_DIR/cache}"
PROFILE_KIND="${PROFILE_KIND:-all}"
ENGINE="${ENGINE:-auto}"
TOR_BROWSER_VERSION="${TOR_BROWSER_VERSION:-16.0.1}"
TOR_BROWSER_SHA256="${TOR_BROWSER_SHA256:-5b36ad610c20c81faa72caf27d1cd3a11f14a327c320b4cec581400016ba78b0}"
TOR_BROWSER_URL="https://dist.torproject.org/torbrowser/${TOR_BROWSER_VERSION}/tor-browser-linux-x86_64-${TOR_BROWSER_VERSION}.tar.xz"

usage() {
  cat <<'EOF'
Uso: ./distro/archiso/build.sh [opciones]

Opciones:
  --profile privacy|audit|all   Perfil a construir (por defecto: all)
  --engine auto|host|docker|podman
                                Motor de build (por defecto: auto)
  --out DIR                     Directorio de salida (por defecto: distro/archiso/out)
  --work DIR                    Directorio de trabajo (por defecto: distro/archiso/.build)
  --cache DIR                   Directorio de caché (por defecto: distro/archiso/cache)
  --clean                       Borra work/out/cache antes de construir
  -h, --help                    Muestra esta ayuda

Variables:
  TOR_BROWSER_VERSION, TOR_BROWSER_SHA256
  HOST_UID, HOST_GID            Solo para el contenedor; ajusta los artefactos.

Ejemplos:
  ./distro/archiso/build.sh --profile all
  ./distro/archiso/build.sh --profile privacy --engine docker
  ./distro/archiso/build.sh --profile audit --engine host
EOF
}

CLEAN=0
while (($#)); do
  case "$1" in
    --profile)
      PROFILE_KIND="${2:?falta el valor de --profile}"
      shift 2
      ;;
    --engine)
      ENGINE="${2:?falta el valor de --engine}"
      shift 2
      ;;
    --out)
      OUT_DIR="${2:?falta el valor de --out}"
      shift 2
      ;;
    --work)
      WORK_DIR="${2:?falta el valor de --work}"
      shift 2
      ;;
    --cache)
      CACHE_DIR="${2:?falta el valor de --cache}"
      shift 2
      ;;
    --clean)
      CLEAN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: opción desconocida: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$PROFILE_KIND" in
  privacy|audit|all) ;;
  *)
    echo "ERROR: --profile debe ser privacy, audit o all." >&2
    exit 2
    ;;
esac

case "$ENGINE" in
  auto|host|docker|podman) ;;
  *)
    echo "ERROR: --engine debe ser auto, host, docker o podman." >&2
    exit 2
    ;;
esac

log() { printf '\n[mtb] %s\n' "$*" >&2; }
warn() { printf '\n[mtb] AVISO: %s\n' "$*" >&2; }
die() { printf '\n[mtb] ERROR: %s\n' "$*" >&2; exit 1; }

if [[ "$ENGINE" == "auto" ]]; then
  if command -v mkarchiso >/dev/null 2>&1; then
    ENGINE=host
  elif command -v docker >/dev/null 2>&1; then
    ENGINE=docker
  elif command -v podman >/dev/null 2>&1; then
    ENGINE=podman
  else
    die "No encuentro mkarchiso, docker ni podman. Instala archiso en Arch o Docker en tu Linux."
  fi
fi

# Re-exec inside an Arch container when requested. The container needs
# --privileged because archiso mounts proc/sys/dev and uses arch-chroot.
if [[ "$ENGINE" == "docker" || "$ENGINE" == "podman" ]]; then
  command -v "$ENGINE" >/dev/null 2>&1 || die "No encuentro el motor '$ENGINE'."
  [[ "${MTB_ARCHISO_IN_CONTAINER:-0}" == "1" ]] && die "Ya estamos dentro del contenedor; usa --engine host."

  if [[ "$OUT_DIR" != "$ROOT"/* || "$WORK_DIR" != "$ROOT"/* || "$CACHE_DIR" != "$ROOT"/* ]]; then
    die "Con --engine $ENGINE, --out/--work/--cache deben estar dentro del repositorio ($ROOT)."
  fi
  container_out="/work/${OUT_DIR#"$ROOT"/}"
  container_work="/work/${WORK_DIR#"$ROOT"/}"
  container_cache="/work/${CACHE_DIR#"$ROOT"/}"

  log "Construyendo en un contenedor Arch Linux ($ENGINE). Esto necesita --privileged."
  exec "$ENGINE" run --rm --privileged \
    -e MTB_ARCHISO_IN_CONTAINER=1 \
    -e HOST_UID="$(id -u)" \
    -e HOST_GID="$(id -g)" \
    -e PROFILE_KIND="$PROFILE_KIND" \
    -e CONTAINER_OUT="$container_out" \
    -e CONTAINER_WORK="$container_work" \
    -e CONTAINER_CACHE="$container_cache" \
    -v "$ROOT:/work" \
    -w /work \
    archlinux:latest \
    bash -lc '
      set -euo pipefail
      if [[ ! -f /etc/pacman.d/gnupg/trustdb.gpg ]]; then
        pacman-key --init
        pacman-key --populate archlinux
      fi
      pacman -Syu --noconfirm --needed archiso rsync curl || \
        pacman -Syu --noconfirm --needed --disable-sandbox archiso rsync curl
      /work/distro/archiso/build.sh \
        --engine host \
        --profile "$PROFILE_KIND" \
        --out "$CONTAINER_OUT" \
        --work "$CONTAINER_WORK" \
        --cache "$CONTAINER_CACHE"
    '
fi

[[ "$(uname -s)" == "Linux" ]] || die "El build de la ISO requiere Linux. Usa --engine docker/podman o GitHub Actions."

for cmd in mkarchiso mksquashfs xorriso; do
  command -v "$cmd" >/dev/null 2>&1 || die "Falta '$cmd'. En Arch: sudo pacman -S archiso. En Debian: usa --engine docker."
done
MKARCHISO_BIN="$(command -v mkarchiso)"

run_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -E "$@"
  else
    die "Se necesitan privilegios de root y no hay sudo. Ejecuta como root o instala sudo."
  fi
}

if [[ "$CLEAN" == "1" ]]; then
  log "Limpiando $WORK_DIR, $OUT_DIR y $CACHE_DIR"
  run_root rm -rf "$WORK_DIR" "$OUT_DIR" "$CACHE_DIR"
fi

mkdir -p "$WORK_DIR" "$OUT_DIR" "$CACHE_DIR"

fetch_tor_browser() {
  local tarball="$CACHE_DIR/tor-browser-linux-x86_64-${TOR_BROWSER_VERSION}.tar.xz"
  if [[ ! -f "$tarball" ]]; then
    log "Descargando Tor Browser ${TOR_BROWSER_VERSION}"
    curl -fL --retry 3 --connect-timeout 20 -o "$tarball.part" "$TOR_BROWSER_URL"
    mv "$tarball.part" "$tarball"
  fi
  local actual
  actual="$(sha256sum "$tarball" | awk '{print $1}')"
  if [[ "$actual" != "$TOR_BROWSER_SHA256" ]]; then
    die "SHA256 de Tor Browser incorrecto: $actual (esperado $TOR_BROWSER_SHA256)"
  fi
  printf '%s\n' "$tarball"
}

assemble_profile() {
  local variant="$1"
  local profile="$WORK_DIR/profile-$variant"
  local src="$ARCHISO_DIR/$variant"

  log "Montando el perfil '$variant' en $profile"
  rm -rf "$profile"
  mkdir -p "$profile/airootfs" "$profile/syslinux" "$profile/efiboot"

  # Common files first, variant overlay second.
  cp -a "$ARCHISO_DIR/common/airootfs/." "$profile/airootfs/"
  cp -a "$src/airootfs/." "$profile/airootfs/"

  cp -a "$ARCHISO_DIR/common/boot/." "$profile/"
  cp -a "$src/boot/." "$profile/"

  cp "$ARCHISO_DIR/common/pacman.conf" "$profile/pacman.conf"
  cp "$ARCHISO_DIR/common/bootstrap_packages" "$profile/bootstrap_packages"
  cp "$src/profiledef.sh" "$profile/profiledef.sh"

  {
    sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$ARCHISO_DIR/common/packages.base.x86_64"
    sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$src/packages.x86_64"
  } | awk '!seen[$0]++' >"$profile/packages.x86_64"

  find "$profile/airootfs/usr/local/bin" -type f -exec chmod 0755 {} + 2>/dev/null || true
  chmod 0755 "$profile/airootfs/root/customize_airootfs.sh"

  if [[ "$variant" == "audit" ]]; then
    log "Copiando el código del panel MarlonTheBug"
    mkdir -p "$profile/airootfs/opt/marlonthebug"
    cp -a "$ROOT/marlonthebug" "$profile/airootfs/opt/marlonthebug/"
    cp "$ROOT/pyproject.toml" "$profile/airootfs/opt/marlonthebug/"
    cp "$ROOT/README.md" "$profile/airootfs/opt/marlonthebug/"
    [[ -f "$ROOT/LICENSE" ]] && cp "$ROOT/LICENSE" "$profile/airootfs/opt/marlonthebug/"
    find "$profile/airootfs/opt/marlonthebug" -type d -name '__pycache__' -prune -exec rm -rf {} +
    find "$profile/airootfs/opt/marlonthebug" -type f -name '*.pyc' -delete
  fi

  if [[ "$variant" == "privacy" ]]; then
    local tarball
    tarball="$(fetch_tor_browser)"
    mkdir -p "$profile/airootfs/opt"
    cp "$tarball" "$profile/airootfs/opt/tor-browser.tar.xz"
  fi

  printf '%s\n' "$profile"
}

build_one() {
  local variant="$1"
  local profile work iso
  profile="$(assemble_profile "$variant")"
  work="$WORK_DIR/mkarchiso-$variant"
  run_root rm -rf "$work"
  local marker="$WORK_DIR/.build-start-$variant"
  touch "$marker"

  log "Construyendo la ISO '$variant' (esto tarda bastante)"
  run_root "$MKARCHISO_BIN" -v -w "$work" -o "$OUT_DIR" "$profile"

  iso="$(find "$OUT_DIR" -maxdepth 1 -type f -name "mtb-${variant}-*.iso" -newer "$marker" -print -quit)"
  rm -f "$marker"
  [[ -n "$iso" ]] || die "mkarchiso terminó pero no encuentro la ISO de $variant en $OUT_DIR."
  log "ISO generada: $iso ($(du -h "$iso" | cut -f1))"

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUT_DIR" && sha256sum "$(basename "$iso")" >"$(basename "$iso").sha256")
  fi

  # Keep disk usage bounded in CI and on small build hosts.
  run_root rm -rf "$work"
  rm -rf "$profile"
}

if [[ "$PROFILE_KIND" == "all" ]]; then
  build_one privacy
  build_one audit
else
  build_one "$PROFILE_KIND"
fi

if [[ -n "${HOST_UID:-}" && -n "${HOST_GID:-}" && "$(id -u)" -eq 0 ]]; then
  chown -R "$HOST_UID:$HOST_GID" "$OUT_DIR" "$WORK_DIR" 2>/dev/null || true
elif [[ "$(id -u)" -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
  # mkarchiso runs through sudo; hand the artifacts back to the caller.
  sudo chown -R "$(id -u):$(id -g)" "$OUT_DIR" "$WORK_DIR" 2>/dev/null || true
fi

log "Listo. ISOs en $OUT_DIR"
ls -lh "$OUT_DIR"/*.iso 2>/dev/null || true
