#!/usr/bin/env bash
# Build the MarlonTheBug Live ISO.
#
# It remasters the official Kali Live build (live-build) with a custom
# variant: Kali Xfce + MarlonTheBug panel + tools + browser autostart.
#
# Recommended: run on a Linux host or in CI. Other systems cannot reliably
# build a live ISO; use the GitHub Actions workflow instead.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DISTRO="$ROOT/distro"
KALI_DIR="${KALI_LIVE_DIR:-$DISTRO/.build/kali-live}"
WHEEL_DIR="$DISTRO/.build/wheel"
OUT_DIR="${OUT_DIR:-$DISTRO/output}"
ARCH="${ARCH:-amd64}"
VARIANT="marlonthebug"
USE_CONTAINER="${USE_CONTAINER:-0}"

if [ "$(uname -s)" != "Linux" ]; then
  echo "ERROR: el build de una ISO live requiere Linux." >&2
  echo "Usa el workflow .github/workflows/iso.yml o una máquina Linux." >&2
  exit 1
fi

command -v git >/dev/null 2>&1 || { echo "ERROR: falta git." >&2; exit 1; }
command -v sudo >/dev/null 2>&1 || { echo "ERROR: falta sudo." >&2; exit 1; }

echo "[1/4] Construyendo el wheel de MarlonTheBug…"
rm -rf "$WHEEL_DIR"
mkdir -p "$WHEEL_DIR"
if command -v uv >/dev/null 2>&1; then
  (cd "$ROOT" && uv build --wheel --out-dir "$WHEEL_DIR")
else
  python3 -m build --wheel --outdir "$WHEEL_DIR"
fi

echo "[2/4] Preparando Kali Live…"
if [ ! -d "$KALI_DIR/.git" ]; then
  mkdir -p "$(dirname "$KALI_DIR")"
  git clone --depth 1 https://gitlab.com/kalilinux/build-scripts/kali-live.git "$KALI_DIR"
else
  git -C "$KALI_DIR" pull --ff-only || true
fi

echo "[3/4] Aplicando la variante MarlonTheBug…"
rm -rf "$KALI_DIR/kali-config/variant-$VARIANT"
cp -r "$DISTRO/kali-config/variant-$VARIANT" "$KALI_DIR/kali-config/"
mkdir -p "$KALI_DIR/kali-config/variant-$VARIANT/includes.chroot/opt/marlonthebug"
cp "$WHEEL_DIR"/*.whl "$KALI_DIR/kali-config/variant-$VARIANT/includes.chroot/opt/marlonthebug/"
mkdir -p "$KALI_DIR/kali-config/variant-$VARIANT/includes.chroot/usr/share/doc/marlonthebug"
cp "$ROOT/README.md" "$KALI_DIR/kali-config/variant-$VARIANT/includes.chroot/usr/share/doc/marlonthebug/README.md"
cp "$ROOT/distro/README.md" "$KALI_DIR/kali-config/variant-$VARIANT/includes.chroot/usr/share/doc/marlonthebug/DISTRO.md"

echo "[4/4] Construyendo la ISO ($ARCH)…"
mkdir -p "$OUT_DIR"
cd "$KALI_DIR"
if [ "$USE_CONTAINER" = "1" ]; then
  CONTAINER="${CONTAINER:-docker}" sudo -E ./build-in-container.sh \
    --variant "$VARIANT" --arch "$ARCH" -o "$OUT_DIR"
else
  sudo ./build.sh --variant "$VARIANT" --arch "$ARCH" -o "$OUT_DIR"
fi

echo
echo "ISO generada en: $OUT_DIR"
ls -lh "$OUT_DIR"/*.iso 2>/dev/null || true
echo "Flashea con Etcher o dd y arranca el USB. Ver distro/README.md."
