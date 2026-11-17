# MarlonTheBug Live

Imagen Linux tipo Kali, con el panel MarlonTheBug preinstalado y autostart en
el navegador. Pensada para un USB: arrancar, trabajar y apagar sin instalación.

## Qué incluye

- Kali Linux Xfce con el metapaquete de herramientas y firmware.
- MarlonTheBug panel + CLI en `/opt/marlonthebug/venv`.
- Chromium con ventana del panel al iniciar sesión.
- `metasploit-framework`, `sqlmap`, `nmap`, `nikto`, `whatweb`, `ffuf`,
  `gobuster`, `nuclei`, `commix`, `hydra`.
- Escritorio Xfce funcional: Firefox, Chromium, Thunderbird, LibreOffice,
  VLC, CherryTree, Zim, notas Xfce, KeePassXC, Synaptic, Flatpak, GParted,
  Timeshift, GUFW, neovim, tmux y htop.
- Ventana de bienvenida con accesos a panel, notas, navegador, instalación de
  aplicaciones, actualización y documentación.
- Fondo de escritorio y menú propios de MarlonTheBug.
- Backends `local` para herramientas y explotación: todo corre dentro del
  sistema live, sin Docker. Es un compromiso de portabilidad; para aislamiento
  por contenedor usa el stack Compose normal.
- Datos en `/home/kali/.local/share/MarlonTheBug`; si habilitas persistencia en
  el USB, sobreviven al reinicio.

## Requisitos de build

- Linux x86_64 recomendado. La ISO por defecto es `amd64`; también se puede
  compilar `arm64` con `ARCH=arm64` (más lento y no arranca en un Mac Apple
  Silicon; esos equipos necesitan virtualización).
- `git`, `sudo`, `uv` (o `python3-build`), y ~20 GB libres.
- `live-build` y dependencias de Kali. El modo contenedor las encapsula.
- **macOS no es un host fiable para construir la ISO**: usa el workflow
  `.github/workflows/iso.yml` o una VM Linux.

## Build

Primero comprueba el host:

```bash
./distro/preflight.sh
```

### GitHub Actions (recomendado)

Lanza manualmente el workflow **Live ISO** o crea un tag `v*`. Genera la ISO
como artefacto descargable. Es un build largo (puede superar 30-60 minutos).

### Linux local

```bash
# Opción A: live-build instalado en el host
sudo apt-get install -y live-build debootstrap cpio apt-utils qemu-user-binfmt
./distro/build.sh

# Opción B: construir dentro de un contenedor Docker (host Linux)
USE_CONTAINER=1 ./distro/build.sh

# Arquitectura
ARCH=arm64 ./distro/build.sh
```

La ISO queda en `distro/output/`.

## Grabar el USB

```bash
# macOS/Linux: identifica el dispositivo con cuidado (diskutil list / lsblk)
# Ejemplo; sustituye /dev/diskN por el USB correcto. DESTRUYE ese disco.
sudo dd if=distro/output/kali-linux-*.iso of=/dev/diskN bs=4M status=progress oflag=sync
```

También puedes usar **balenaEtcher** o **Ventoy**. En Ventoy basta copiar la ISO
al USB.

> Secure Boot puede impedir el arranque de la ISO. Desactívalo en la BIOS/UEFI
> o enrola las claves de Kali según la documentación oficial.

## Persistencia (opcional)

Sin persistencia, todo vive en RAM y se pierde al apagar. Para conservar datos,
proyectos, informes y token:

1. Crea una segunda partición ext4 en el USB y etiquétala `persistence`.
2. En la raíz de esa partición crea `persistence.conf` con:

   ```text
   /home
   ```

3. Arranca el USB y elige la entrada **Live USB Persistence**.

Kali documenta también persistencia cifrada con LUKS. Si usas persistencia,
protege el USB: contiene tokens, evidencias y posibles credenciales.

## Primer arranque

El servicio `marlonthebug.service` arranca el panel en `127.0.0.1:8765`.
Chromium se abre con el token automáticamente. Si no se abre:

```bash
systemctl status marlonthebug
journalctl -u marlonthebug -n 100
cat ~/.local/share/MarlonTheBug/panel.token
# Abre http://127.0.0.1:8765/?token=...
```

## Actualizar

La ISO es inmutable. Para actualizar:

- Reconstruye la ISO con el código nuevo (`./distro/build.sh`).
- O, con persistencia y red, actualiza el venv:

  ```bash
  sudo /opt/marlonthebug/venv/bin/pip install --upgrade \
    git+https://github.com/shakeTheC0de/marlonthebug
  sudo systemctl restart marlonthebug
  ```

## Límites

- Uso exclusivo en sistemas propios o con autorización escrita.
- La imagen incluye herramientas de seguridad de propósito general; no incluye
  malware, mineros, persistencia ofensiva ni payloads destructivos.
- El backend `local` no aísla cada ejecución en un contenedor. Para trabajo
  contra producción, usa el stack Compose con `tools-runner` y
  `exploit-runner` en una máquina dedicada.
- Prueba la ISO en una VM antes de usarla en hardware real.
