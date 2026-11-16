# Despliegue con Docker Compose

El stack portable levanta el panel y un ejecutor de herramientas aislado con un
solo comando. No necesitas Python, `uv` ni el socket de Docker en el equipo.

```
docker compose up -d
├── panel          FastAPI + SQLite + ./mtb-data
│                  127.0.0.1:8765, sin Docker CLI ni socket
└── tools-runner   Kali + sqlmap/nuclei/commix/whatweb/nikto/nmap
                   red interna, token, usuario sin privilegios
```

El panel llama al `tools-runner` por HTTP interno (`http://tools-runner:8080`).
El runner ejecuta la herramienta dentro de su propio contenedor y devuelve
salida, código de retorno y duración. No hay Docker-in-Docker.

## Requisitos

- Docker Engine 24+ o Docker Desktop con Compose v2.
- 4 GB de RAM recomendados (el runner usa 2 GB como máximo).
- Puertos: solo el 8765 en `127.0.0.1` (configurable con `MTB_PANEL_PORT`).

## Instalación rápida

```bash
git clone https://github.com/shakeTheC0de/marlonthebug
cd marlonthebug
./scripts/install.sh
```

El script:

1. Copia `.env.example` a `.env` si no existe.
2. Genera `MTB_TOOLS_TOKEN` con `openssl` o Python.
3. Ajusta `MTB_UID`/`MTB_GID` al usuario del host en Linux.
4. Crea `./mtb-data`.
5. Descarga las imágenes de GHCR o las construye localmente.
6. Espera al healthcheck y muestra la URL con token.

También puedes hacerlo a mano:

```bash
cp .env.example .env
# Edita .env y define un token real:
#   openssl rand -hex 32
docker compose up -d --build
```

En Windows usa PowerShell o Git Bash. Docker Desktop debe estar arrancado.

## Acceso

```bash
# Token persistente en ./mtb-data/panel.token
cat ./mtb-data/panel.token

# URL de acceso
open "http://127.0.0.1:8765/?token=$(cat ./mtb-data/panel.token)"
```

El token se guarda en `panel.token` con permisos restringidos y se conserva en
el volumen de datos. El panel también lo imprime en los logs del primer arranque:

```bash
docker compose logs panel | grep -i "token\|panel"
```

## Servicios y aislamiento

| Servicio | Puerto | Volumen | Seguridad |
|---|---|---|---|
| `panel` | `127.0.0.1:8765` | `./mtb-data:/data` | `cap_drop: ALL`, `no-new-privileges`, rootfs read-only, sin socket |
| `tools-runner` | solo red interna (`expose`) | tmpfs `/work` y `/tmp` | usuario sin privilegios, `cap_drop: ALL`, límites de CPU/memoria, rootfs read-only |

El `tools-runner` no publica puertos. Solo es alcanzable desde la red de Compose.
El panel no monta `/var/run/docker.sock`.

`tools-runner` valida cada petición:

- Token obligatorio (`MTB_TOOLS_TOKEN`), comparado en tiempo constante.
- Allowlist de herramientas y de flags por herramienta.
- Sin shell: `subprocess` con lista de argumentos.
- Timeout máximo de 900 s, salida truncada y concurrencia limitada.
- `/work` temporal por ejecución y limpieza al terminar.
- Rechazo de rutas de salida fuera de `/work`.

Los targets `localhost`/`127.0.0.1` se reescriben a `host.docker.internal`
cuando el backend es `docker` o `remote`. En el stack, `host.docker.internal`
apunta al equipo que ejecuta Docker. Para escanear servicios publicados en el
host usa `host.docker.internal` como activo (o el nombre/IP de la máquina).

## Backends de herramientas

| Backend | Uso | Requisitos |
|---|---|---|
| `remote` | Recomendado con Compose | `tools-runner` levantado y token |
| `docker` | Panel nativo con Docker Desktop/Engine en el host | Docker CLI e imagen local |
| `local` | Desarrollo o laboratorio | Herramientas instaladas en `PATH` |

Se configura en `.env` (`MTB_TOOLS_BACKEND`) o en **Configuración → Herramientas
reales**. La variable `MTB_TOOLS_URL` apunta al runner y `MTB_TOOLS_TIMEOUT`
limita cada ejecución.

```bash
# Comprobar el estado del motor configurado
marlonthebug tools status
# o dentro del contenedor
docker compose exec panel marlonthebug tools status
```

## Actualización

```bash
git pull
docker compose pull
docker compose up -d
```

Los datos viven en `./mtb-data` y sobreviven a `docker compose down`, a
recreaciones y a la actualización de imágenes. Para reconstruir localmente:

```bash
docker compose build --pull
docker compose up -d
```

## Backup y restauración

### Desde el stack

```bash
./scripts/backup.sh
# ./mtb-data/backups/marlonthebug-backup-YYYYmmdd-HHMMSS.tar.gz
```

El backup incluye la base SQLite (copiada con la API de backup, consistente
aunque el panel esté escribiendo), informes, configuración, feeds y el token del
panel. **Trátalo como material sensible.**

Retención por defecto: 14 copias (`MTB_BACKUP_KEEP`).

Restaurar:

```bash
./scripts/restore.sh ./mtb-data/backups/marlonthebug-backup-....tar.gz --force
```

El script detiene el panel, restaura en el volumen y lo vuelve a arrancar. Sin
`--force` se niega a sobrescribir datos existentes.

### Desde la CLI nativa

```bash
marlonthebug backup --output ~/backups/mtb.tar.gz
marlonthebug restore ~/backups/mtb.tar.gz --data-dir /ruta/mtb-data --force
```

## Migrar datos de una instalación nativa

```bash
# Instalación nativa (macOS de ejemplo)
OLD="$HOME/Library/Application Support/MarlonTheBug"

# Copia al volumen del stack
mkdir -p ./mtb-data
cp -a "$OLD"/. ./mtb-data/

# Ajusta permisos (Linux)
sudo chown -R "${MTB_UID:-10001}:${MTB_GID:-10001}" ./mtb-data

docker compose up -d
```

También puedes usar `marlonthebug backup` en el equipo original y
`./scripts/restore.sh` en el destino.

## Acceso remoto seguro

Por defecto el panel solo escucha en `127.0.0.1`. Para acceder desde otro equipo
no publiques el puerto directamente. Opciones recomendadas:

### Tailscale

```bash
# En el servidor, con Tailscale instalado y autenticado
tailscale serve --bg 8765
tailscale serve status
```

La URL queda disponible solo dentro de tu tailnet. Mantén la autenticación del
panel activada.

### Caddy como reverse proxy

```caddyfile
mtb.example.com {
    reverse_proxy 127.0.0.1:8765
    tls internal
}
```

Caddy escucha en el host y el contenedor sigue vinculado a `127.0.0.1`. No
cambies el mapeo a `0.0.0.0` salvo que tengas firewall y TLS delante.

### Endurecimiento adicional

- Mantén `MTB_TOOLS_TOKEN` y `panel.token` fuera de Git y de capturas.
- Rota el token si sospechas que se ha filtrado:
  ```bash
  docker compose down
  # edita MTB_TOOLS_TOKEN en .env con un valor nuevo
  docker compose up -d
  ```
  El token del panel (`panel.token`) se puede rotar borrando el archivo con el
  panel parado.
- Usa un usuario del sistema sin privilegios para Docker.
- Revisa `docker compose logs` y el **audit log** del panel.
- El multiusuario no está incluido en 2.0: el token es compartido. Para varios
  operadores, despliega una instancia por cliente o pon un proxy con identidad.

## Variables de entorno

| Variable | Por defecto | Descripción |
|---|---|---|
| `MTB_DATA_DIR` | `./mtb-data` | Datos del panel en el host |
| `MTB_PANEL_PORT` | `8765` | Puerto del panel (solo `127.0.0.1`) |
| `MTB_PANEL_IMAGE` | `ghcr.io/shakethec0de/marlonthebug:latest` | Imagen del panel |
| `MTB_TOOLS_IMAGE` | `ghcr.io/shakethec0de/marlonthebug-tools:latest` | Imagen del runner |
| `MTB_TOOLS_TOKEN` | — | Token compartido (obligatorio) |
| `MTB_TOOLS_BACKEND` | `remote` | `remote`, `docker` o `local` |
| `MTB_TOOLS_URL` | `http://tools-runner:8080` | URL interna del runner |
| `MTB_TOOLS_TIMEOUT` | `180` | Timeout por herramienta (s) |
| `MTB_TOOLS_CONCURRENCY` | `2` | Ejecuciones simultáneas en el runner |
| `MTB_TOOLS_MAX_OUTPUT` | `60000` | Caracteres máximos de salida |
| `MTB_UID` / `MTB_GID` | `10001` | UID/GID con el que corren los contenedores |
| `MTB_INTEL_OFFLINE` | `0` | `1` desactiva la descarga de feeds |
| `MTB_MAX_CPE_LOOKUPS` | `5` | Consultas CPE por activo al correlacionar |
| `MTB_CPE_TIMEOUT` | `12` | Timeout de cada consulta CPE a NVD |
| `MTB_BUNDLE_PUBLIC_KEY` | — | Clave pública Ed25519 para bundles |
| `MTB_REQUIRE_BUNDLE_SIGNATURE` | `0` | `1` exige firma al importar bundles |
| `NVD_API_KEY` | — | Clave opcional de NVD |
| `MTB_BACKUP_KEEP` | `14` | Backups locales a conservar |

## Solución de problemas

**El panel no arranca o no escribe en `./mtb-data`**

En Linux, el directorio debe pertenecer al UID configurado:

```bash
mkdir -p ./mtb-data
sudo chown -R "${MTB_UID:-10001}:${MTB_GID:-10001}" ./mtb-data
```

**`tools-runner` no está disponible**

```bash
docker compose ps
docker compose logs --tail=80 tools-runner
curl -fsS http://127.0.0.1:8080/healthz   # no publicado: usa exec
docker compose exec tools-runner curl -fsS http://127.0.0.1:8080/healthz
```

Comprueba que `MTB_TOOLS_TOKEN` coincide en ambos servicios. El panel sigue
funcionando si el runner está caído; mostrará el error en la ficha del hallazgo.

**Token inválido**

El token del panel (`panel.token`) y el token interno (`MTB_TOOLS_TOKEN`) son
distintos. El primero autentica el navegador; el segundo protege la API interna.

**Un target local no responde desde las herramientas**

Usa `host.docker.internal` en lugar de `localhost`/`127.0.0.1`, o el nombre/IP
real del equipo. Añade ese host al alcance del proyecto.

**Informes PDF**

La imagen del panel incluye WeasyPrint. Si generas informes nativos fuera de
Docker, instala `uv sync --extra pdf` o usa Chrome/Edge.
