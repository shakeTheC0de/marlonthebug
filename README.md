# MarlonTheBug 2.0

**Plataforma local de auditoría de seguridad y generación de informes.**

MarlonTheBug combina reconocimiento, detección de vulnerabilidades, triaje, inteligencia de CVE y reporting profesional en un único panel web que funciona en tu equipo, sin depender de servicios externos.

> Uso exclusivo sobre sistemas propios o con autorización escrita. Cada acción queda registrada en el log de auditoría.

![Dashboard del panel](docs/screenshots/dashboard.png)

---

## Qué incluye

- **Panel web local** con dashboard, proyectos, activos, análisis, hallazgos, triaje e informes.
- **35 módulos** de reconocimiento, web, API, cloud, CI/CD y LLM.
- **CLI** completa para automatizar y ejecutar en servidores.
- **Persistencia SQLite** con deduplicación de hallazgos e histórico por proyecto.
- **Informes** ejecutivos y técnicos en PDF, HTML, Markdown y JSON, en español e inglés.
- **Explotación controlada** con evidencia: SQLi de solo lectura, XSS canario, LFI, RCE de prueba (`id`/`whoami`), SSTI, SSRF y open redirect. Sin shells inversas ni persistencia por defecto.
- **Explotación en contenedores efímeros**: un contenedor por intento, sin datos ni socket, que solo exporta resultado, credenciales/passwords y accesos.
- **Inteligencia de vulnerabilidades**: CISA KEV, EPSS, NVD y OSV con caché local y bundles para entornos air-gapped.
- **Stack Docker portable**: panel + tools-runner Kali aislado, sin socket de Docker, con backup y restauración.
- **Modo portable**: todos los datos en `./data`, ideal para USB.
- **Sin CDN, sin telemetría y sin dependencias de servicios cloud**.

| Bandeja de hallazgos | Informe PDF |
|---|---|
| ![Hallazgos](docs/screenshots/findings.png) | ![Informe](docs/screenshots/report-cover.png) |

---

## Instalación

### Con `uv` (recomendado)

```bash
uv tool install git+https://github.com/shakeTheC0de/marlonthebug
marlonthebug panel
```

### Con `pipx`

```bash
pipx install git+https://github.com/shakeTheC0de/marlonthebug
marlonthebug panel
```

### Desde el código

```bash
git clone https://github.com/shakeTheC0de/marlonthebug
cd marlonthebug
uv sync
uv run marlonthebug panel
```

### Binario portable

Descarga el binario de la sección **Releases**, descomprímelo y ejecuta:

```bash
./marlonthebug panel --portable --no-browser
```

En Windows:

```powershell
.\marlonthebug.exe panel --portable --no-browser
```

### Docker Compose (recomendado para desplegar)

```bash
git clone https://github.com/shakeTheC0de/marlonthebug
cd marlonthebug
./scripts/install.sh
```

El stack levanta el **panel**, un **tools-runner** Kali aislado y un
**exploit-runner** que lanza contenedores efímeros de explotación. El panel no
tiene Docker CLI ni socket. Los datos quedan en `./mtb-data` y el panel escucha
solo en `127.0.0.1:8765`. Guía completa: [`docs/DOCKER.md`](docs/DOCKER.md).

```bash
docker compose up -d          # arranque manual
docker compose logs -f panel  # token y URL
./scripts/backup.sh           # backup consistente
```

### MarlonTheBug Live (USB)

La carpeta [`distro/`](distro/README.md) contiene el esqueleto para una ISO
basada en Kali Live con el panel preinstalado, autostart y persistencia
opcional. El build se lanza en Linux o con el workflow **Live ISO** de GitHub
Actions; macOS no es un host fiable para construir ISOs live.

```bash
# En Linux
./distro/build.sh

# En CI: Actions → Live ISO → Run workflow (amd64/arm64)
```

La ISO se graba con Etcher, `dd` o Ventoy. Sin persistencia, todo se pierde al
apagar; con una partición `persistence` se conservan `/home`, informes y token.

### Laboratorio de práctica

```bash
./scripts/lab.sh up       # Juice Shop + WebGoat en 127.0.0.1
./scripts/lab.sh tools    # Kali + Metasploit + sqlmap/nmap/ffuf...
./scripts/lab.sh down     # parar
./scripts/lab.sh reset    # recrear limpio
```

Es un entorno desechable para practicar con frameworks establecidos y
objetivos vulnerables. No forma parte del stack de producción. Guía:
[`docs/LAB.md`](docs/LAB.md).

---

## Primer arranque

`marlonthebug panel` arranca en `127.0.0.1:8765`, abre el navegador y muestra una URL con token:

```
http://127.0.0.1:8765/?token=...
```

El token también se guarda en el directorio de datos (`panel.token`) y se puede consultar con:

```bash
marlonthebug config
```

Flujo recomendado:

1. Crea un **proyecto** y define el alcance autorizado. Para enumerar subdominios añade el patrón `*.example.com`.
2. Añade dominios o IPs como **activos**.
3. Lanza un **análisis** con perfil seguro o estándar.
4. Revisa y tria los **hallazgos** (confirmado, falso positivo, aceptado, remediado).
5. Genera un **informe** ejecutivo o técnico en PDF.
6. Sincroniza **inteligencia** (KEV/EPSS) para priorizar lo que se explota de verdad.

---

## CLI

```bash
marlonthebug --help
marlonthebug panel --help
marlonthebug workspace create --name acme-audit --client "Acme S.L."
marlonthebug workspace add --name acme-audit --domains "example.com,api.example.com"
marlonthebug scan run --workspace acme-audit --categories recon,web --profile safe --authorized
marlonthebug report generate --workspace acme-audit --format pdf --template full
marlonthebug intel sync
marlonthebug intel search CVE-2021-44228
marlonthebug intel export --output intel-bundle.json
marlonthebug legacy import --reports reports
marlonthebug exploit list --workspace acme-audit
marlonthebug exploit run --finding <id> --module webapp/xss_exploit --confirm-text EXPLOTAR
marlonthebug exploit status
marlonthebug exploit build   # imagen del contenedor efímero de explotación
marlonthebug tools status
marlonthebug tools run --finding <id> --tool sqlmap --confirm-text EXPLOTAR
marlonthebug tools target --workspace acme-audit --target https://app.example.com --tool ffuf --confirm-text EXPLOTAR
# Si el host aún no está en el alcance del proyecto:
marlonthebug tools target --workspace acme-audit --target https://app.example.com --tool nmap --confirm-text EXPLOTAR --add-to-scope
marlonthebug backup --output ~/backups/acme-audit.tar.gz
marlonthebug restore ~/backups/acme-audit.tar.gz --data-dir ./mtb-data --force
```

### Perfiles de análisis

| Perfil | Peticiones/s | Máx. peticiones | Páginas crawler |
|---|---:|---:|---:|
| `safe` | 2 | 600 | 40 |
| `standard` | 8 | 2.500 | 200 |
| `deep` | 12 | 10.000 | 800 |

Los módulos intrusivos (smuggling, race conditions, upload, RCE, deserialización, mass assignment, BOLA, prompt injection, auth bypass, etc.) solo se ejecutan automáticamente con el perfil `deep` o si se seleccionan explícitamente.

---

## Datos y portabilidad

Por defecto los datos se guardan fuera del código:

| Sistema | Directorio |
|---|---|
| macOS | `~/Library/Application Support/MarlonTheBug` |
| Linux | `~/.local/share/marlonthebug` |
| Windows | `%APPDATA%\MarlonTheBug` |

Con `--portable` o `--data-dir`, todo (base de datos, informes, feeds, logs y token) se guarda en la ruta indicada:

```bash
marlonthebug panel --portable
# ./data/marlonthebug.db
# ./data/reports/
# ./data/feeds/
```

Variables de entorno útiles:

```bash
MARLONTHEBUG_DATA_DIR=/ruta/datos
MARLONTHEBUG_HOST=127.0.0.1
MARLONTHEBUG_PORT=8765
MARLONTHEBUG_OFFLINE=1
NVD_API_KEY=...
```

En Docker Compose se usan las variables `MTB_*` documentadas en
[`docs/DOCKER.md`](docs/DOCKER.md) y en `.env.example`:

```bash
MTB_DATA_DIR=./mtb-data
MTB_PANEL_PORT=8765
MTB_TOOLS_BACKEND=remote
MTB_TOOLS_URL=http://tools-runner:8080
MTB_TOOLS_TOKEN=...
MTB_TOOLS_TIMEOUT=180
MTB_EXPLOIT_BACKEND=runner
MTB_EXPLOIT_URL=http://exploit-runner:8090
MTB_EXPLOIT_TOKEN=...
```

---

## Explotación controlada

La explotación no se ejecuta durante el escaneo. Se habilita por proyecto y requiere escribir `EXPLOTAR` en el panel (o pasar `--confirm-text EXPLOTAR` en CLI).

Cada módulo se ejecuta en un **contenedor efímero** de la imagen de explotación: sin base de datos, sin volúmenes, sin socket de Docker y con `cap_drop: ALL`, rootfs de solo lectura, tmpfs `/tmp` y límites de CPU/memoria/PIDs. El contenedor recibe un JSON por `stdin` y devuelve únicamente un JSON por `stdout` con **resultado, credenciales/passwords y accesos obtenidos**. No exporta su sistema de ficheros ni estado.

| Módulo | Prueba de concepto | Riesgo |
|---|---|---|
| `webapp/sqli_exploit` | Versión/usuario/base de datos vía error SQL, solo lectura | Medio |
| `webapp/xss_exploit` | Payload único y comprobación de reflejo ejecutable | Bajo |
| `webapp/lfi_exploit` | Lectura de `/etc/passwd` o `win.ini` | Medio |
| `webapp/rce_exploit` | `id`/`whoami` sin shell inversa ni persistencia | Alto |
| `webapp/ssti_exploit` | Evaluación de `7*7` | Medio |
| `webapp/ssrf_exploit` | Metadata cloud y loopback | Alto |
| `webapp/open_redirect_exploit` | Redirección a destino canario | Bajo |

Cada ejecución se guarda en `exploit_runs` con payload, salida, evidencia, operador y estado de limpieza. Además se registra una **traza paso a paso** de cada petición y respuesta, una justificación del hallazgo, comandos de reproducción y un hash SHA-256 de integridad. La evidencia incluye las **credenciales, contraseñas, hashes, tokens y accesos** que el contenedor haya demostrado, y se puede descargar en Markdown o JSON. Si la prueba se confirma, el hallazgo pasa a **verificado** y **confirmado**.

En el stack Compose el panel delega el lanzamiento en `exploit-runner`, el único servicio con socket de Docker; los hijos no tienen socket ni acceso a los datos. En una instalación nativa, el backend `docker` usa el Docker local. `local` queda reservado para desarrollo.

La ficha de cada hallazgo indica su cobertura: **módulo automático**, **plugin que ya ejecutó pruebas activas**, **validación guiada** o **informativo**. Las validaciones guiadas muestran pasos, herramientas y límites de seguridad; no se ejecutan solas. En LFI/RCE confirmados se añade post-explotación de solo lectura (ficheros de configuración, hostname, kernel, SO) para demostrar acceso sin persistencia ni escalada.

Solo debes usar estos módulos contra sistemas propios o con autorización escrita.

---

## Herramientas reales

El motor de herramientas admite tres backends:

| Backend | Descripción | Uso |
|---|---|---|
| `remote` | Panel → `tools-runner` por HTTP interno | Docker Compose (recomendado) |
| `docker` | Contenedor efímero desde el panel nativo | Docker Desktop/Engine en el host |
| `local` | Herramientas instaladas en `PATH` | Desarrollo y laboratorio |

La imagen incluye `sqlmap`, `nuclei`, `commix`, `whatweb`, `nikto`, `nmap`,
`ffuf`, `gobuster` y `hydra`. `ffuf` está integrado en el catálogo con una
wordlist de rutas y API (incluye `/api/docs`, `/api/v1/*`, OpenAPI, etc.).

```bash
# Comprobar el motor configurado
marlonthebug tools status

# Ejecutar una herramienta contra un hallazgo
marlonthebug tools run --finding <id> --tool sqlmap --confirm-text EXPLOTAR

# Arrancar el runner fuera de Compose (desarrollo)
MTB_TOOLS_TOKEN=... marlonthebug tools runner --host 127.0.0.1 --port 8080
```

Desde el panel: abre un hallazgo con explotación activada y usa
**Herramientas reales → Ejecutar herramienta**, o entra en **Herramientas** para
lanzar una herramienta directamente contra un objetivo autorizado sin crear un
hallazgo.

Medidas de seguridad:

- El panel no monta el socket de Docker en el stack portable.
- El `tools-runner` valida token, herramienta, flags, objetivo, timeout y
  tamaño de argumentos; no usa shell.
- `cap_drop: ALL`, `no-new-privileges`, rootfs de solo lectura, límites de
  CPU/memoria/PIDs y `/work` temporal.
- El objetivo se valida contra el scope antes de ejecutar.
- Cada ejecución crea un `exploit_run` con comando, salida, duración y
  evidencia; la clasificación (confirmado/no confirmado) se aplica en el panel.
- Si el runner o Docker no están disponibles, el panel lo indica y no ejecuta
  nada.

Las imágenes se publican en GHCR para `linux/amd64` y `linux/arm64` mediante el
workflow **Container images**.

---

## Inteligencia de vulnerabilidades

- **CISA KEV**: vulnerabilidades explotadas activamente.
- **EPSS**: probabilidad de explotación en 30 días.
- **NVD**: detalle técnico, CVSS y CWE bajo demanda.
- **OSV**: dependencias npm, PyPI, Maven, Go, etc.
- **CPE 2.3**: correlación de producto y versión detectados con CVEs de NVD, con confianza alta y sin ruido cuando la versión no tiene CVEs.
- **Frescura de feeds**: ETag/Last-Modified, última y próxima sincronización, errores y aviso de feed desactualizado.
- **Bundles firmados Ed25519** para entornos air-gapped, con verificación antes de importar.

La sincronización es automática al arrancar (si hay red) y puede lanzarse desde el panel o con `marlonthebug intel sync`. Para entornos sin Internet:

```bash
# En un equipo conectado
marlonthebug intel export --output intel-bundle.json --sign-key signing.pem

# En el equipo air-gapped
marlonthebug intel verify intel-bundle.json --public-key signing.pub
marlonthebug intel import intel-bundle.json --signature intel-bundle.json.sig --public-key signing.pub
```

Genera el par de claves una vez con `marlonthebug intel keygen --private signing.pem --public signing.pub`.

---

## Módulos

| Categoría | Módulos |
|---|---|
| Reconocimiento | subdominios, DNS, fingerprint con versiones, endpoints, JS, secretos, `.git`, OpenAPI/Swagger expuesto, auth bypass, supply chain |
| Web | SQLi, XSS, SSRF, CSRF, LFI/RFI, path traversal, file upload, SSTI, RCE, command injection, deserialización, smuggling, race conditions, lógica de negocio, WAF bypass, prototype pollution, cache poisoning |
| API | JWT, OAuth/OIDC, BOLA/IDOR, mass assignment, GraphQL |
| Cloud / CI-CD | dashboards y APIs cloud expuestas, pipelines y manifiestos públicos |
| LLM | prompt injection con canario |

Los módulos marcados como **beta** son heurísticas conservadoras y requieren validación manual. El panel muestra la confianza de cada hallazgo.

---

## Seguridad y alcance

- **Scope guard fail-closed**: ninguna petición sale sin validar el host contra el alcance del proyecto.
- **Explotación desactivada por defecto** a nivel de proyecto.
- **Confirmación explícita** en el formulario de análisis.
- **Token local** para el panel y cookies `HttpOnly`/`SameSite=Strict`.
- **CSRF** en todas las acciones de escritura.
- **Audit log** de creación de proyectos, cambios de alcance, análisis, triaje e informes.
- **Sin telemetría**.

---

## Desarrollo

```bash
uv sync --group dev
uv run pytest --cov=marlonthebug
uv run ruff check .
uv run ruff format --check .
uv run mypy marlonthebug/
```

### Migraciones

```bash
uv run alembic upgrade head
uv run alembic revision --autogenerate -m "cambio"
```

La aplicación crea el esquema automáticamente en el primer arranque; Alembic queda disponible para evolución controlada.

### Build local del binario

```bash
uv pip install pyinstaller
uv run pyinstaller \
  --noconfirm --clean --onedir --name marlonthebug \
  --collect-all marlonthebug \
  --hidden-import aiosqlite \
  --hidden-import sqlalchemy.dialects.sqlite.aiosqlite \
  --hidden-import uvicorn.logging \
  --hidden-import uvicorn.loops.auto \
  --hidden-import uvicorn.protocols.http.auto \
  --hidden-import uvicorn.protocols.websockets.auto \
  --hidden-import uvicorn.lifespan.on \
  scripts/entrypoint.py
```

El resultado queda en `dist/marlonthebug/`.

---

## Estructura

```
marlonthebug/
├── cli/            CLI Typer
├── web/            FastAPI + Jinja + assets del panel
├── db/             modelos, repositorio, migraciones
├── core/           contexto de scan, scope, pipeline, workspaces
├── http/           cliente httpx, baseline/soft-404, rate limit
├── plugins/        recon, web, api, llm
├── services/       scanner, informes, inteligencia, backup
├── output/         plantillas de informes PDF/HTML/Markdown
├── crawler/        spider async
├── fuzzer/         motor de fuzzing y wordlists
├── collaborator/   OOB DNS/HTTP
├── listeners/      listeners de reverse connections
├── tools/          catálogo, backends docker/remote/local y runner API
└── exploit/        módulos, runners y contenedor efímero de explotación
```

---

## Licencia

MIT. Consulta [LICENSE](LICENSE).
