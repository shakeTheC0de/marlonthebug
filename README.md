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
- **Inteligencia de vulnerabilidades**: CISA KEV, EPSS, NVD y OSV con caché local y bundles para entornos air-gapped.
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

### Docker

```bash
docker build -t marlonthebug .
docker run --rm -p 8765:8765 -v "$PWD/mtb-data:/data" marlonthebug
```

El token de acceso aparece en los logs del contenedor.

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

---

## Explotación controlada

La explotación no se ejecuta durante el escaneo. Se habilita por proyecto y requiere escribir `EXPLOTAR` en el panel (o pasar `--confirm-text EXPLOTAR` en CLI).

| Módulo | Prueba de concepto | Riesgo |
|---|---|---|
| `webapp/sqli_exploit` | Versión/usuario/base de datos vía error SQL, solo lectura | Medio |
| `webapp/xss_exploit` | Payload único y comprobación de reflejo ejecutable | Bajo |
| `webapp/lfi_exploit` | Lectura de `/etc/passwd` o `win.ini` | Medio |
| `webapp/rce_exploit` | `id`/`whoami` sin shell inversa ni persistencia | Alto |
| `webapp/ssti_exploit` | Evaluación de `7*7` | Medio |
| `webapp/ssrf_exploit` | Metadata cloud y loopback | Alto |
| `webapp/open_redirect_exploit` | Redirección a destino canario | Bajo |

Cada ejecución se guarda en `exploit_runs` con payload, salida, evidencia, operador y estado de limpieza. Además se registra un **traza paso a paso** de cada petición y respuesta, una justificación del hallazgo, comandos de reproducción y un hash SHA-256 de integridad. La evidencia se puede descargar en Markdown o JSON y aparece también en los informes. Si la prueba se confirma, el hallazgo pasa a **verificado** y **confirmado**.

Solo debes usar estos módulos contra sistemas propios o con autorización escrita.

---

## Herramientas reales en Docker

El panel puede ejecutar herramientas reales dentro de un contenedor Kali aislado. La imagen incluye `sqlmap`, `nuclei`, `commix`, `whatweb`, `nikto`, `nmap`, `ffuf`, `gobuster` y `hydra`.

```bash
# Construir la imagen (una vez)
marlonthebug tools build

# Comprobar Docker y la imagen
marlonthebug tools status

# Ejecutar una herramienta contra un hallazgo
marlonthebug tools run --finding <id> --tool sqlmap --confirm-text EXPLOTAR
```

Desde el panel: abre un hallazgo con explotación activada y usa **Herramientas reales → Ejecutar en Docker**.

Medidas de seguridad:

- El contenedor usa `--rm`, `--cap-drop ALL`, `--security-opt no-new-privileges`, límites de CPU/memoria y un volumen temporal `/work`.
- El objetivo se valida contra el scope antes de arrancar Docker.
- Los targets `localhost`/`127.0.0.1` se reescriben a `host.docker.internal` para Docker Desktop.
- Cada ejecución crea un `exploit_run` con comando, salida, duración y evidencia.
- Si Docker no está arrancado, el panel lo indica y no ejecuta nada.

La imagen también puede publicarse en GHCR con el workflow `Tools image`.

---

## Inteligencia de vulnerabilidades

- **CISA KEV**: vulnerabilidades explotadas activamente.
- **EPSS**: probabilidad de explotación en 30 días.
- **NVD**: detalle técnico, CVSS y CWE bajo demanda.
- **OSV**: dependencias npm, PyPI, Maven, Go, etc.

La sincronización es automática al arrancar (si hay red) y puede lanzarse desde el panel o con `marlonthebug intel sync`. Para entornos sin Internet:

```bash
# En un equipo conectado
marlonthebug intel export --output intel-bundle.json

# En el equipo air-gapped
marlonthebug intel import intel-bundle.json
```

---

## Módulos

| Categoría | Módulos |
|---|---|
| Reconocimiento | subdominios, DNS, fingerprint con versiones, endpoints, JS, secretos, `.git`, auth bypass, supply chain |
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
├── services/       scanner, informes, inteligencia
├── output/         plantillas de informes PDF/HTML/Markdown
├── crawler/        spider async
├── fuzzer/         motor de fuzzing y wordlists
├── collaborator/   OOB DNS/HTTP
├── listeners/      listeners de reverse connections
└── exploit/        módulos de explotación controlada
```

---

## Licencia

MIT. Consulta [LICENSE](LICENSE).
