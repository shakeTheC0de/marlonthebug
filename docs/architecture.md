# MarlonTheBug 2.0 — Arquitectura

## Visión general

MarlonTheBug es una aplicación local-first con tres planos:

1. **Plano de datos**: SQLite + SQLAlchemy async. Es la fuente de verdad para proyectos, activos, análisis, hallazgos, informes, auditoría e inteligencia.
2. **Plano de ejecución**: `ScanManager` orquesta crawler, cliente HTTP compartido, scope guard, rate limiter y plugins. Cada scan tiene un `ScanContext` y un presupuesto de peticiones.
3. **Plano de presentación**: panel FastAPI + Jinja2 + CSS/JS propios, sin CDN ni build de Node. La API JSON queda disponible para integraciones futuras.

```
┌─────────────────────────────────────────────────────────────┐
│ Panel web local (FastAPI + Jinja2)   CLI (Typer)            │
├─────────────────────────────────────────────────────────────┤
│ API JSON · SSE de progreso · informes · triaje             │
├─────────────────────────────────────────────────────────────┤
│ ScanManager                                                 │
│  ├─ ScanContext (scope, rate limit, baseline, presupuesto)  │
│  ├─ Crawler compartido                                      │
│  ├─ Plugins recon / web / api / llm                         │
│  └─ Persistencia y deduplicación                            │
├─────────────────────────────────────────────────────────────┤
│ IntelService (KEV · EPSS · NVD · OSV · bundles offline)     │
├─────────────────────────────────────────────────────────────┤
│ ToolService                                                 │
│  ├─ backend remote  → tools-runner (HTTP interno)           │
│  ├─ backend docker  → contenedor efímero                    │
│  └─ backend local   → binarios en PATH                      │
├─────────────────────────────────────────────────────────────┤
│ SQLite + SQLAlchemy + Alembic                               │
└─────────────────────────────────────────────────────────────┘
```

## Flujo de un análisis

```
POST /scans
  → valida autorización y alcance
  → crea ScanRun (pending)
  → ScanManager.start()
      → ScanContext.create()  (cliente httpx, scope, rate limit)
      → resuelve base URL https/http
      → build_baseline()      (catch-all / soft-404)
      → Crawler.crawl()       (endpoints, forms, JS)
      → plugins en paralelo (semáforo)
          → Finding
          → normalización + fingerprint
          → upsert con deduplicación
          → evento SSE al panel
      → stats + logs + estado final
```

## Modelo de datos

| Tabla | Propósito |
|---|---|
| `workspaces` | Proyecto, cliente, alcance, autorización y flags de explotación |
| `targets` | Activos, tecnologías, puertos y metadatos |
| `scan_runs` | Ejecuciones, perfil, opciones, estado, estadísticas y logs |
| `findings` | Hallazgos deduplicados, CVSS, CWE, OWASP, confianza, estado, evidencia, KEV/EPSS |
| `reports` | Entregables generados y metadatos |
| `exploit_runs` | Ejecuciones de explotación controlada, payload, salida y evidencia |
| `audit_log` | Acciones sensibles |
| `intel_feeds` | Estado de KEV, EPSS, NVD y OSV |
| `cves` | Caché local de vulnerabilidades |
| `asset_intel` | Correlación activo ↔ CVE |

Un hallazgo se identifica por `workspace_id + fingerprint`, donde el fingerprint combina plugin, título, endpoint, host y parámetro. Así se evita duplicar el mismo resultado en scans sucesivos sin perder el histórico (`occurrences`).

## Scope guard

`ScopeConfig` es **fail-closed**: sin dominios o rangos explícitos no se autoriza nada. `AsyncHTTPClient` valida cada URL antes de enviarla y lanza `ScopeViolation` si queda fuera. Los targets añadidos al proyecto actualizan automáticamente el alcance con su host (sin puerto).

## Baseline y falsos positivos

`http/baseline.py` solicita rutas aleatorias y compara estado, longitud, título y similitud de cuerpo. Los plugins de descubrimiento y `.git` solo reportan si el contenido supera Validación específica:

- `.git/HEAD` debe contener una referencia Git real.
- `.git/config` debe contener `[core]`.
- `.env` debe contener pares clave/valor.
- `robots.txt` debe contener directivas.
- `package.json` debe ser JSON con dependencias.

Esto elimina los falsos positivos típicos de aplicaciones SPA que devuelven HTTP 200 para cualquier ruta.

## Inteligencia

- **KEV**: descarga del catálogo CISA y actualización de `cves`.
- **EPSS**: descarga del CSV diario y actualización de scores.
- **NVD**: consulta bajo demanda para detalle técnico.
- **CPE 2.3**: las tecnologías con versión detectadas por `tech_fingerprint` se
  mapean a `cpe:2.3:a:vendor:product:version` y se consultan con
  `virtualMatchString`. Las coincidencias se guardan en `asset_intel` con
  confianza alta; si no hay versión mapeable o NVD no responde, se usa el índice
  local por palabra clave con confianza baja.
- **OSV**: consulta por ecosistema/paquete/versión desde supply chain.
- **OpenAPI/Swagger**: detecta especificaciones expuestas, registra el hallazgo y añade sus rutas al contexto del análisis.
- **Frescura**: ETag/Last-Modified por feed, última y próxima sincronización,
  error y marca de desactualizado.
- **Offline**: exportación/importación de bundles JSON con firma Ed25519
  separada (`.sig`), verificación con clave pública y opción de exigir firma.

## Explotación controlada

`ExploitationService` es el único punto de entrada. Antes de ejecutar un módulo comprueba:

1. Que el proyecto tenga `allow_exploitation=True`.
2. Que el hallazgo no esté marcado como falso positivo.
3. Que el operador escriba `EXPLOTAR`.
4. Que el endpoint siga dentro del scope.
5. Que el módulo esté mapeado al plugin del hallazgo.

Cada ejecución se registra en `exploit_runs` y en el audit log. `exploit/trace.py` captura cada petición y respuesta en un contextvar, y `services/evidence.py` genera la justificación, los comandos de reproducción y el hash SHA-256. La evidencia se muestra en el panel, se exporta en Markdown/JSON e incluye **credenciales, contraseñas, hashes, tokens y accesos** demostrados. Los módulos incluidos son pruebas de concepto reversibles y de solo lectura: fingerprint SQL, canario XSS, lectura LFI, `id`/`whoami` para RCE, `7*7` para SSTI, metadata cloud/loopback para SSRF y redirección canario para open redirect.

`ExploitationService` delega la ejecución en `exploit/runners.py`:

| Backend | Ejecución | Aislamiento |
|---|---|---|
| `docker` | `docker run --rm -i ...` desde el panel nativo | Hijo efímero, `/tmp` tmpfs, usuario 10002, sin volúmenes ni socket |
| `runner` | `POST http://exploit-runner:8090/run` | El controlador lanza el mismo hijo efímero; único con socket |
| `local` | En proceso | Solo desarrollo; no aísla |

El contenedor hijo recibe un JSON compacto por `stdin` (módulo, endpoint, finding y opciones), ejecuta `exploit/container_runner.py` y escribe un único JSON por `stdout` con `success`, `output`, `error`, `evidence`, `trace`, `credentials` y `access`. No tiene base de datos, token, volumen ni socket. `exploit/artifacts.py` extrae únicamente esos artefactos; el panel los guarda en la evidencia y los muestra en la ficha de la ejecución.

`exploit/runner_api.py` es el controlador del stack Compose. Valida el token y el módulo, y lanza un contenedor de un solo uso con `--read-only`, `--cap-drop ALL`, `no-new-privileges`, CPU/memoria/PIDs limitados y sin volúmenes.

`services/playbooks.py` cubre los hallazgos sin módulo automático con una validación guiada: pasos, herramientas y límites. Distingue plugins que ya hicieron pruebas activas (`auth_bypass`, `jwt`), validaciones manuales de alto riesgo (smuggling, deserialización, race conditions) y hallazgos informativos. Los módulos LFI/RCE añaden post-explotación de solo lectura para demostrar acceso y extraer configuración, sin persistencia ni escalada.

## Herramientas reales

`ToolService` valida `allow_exploitation`, confirmación tipada, scope y mapeo
plugin→herramienta. Después delega en uno de tres backends:

| Backend | Ejecución | Aislamiento |
|---|---|---|
| `remote` | `POST http://tools-runner:8080/run` | Contenedor Kali sin privilegios, red interna, token |
| `docker` | `docker run --rm ...` | Contenedor efímero con `--cap-drop ALL`, `no-new-privileges`, CPU/memoria y `/work` |
| `local` | Subproceso en el host | Sin aislamiento; solo desarrollo/laboratorio |

El `tools-runner` (`tools/runner_api.py`) es un servicio FastAPI independiente
del panel. Solo expone `GET /healthz` y `POST /run`, autentica con
`MTB_TOOLS_TOKEN`, aplica una allowlist de herramientas y flags, valida el
objetivo y ejecuta sin shell. Devuelve salida, código de retorno, duración y
estado de truncado; la clasificación de evidencia se hace en el panel
(`tools/base.py`) para que los tres backends apliquen las mismas reglas.

El stack `docker compose` levanta `panel`, `tools-runner` y `exploit-runner`. El
panel no tiene Docker CLI ni monta `/var/run/docker.sock`; el `tools-runner` no
publica puertos y corre con rootfs de solo lectura excepto `/work` y `/tmp`
(tmpfs). El `exploit-runner` es el único con el socket, solo lanza contenedores
hijos efímeros y no ejecuta el módulo en su propio proceso.

Herramientas: sqlmap, nuclei, commix, whatweb, nikto, nmap, ffuf, gobuster y hydra.

## Portabilidad

- `AppPaths` resuelve datos, configuración, informes, logs, caché y token.
- `--portable` guarda todo en `./data`.
- Docker Compose guarda todo en `./mtb-data` (`/data` dentro del panel) y no
  requiere Python/uv en el host.
- SQLite usa journal `DELETE` en modo portable para evitar problemas en USB/red.
- El cliente HTTP, los feeds y el panel no dependen de servicios externos.
- Los binarios se generan con PyInstaller en CI para macOS, Linux y Windows.
- Docker usa WeasyPrint para PDF; el binario local usa Chrome/Edge si está disponible y cae a HTML si no.

## Seguridad del panel

- Escucha en `127.0.0.1` por defecto.
- Token aleatorio en `panel.token` (0600) y cookie `HttpOnly`, `SameSite=Strict`.
- CSRF en formularios y acciones de escritura.
- CSP, `X-Frame-Options`, `nosniff` y `Referrer-Policy`.
- Sin telemetría.
- Modo remoto solo con `--host` explícito; si se desactiva auth se avisa por consola.
