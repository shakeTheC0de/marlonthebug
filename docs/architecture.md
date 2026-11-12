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
- **OSV**: consulta por ecosistema/paquete/versión desde supply chain.
- **Offline**: exportación/importación de bundles JSON.

## Portabilidad

- `AppPaths` resuelve datos, configuración, informes, logs, caché y token.
- `--portable` guarda todo en `./data`.
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
