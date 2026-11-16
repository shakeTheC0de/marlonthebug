# MarlonTheBug 2.0 — Plan y estado

## Estado actual

| Fase | Estado | Entregado |
|---|---|---|
| 0. Saneamiento | ✅ | Repo privado, `.gitignore`, datos sensibles fuera de Git, CI, ruff limpio |
| 1. Persistencia | ✅ | SQLite, SQLAlchemy async, Alembic, repositorio, deduplicación, audit log |
| 2. Panel web | ✅ | FastAPI + Jinja, dashboard, proyectos, activos, scans, hallazgos, triaje |
| 3. Informes | ✅ | PDF/HTML/Markdown/JSON, plantillas ES/EN, evidencia, CVSS, CWE, OWASP |
| 4. Fiabilidad | ✅ | Scope guard fail-closed, baseline/soft-404, HTTP compartido, rate limit, dedupe |
| 5. Inteligencia | ✅ | CISA KEV, EPSS, NVD, OSV, caché local, bundles offline |
| 6. Módulos modernos | ✅ | JWT, OAuth, BOLA/IDOR, mass assignment, GraphQL, prototype pollution, cache poisoning, supply chain, cloud dashboards, CI/CD, LLM |
| 7. Portabilidad | ✅ | `--portable`, datos fuera del repo, Docker, PyInstaller en CI, README |
| 8. Explotación controlada | ✅ | SQLi, XSS, LFI, RCE, SSTI, SSRF, open redirect; confirmación tipada, evidencia y audit log |
| 9. Herramientas Docker | ✅ | Imagen Kali con sqlmap, nuclei, commix, whatweb, nikto, nmap; ejecución aislada y conectada al panel |

## Principios

1. **Local-first**: sin servicios externos obligatorios.
2. **Evidencia antes que volumen**: un hallazgo sin validación no se reporta como crítico.
3. **Scope fail-closed**: nada sale sin autorización explícita.
4. **Datos fuera del código**: informes, workspaces, logs y BD nunca se versionan.
5. **Informes accionables**: severidad, CVSS, CWE, OWASP, evidencia, remediación y KEV/EPSS.

## Próximos pasos recomendados

- Implementar el stack Docker portable panel + tools-runner descrito en `docs/ROADMAP_NEXT.md`.
- Mejorar la correlación de inteligencia por CPE y versiones.
- Añadir autenticación multiusuario opcional para despliegues en servidor.
- Firmar los bundles de inteligencia con Ed25519.
- Añadir retest automatizado y comparación de informes entre ejecuciones.
- Empaquetar una app de escritorio (Tauri) si se quiere una experiencia sin navegador.

## Criterios de calidad

- `ruff check` y `ruff format --check` en verde.
- Tests en macOS, Linux y Windows con Python 3.12 y 3.13.
- Cobertura de persistencia, panel, informes, scope, baseline y detectores clave.
- Migraciones Alembic reproducibles.
- Binarios y wheel generados en cada release.
