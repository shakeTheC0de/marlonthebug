# MarlonTheBug 2.0 — Manual de usuario

## 1. Arranque

```bash
uv tool install git+https://github.com/shakeTheC0de/marlonthebug
marlonthebug panel
```

El panel abre `http://127.0.0.1:8765` con un token de acceso. Si no se abre solo:

```bash
marlonthebug panel --no-browser
marlonthebug config        # muestra rutas y configuración
cat <directorio-de-datos>/panel.token
```

## 2. Crear un proyecto

1. Entra en **Proyectos → Crear proyecto**.
2. Indica nombre, cliente y descripción.
3. Añade los dominios o IPs autorizados.
4. Revisa el alcance y activa explotación solo si el contrato lo permite.

El scope es fail-closed: un host que no esté en el alcance no recibirá peticiones.

## 3. Lanzar un análisis

**Análisis → Nuevo análisis**:

- Selecciona uno o varios activos.
- Marca las categorías (reconocimiento, web, API, LLM).
- Elige perfil `safe`, `standard` o `deep`.
- Opcionalmente selecciona módulos concretos.
- Confirma la autorización.
- Pulsa **Iniciar análisis**.

La pantalla de detalle muestra logs en vivo por SSE, progreso, peticiones, errores y hallazgos en tiempo real.

## 4. Triaje de hallazgos

En **Hallazgos** puedes:

- Filtrar por severidad, estado, categoría, KEV o búsqueda libre.
- Abrir un hallazgo para ver evidencia, request/response, CVSS, CWE, OWASP y remediación.
- Cambiar el estado a **Confirmado**, **Falso positivo**, **Riesgo aceptado** o **Remediado**.
- Añadir notas internas.
- Exportar a CSV.

Los hallazgos se deduplican automáticamente entre análisis del mismo proyecto.

## 5. Informes

**Informes → Nuevo informe**:

- Elige proyecto y, opcionalmente, un análisis concreto.
- Plantilla **Completa**, **Ejecutiva** o **Técnica**.
- Formato PDF, HTML, Markdown o JSON.
- Idioma español o inglés.
- Cliente, clasificación, logo/empresa e inclusión de evidencia.

El PDF se genera con Chrome/Edge, Playwright o WeasyPrint. Si no hay ninguno disponible, se entrega HTML autocontenido listo para imprimir.

## 6. Inteligencia

**Inteligencia** muestra:

- CVEs en caché.
- Entradas de CISA KEV.
- Scores EPSS.
- Estado, última y próxima sincronización de los feeds (con aviso si están desactualizados).
- Buscador de CVE.

`Sincronizar KEV + EPSS` actualiza la caché con ETag/Last-Modified, de modo que
un feed sin cambios no se descarga de nuevo. Para entornos sin Internet:

```bash
# Equipo conectado
marlonthebug intel keygen --private signing.pem --public signing.pub
marlonthebug intel export --output bundle.json --sign-key signing.pem

# Equipo air-gapped
marlonthebug intel verify bundle.json --public-key signing.pub
marlonthebug intel import bundle.json --signature bundle.json.sig --public-key signing.pub
```

En el panel puedes configurar la ruta de la clave pública y marcar **Exigir
firma Ed25519 al importar bundles**.

## 7. Activos e inteligencia

En **Activos** puedes ver tecnologías, puertos y hallazgos por host. El botón
**Buscar CVEs** correlaciona producto y versión mediante CPE 2.3 contra NVD y
muestra CVSS, KEV, EPSS y confianza. Si la versión no tiene CVEs, no se generan
coincidencias; si no hay versión mapeable, se usa la caché local con confianza
baja.

## 8. Explotación controlada

La explotación se habilita por proyecto. En **Proyectos → Alcance**, activa **Permitir explotación**. Después:

1. Abre un hallazgo con módulo mapeado.
2. En **Explotación controlada**, elige el módulo.
3. Escribe `EXPLOTAR` y ejecuta.
4. Revisa la evidencia en la pantalla de la ejecución.

Los módulos son pruebas de concepto: SQLi de solo lectura, XSS canario, LFI de ficheros de prueba, RCE con `id`/`whoami`, SSTI aritmético, SSRF a metadata/loopback y open redirect canario. No hay shells inversas ni persistencia por defecto. Cada módulo corre en un **contenedor efímero** sin base de datos, volúmenes ni socket; al terminar se elimina y solo devuelve resultado, credenciales/passwords y accesos. La ejecución guarda la traza de peticiones/respuestas, la justificación, los comandos de reproducción y un hash SHA-256. Puedes descargar la evidencia en Markdown o JSON desde la pantalla de la ejecución; la sección **Credenciales y accesos obtenidos** contiene el material sensible exportado.

En el stack Compose el backend es `runner` y el panel delega en `exploit-runner`. En una instalación nativa usa `docker`; solo `local` ejecuta en el proceso del panel y está pensado para desarrollo. Si el backend no está disponible, el panel lo indica y no ejecuta nada.

En el formulario de análisis, **Seleccionar todos** marca todos los módulos; **Limpiar** los desmarca.

## 9. Herramientas reales

El motor admite backend `remote` (tools-runner en Docker Compose), `docker`
(contenedor efímero desde el panel nativo) y `local` (binarios en `PATH`).

```bash
marlonthebug tools status    # comprobar backend, Docker o runner
marlonthebug tools build     # solo backend docker: construir imagen Kali
marlonthebug tools run --finding <id> --tool sqlmap --confirm-text EXPLOTAR
```

En el panel, abre un hallazgo con explotación activada y usa **Herramientas
reales → Ejecutar herramienta**. Herramientas incluidas: sqlmap, nuclei,
commix, whatweb, nikto y nmap.

El contenedor es efímero, sin capacidades extra y con un volumen temporal. En el
stack Compose el panel delega en `tools-runner` por la red interna y no monta el
socket de Docker. Si el motor no está disponible, el panel lo avisa y no ejecuta
nada.

## 10. CLI

```bash
marlonthebug workspace list
marlonthebug workspace add --name acme --domains example.com
marlonthebug scan run --workspace acme --categories recon,web --profile safe --authorized
marlonthebug report generate --workspace acme --format pdf
marlonthebug intel sync
marlonthebug legacy import --reports reports
```

## 11. Datos y backup

Todo vive en el directorio de datos. Usa el backup consistente:

```bash
marlonthebug backup --output ~/backups/marlonthebug.tar.gz
marlonthebug restore ~/backups/marlonthebug.tar.gz --data-dir ~/.local/share/marlonthebug --force
```

Con Docker Compose:

```bash
./scripts/backup.sh
./scripts/restore.sh ./mtb-data/backups/marlonthebug-backup-....tar.gz --force
```

En modo portable:

```bash
marlonthebug panel --portable
# datos en ./data
```

Nunca copies `panel.token` a un repositorio ni lo compartas. Los backups
incluyen ese token: guárdalos cifrados y fuera del equipo si es posible.

## 12. Solución de problemas

| Problema | Solución |
|---|---|
| El token no funciona | Revisa `panel.token` en el directorio de datos; reinicia el panel |
| PDF no se genera | Instala Chrome/Edge, `uv sync --extra pdf` o usa HTML |
| El panel no abre | Comprueba `lsof -i :8765` y cambia `--port` |
| Un análisis falla por scope | Añade el host al proyecto o revisa dominios/IPs |
| No hay CVEs | Sincroniza inteligencia o importa un bundle |
| Base de datos bloqueada | Cierra otras instancias del panel/CLI |
