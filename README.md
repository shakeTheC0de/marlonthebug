# MarlonTheBug

**Panel local de auditoría de seguridad y generación de informes.**

MarlonTheBug reúne reconocimiento, detección de vulnerabilidades, triaje,
inteligencia de CVE y reporting en una aplicación que se ejecuta en tu equipo.
No usa CDN, telemetría ni servicios obligatorios en la nube.

> Uso exclusivo sobre sistemas propios o con autorización escrita. Cada acción
> queda registrada en el log de auditoría.

## Qué incluye

- Panel web local con proyectos, activos, análisis, hallazgos, triaje e informes.
- Módulos de reconocimiento, web, API, cloud, CI/CD y LLM.
- CLI para automatizar análisis, informes, backups y tareas de laboratorio.
- Persistencia SQLite con deduplicación e histórico por proyecto.
- Informes ejecutivos y técnicos en PDF, HTML, Markdown y JSON.
- Inteligencia de vulnerabilidades: CISA KEV, EPSS, NVD y OSV con caché local.
- Explotación controlada y aislada en contenedores efímeros, con evidencia.
- Stack Docker opcional: panel, tools-runner y exploit-runner.
- Dos imágenes live basadas en Arch Linux: privacidad y auditoría.
- Modo portable para guardar todos los datos en una carpeta o USB.

## Inicio rápido

Con `uv`:

```bash
uv tool install git+https://github.com/shakeTheC0de/marlonthebug
marlonthebug panel
```

Con `pipx`:

```bash
pipx install git+https://github.com/shakeTheC0de/marlonthebug
marlonthebug panel
```

Desde el código:

```bash
git clone https://github.com/shakeTheC0de/marlonthebug
cd marlonthebug
uv sync
uv run marlonthebug panel
```

El panel abre `http://127.0.0.1:8765` con un token local. También puedes
consultar la URL y el token con:

```bash
marlonthebug config
```

## Docker Compose

El stack incluye panel, tools-runner y exploit-runner. El panel no monta el
socket de Docker.

```bash
git clone https://github.com/shakeTheC0de/marlonthebug
cd marlonthebug
./scripts/install.sh
docker compose up -d
docker compose logs -f panel
./scripts/backup.sh
```

Guía completa: [`docs/DOCKER.md`](docs/DOCKER.md).

## Imágenes live

La carpeta [`distro/`](distro/README.md) construye dos imágenes con **Arch Linux
+ archiso**:

| Imagen | Uso | Red |
|---|---|---|
| `mtb-privacy` | Sesión privada, amnésica, sin persistencia | Solo Tor |
| `mtb-audit` | Auditoría, CPTS y CTF | Directa |

La imagen de privacidad incluye Xfce y Tor Browser, bloquea la salida directa
con nftables, desactiva IPv6 y aleatoriza MAC, hostname y machine-id. La imagen
de auditoría incluye Xfce y KDE, el panel, herramientas de seguridad y
`archinstall`.

El build de las ISOs requiere un host Linux o el workflow de GitHub Actions.
Consulta [`distro/archiso/README.md`](distro/archiso/README.md) para el flujo
completo, las pruebas, los límites y las instrucciones de grabación.

## CLI

```bash
marlonthebug --help
marlonthebug panel --help

marlonthebug workspace create --name demo --client "Demo"
marlonthebug workspace add --name demo --domains "example.com,api.example.com"
marlonthebug scan run --workspace demo --categories recon,web --profile safe --authorized
marlonthebug report generate --workspace demo --format pdf --template full

marlonthebug intel sync
marlonthebug intel search CVE-2021-44228
marlonthebug intel export --output intel-bundle.json

marlonthebug tools status
marlonthebug tools target --workspace demo --target https://app.example.com --tool nmap --confirm-text EXPLOTAR
marlonthebug backup --output ~/backups/demo.tar.gz
marlonthebug restore ~/backups/demo.tar.gz --data-dir ./mtb-data --force
```

Las herramientas solo se ejecutan contra objetivos dentro del alcance y con
confirmación explícita.

## Datos y configuración

Por defecto los datos se guardan fuera del código. En Linux:

```text
~/.local/share/marlonthebug
```

Con `--portable` o `--data-dir` todo se guarda en la ruta indicada:

```bash
marlonthebug panel --portable
# ./data/marlonthebug.db
# ./data/reports/
# ./data/feeds/
```

Variables útiles:

```bash
MARLONTHEBUG_DATA_DIR=/ruta/datos
MARLONTHEBUG_HOST=127.0.0.1
MARLONTHEBUG_PORT=8765
MARLONTHEBUG_OFFLINE=1
NVD_API_KEY=...
```

El token del panel se guarda en el directorio de datos (`panel.token`). No lo
compartas ni lo subas a Git.

## Seguridad y límites

- El panel escucha en `127.0.0.1` por defecto.
- El scope es obligatorio antes de ejecutar herramientas.
- La explotación se habilita por proyecto y requiere confirmación tipada.
- En Docker, el panel no tiene acceso al socket; el exploit-runner lanza
  contenedores hijos efímeros.
- La imagen de privacidad no sustituye a Tails ni garantiza anonimato frente a
  hardware, firmware o exploits del navegador.
- La imagen de auditoría usa red directa y no ofrece anonimato.
- No se incluyen mineros, malware, persistencia ofensiva ni payloads
  destructivos.

## Estructura

```text
marlonthebug/       aplicación, panel, CLI, plugins y servicios
config/             configuración por defecto
distro/             imágenes live Arch Linux
docs/               manual, Docker, laboratorio y arquitectura
scripts/            instalación, backup, restore y laboratorio
tests/              pruebas automatizadas
```

## Documentación

- [Guía de Docker](docs/DOCKER.md)
- [Manual de usuario](docs/USER_MANUAL.md)
- [Laboratorio](docs/LAB.md)
- [Arquitectura](docs/architecture.md)
- [Imágenes live](distro/archiso/README.md)
- [Roadmap](docs/ROADMAP.md)

## Licencia

MIT. Consulta [`LICENSE`](LICENSE).
