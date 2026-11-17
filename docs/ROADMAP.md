# Roadmap

## Hecho

- Panel web local con proyectos, activos, análisis, hallazgos e informes.
- Persistencia SQLite, deduplicación, evidencia y audit log.
- Informes PDF, HTML, Markdown y JSON.
- Inteligencia KEV, EPSS, NVD y OSV con caché y bundles firmados.
- Explotación controlada en contenedores efímeros.
- Stack Docker con panel, tools-runner y exploit-runner.
- Laboratorio Juice Shop, WebGoat y Kali/Metasploit.
- Imágenes live `mtb-privacy` y `mtb-audit` con Arch Linux + archiso.
- Build de ISOs en GitHub Actions.

## Siguiente

- Probar las dos ISOs en hardware real: UEFI, BIOS, Wi-Fi, Ethernet y teclado.
- Añadir puentes Tor y un modo explícito para portales cautivos.
- Instalador propio que conserve el panel y permita cifrado LUKS.
- Persistencia cifrada opcional para la imagen de auditoría.
- Sustituir `archinstall` por un perfil de instalación propio.
- Diseñar el branding definitivo: arranque, login, escritorio, iconos y welcome.
- Ampliar la cobertura de herramientas de Active Directory y pivoting.
- Documentar un flujo de aprendizaje con CPTS y CTF fuera del repositorio.

## Criterios de calidad

- `ruff`, `mypy` y `pytest` en verde.
- Sin secretos, tokens, rutas personales ni datos de clientes en el repositorio.
- Builds de ISO reproducibles en Linux/CI.
- Pruebas de arranque y de red documentadas antes de publicar una release.
