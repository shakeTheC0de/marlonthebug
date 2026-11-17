# Aprender construyendo: sistema operativo + CPTS + CTF

Este proyecto tiene dos pistas que se alimentan entre sí:

1. **Construir una distro Linux funcional y personal.**
2. **Usarla para aprender seguridad ofensiva, CPTS y CTF.**

La distro no es un fin aislado: es tu laboratorio, tu estación de trabajo y el
entregable que puedes enseñar.

## Pista A — Construir el sistema

### Fase 1: Linux y Debian

- Procesos, systemd, permisos, usuarios, paquetes, repositorios y logs.
- `apt`, `dpkg`, `systemd`, `journalctl`, `ssh`, `ufw`, `cron`, `fstab`.
- Documentación: Debian Administrator's Handbook.

### Fase 2: live-build

- Cómo se construye una ISO live: `debootstrap`, chroot, paquetes, hooks,
  squashfs, initramfs y bootloader.
- `distro/build.sh`, `auto/config`, `kali-config/variant-marlonthebug/`.
- Ejercicio: cambia un paquete, un hook o el fondo y reconstruye.
- Documentación: live-build manual y Kali “Live Build a Custom Kali ISO”.

### Fase 3: escritorio y producto

- Xfce, autostart, menú, iconos, temas, idioma, teclado y aplicaciones.
- Instalador a disco, persistencia, LUKS, Secure Boot y actualizaciones.
- Ejercicio: crea una variante con KDE o GNOME y compara tamaño/rendimiento.
- Ejercicio: firma la ISO, publica checksums y un workflow de release.

### Fase 4: CI/CD y release

- GitHub Actions, artefactos, versionado, builds reproducibles y pruebas en VM.
- Ejercicio: ISO en tag `v*`, changelog y descarga desde Releases.

## Pista B — CPTS y CTF

### Fundamentos

- Redes: TCP/IP, DNS, HTTP, TLS, proxies, VPN.
- Linux y Windows: permisos, servicios, AD, Kerberos, SMB, LDAP.
- Web: OWASP Top 10, APIs, autenticación, autorización, JWT, SSRF, SQLi, XSS.
- Metodología: alcance, enumeración, hipótesis, evidencia, impacto, remediación.

### CPTS (Hack The Box)

La ruta CPTS cubre, entre otras áreas:

- Enumeración de red y servicios.
- Web y APIs.
- Active Directory: enumeración, Kerberos, ACLs, delegación, ADCS.
- Pivoting y túneles.
- Privilege escalation Linux/Windows.
- Reporting profesional.

Herramientas incluidas en la distro:

| Área | Herramientas |
|---|---|
| Web/API | Burp Suite, ffuf, feroxbuster, gobuster, nuclei, sqlmap |
| AD/Windows | BloodHound, Neo4j, Impacket, NetExec, enum4linux-ng, Certipy, Responder, mitm6, Evil-WinRM |
| Pivoting | Chisel, Ligolo-ng, Proxychains, socat, OpenVPN, WireGuard |
| Passwords | Hashcat, John, Hydra |
| CTF/reversing | GDB, Radare2, Ghidra, Binwalk, Foremost, Steghide, exiftool, pwntools |
| Red | nmap, tcpdump, Wireshark/tshark, dnsutils, traceroute |

Práctica recomendada:

1. Completa los módulos de HTB Academy en orden.
2. Haz las máquinas retiradas de HTB y escribe un writeup por máquina.
3. Monta un AD de práctica (GOAD/VulnAD o el lab de CPTS) y documenta cada
   ataque y su detección.
4. Practica el examen con un objetivo cronometrado y un informe final.

### CTF

- Web, crypto, reversing, pwn, forensics, stego, OSINT y misc.
- Usa la distro para notes, screenshots, scripts y evidencias.
- Guarda cada reto en `~/notas/ctf/<evento>/<reto>/` con:
  - enunciado, hipótesis, comandos, flags, tiempo y aprendizajes.

## Cómo encaja MarlonTheBug

- **Panel**: proyectos, activos, hallazgos, evidencia, informes y remediación.
- **Herramientas**: ejecución directa contra un objetivo autorizado.
- **Laboratorio**: Juice Shop, WebGoat y Kali/Metasploit aislados.
- **Live USB**: escritorio con notas, navegador, apps y herramientas.
- **CTF/CPTS**: notes + terminal + herramientas + writeups en el mismo sistema.

## Plan de 6 semanas

| Semana | Sistema | Seguridad |
|---|---|---|
| 1 | Linux, systemd, apt, logs | Redes y HTTP; laboratorio |
| 2 | live-build, chroot, hooks | Enumeración y web |
| 3 | escritorio, apps, autostart | APIs, JWT, authz |
| 4 | persistencia, LUKS, instalador | Linux privesc y pivoting |
| 5 | CI, release, firma | Active Directory y ADCS |
| 6 | pulido y documentación | CTF y simulación de informe CPTS |

## Reglas de trabajo

- Practica solo en tus sistemas o en labs con autorización.
- Documenta antes de explotar: alcance, hipótesis, evidencia, impacto.
- En producción, usa pruebas de solo lectura y restauración.
- No añadas malware, mineros, persistencia ofensiva ni payloads destructivos al
  sistema que distribuyes.
- Guarda writeups y evidencias; el informe es parte de la habilidad.
