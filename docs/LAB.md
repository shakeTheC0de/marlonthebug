# Laboratorio de práctica

Entorno desechable para ejecutar herramientas reales y frameworks establecidos
sin tocar producción. No forma parte del stack del panel.

```
docker compose -f docker-compose.lab.yml up -d juice-shop webgoat
docker compose -f docker-compose.lab.yml run --rm lab-tools
```

| Servicio | Acceso | Contenido |
|---|---|---|
| Juice Shop | `http://127.0.0.1:3000` | OWASP Juice Shop |
| WebGoat | `http://127.0.0.1:8080/WebGoat` | OWASP WebGoat |
| lab-tools | consola interactiva | Kali + Metasploit + nmap/sqlmap/ffuf/nikto/nuclei/commix |

Los puertos están publicados solo en `127.0.0.1`. Los contenedores del
laboratorio usan la red `marlonthebug-lab_lab`, separada del panel.

## Uso básico

Dentro de `lab-tools`:

```bash
nmap -Pn -sV -p 3000,8080 juice-shop webgoat
curl -I http://juice-shop:3000
curl -I http://webgoat:8080/WebGoat/

ffuf -u http://juice-shop:3000/FUZZ -w /opt/mtb/wordlists/common.txt \
  -mc 200,204,301,302,307,401,403 -t 10 -rate 10

sqlmap -u "http://juice-shop:3000/rest/products/search?q=test" \
  --batch --level=1 --risk=1

msfconsole
```

Metasploit está instalado en `lab-tools`. Úsalo únicamente contra los servicios
del laboratorio. El objetivo es practicar, documentar y detectar; no apuntes
payloads ni frameworks a producción desde este entorno.

## Conectar el panel al laboratorio

El panel corre en otra red. Desde sus contenedores, los puertos publicados del
laboratorio se alcanzan con `host.docker.internal` (Docker Desktop y el stack
Compose ya lo configuran con `host-gateway`).

```bash
# Proyecto de laboratorio en el panel
docker compose exec -T panel marlonthebug workspace create --name lab
docker compose exec -T panel marlonthebug workspace add \
  --name lab --domains host.docker.internal

# Herramienta directa contra Juice Shop
docker compose exec -T panel marlonthebug tools target \
  --workspace lab \
  --target http://host.docker.internal:3000 \
  --tool ffuf \
  --confirm-text EXPLOTAR

# Análisis safe del laboratorio
docker compose exec -T panel marlonthebug scan run \
  --workspace lab \
  --targets host.docker.internal:3000,host.docker.internal:8080 \
  --categories recon,web \
  --profile safe \
  --authorized
```

## Reset

```bash
# Parar y eliminar el laboratorio (los datos de las apps son desechables)
docker compose -f docker-compose.lab.yml down -v

# Volver a levantar limpio
docker compose -f docker-compose.lab.yml up -d juice-shop webgoat
```

## Límites

- El laboratorio es para pruebas autorizadas y desechables.
- No se debe conectar a bases de datos, APIs ni servicios de producción.
- Para probar técnicas destructivas, hazlo aquí y restaura el laboratorio
  después; no en el entorno real.
- MarlonTheBug mantiene sus módulos de explotación controlada y su ejecución en
  contenedores efímeros. El laboratorio es el sitio para las herramientas y
  frameworks de propósito general.
