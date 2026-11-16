"""Guided validation playbooks for findings without an automatic exploit module.

The playbooks are shown in the panel when a finding is informational, already
self-tested by its plugin, or requires a manual/riskier validation. They never
execute automatically.
"""

from __future__ import annotations

from typing import Any

PLAYBOOKS: dict[str, dict[str, Any]] = {
    "openapi": {
        "kind": "guided",
        "title": "Inventario de API expuesto",
        "risk": "medium",
        "summary": (
            "La especificación revela rutas, esquemas y autenticación. El siguiente paso es validar "
            "el control de acceso de cada ruta, no lanzar exploits a ciegas."
        ),
        "steps": [
            "Descarga la especificación y revisa las rutas con seguridad Bearer.",
            "Prueba cada ruta sin token: debe devolver 401/403, nunca datos.",
            "Compara respuestas con un token de un usuario de auditoría autorizado.",
            "Prueba IDOR/BOLA cambiando IDs de households, tareas, ejecuciones e invitaciones.",
            "Prueba mass assignment en perfil, household y tarea con campos no documentados.",
            "Documenta la exposición de Swagger y restringe /api/docs en producción.",
        ],
        "tools": ["ffuf", "nuclei", "sqlmap"],
        "notes": (
            "Para BOLA/IDOR se necesitan dos identidades. Si el registro público está abierto, "
            "solo crea cuentas de auditoría con autorización expresa y limpia los datos al terminar."
        ),
    },
    "endpoint_discovery": {
        "kind": "guided",
        "title": "Validación de endpoint descubierto",
        "risk": "low",
        "summary": "Comprueba manualmente si el recurso expone datos, permite escritura o salta autenticación.",
        "steps": [
            "Revisa método, autenticación y contenido del endpoint.",
            "Prueba GET/POST/OPTIONS y compara con la respuesta sin credenciales.",
            "Busca parámetros ocultos y prueba valores límite.",
            "Comprueba si el recurso debe ser público y añade allowlist/reautenticación.",
        ],
        "tools": ["ffuf", "nuclei"],
    },
    "tech_fingerprint": {
        "kind": "guided",
        "title": "Tecnología y versión detectadas",
        "risk": "low",
        "summary": "La versión puede tener CVEs; valida la versión exacta y el parche antes de asumir impacto.",
        "steps": [
            "Confirma la versión exacta con una petición adicional.",
            "Correlaciona el producto/versión con CPE y NVD desde la ficha del activo.",
            "Revisa si el CVE es explotable en esta configuración.",
            "Aplica el parche o la mitigación del proveedor.",
        ],
        "tools": ["nuclei", "whatweb"],
    },
    "js_analyzer": {
        "kind": "guided",
        "title": "Endpoints y secretos en JavaScript",
        "risk": "medium",
        "summary": "Valida si los endpoints son accesibles sin autenticación y si los secretos siguen activos.",
        "steps": [
            "Prueba los endpoints con y sin sesión.",
            "Comprueba si las claves/tokens son de producción y están activos.",
            "Rota cualquier secreto real y elimínalo del bundle.",
            "Revisa sourcemaps y builds de producción.",
        ],
        "tools": ["ffuf", "nuclei"],
    },
    "auth_bypass": {
        "kind": "self_tested",
        "title": "Pruebas activas de bypass ya ejecutadas",
        "risk": "high",
        "summary": (
            "El plugin ya probó credenciales por defecto, cabeceras de proxy, métodos y variantes de ruta. "
            "Si encontró un bypass, el hallazgo ya incluye la evidencia; no hay un segundo módulo que añada valor."
        ),
        "steps": [
            "Revisa la evidencia del bypass confirmado.",
            "Reproduce solo el vector exacto que funcionó.",
            "Corrige la confianza en X-Forwarded-* y valida autorización en el servidor.",
        ],
        "tools": [],
    },
    "jwt": {
        "kind": "self_tested",
        "title": "Análisis JWT ya ejecutado",
        "risk": "high",
        "summary": (
            "El plugin ya comprobó alg=none, secretos débiles, expiración, kid y jku/x5u. "
            "Si hay un hallazgo crítico, la explotación ya está demostrada en la evidencia."
        ),
        "steps": [
            "Rota el secreto o corrige el algoritmo.",
            "Invalida los tokens afectados.",
            "Añade validación de firma, emisor, audiencia y expiración.",
        ],
        "tools": [],
    },
    "file_upload": {
        "kind": "guided",
        "title": "Validación manual de subida de ficheros",
        "risk": "high",
        "summary": (
            "El detector solo identifica el formulario. La subida automática de un fichero ejecutable "
            "crea estado en el servidor y no se lanza sin autorización expresa."
        ),
        "steps": [
            "Sube un fichero de texto inocuo con nombre único y comprueba si se sirve públicamente.",
            "Prueba extensiones/MIME en un entorno de laboratorio, no en producción.",
            "Nunca subas una web shell a producción.",
            "Aplica allowlist de extensión/MIME, almacenamiento fuera del webroot y rename aleatorio.",
        ],
        "tools": [],
    },
    "cache_poisoning": {
        "kind": "guided",
        "title": "Validación de cache poisoning",
        "risk": "medium",
        "summary": "El hallazgo exige validar reflexión, clave de caché y cacheability real antes de darle severidad.",
        "steps": [
            "Comprueba que el canario se refleja y que la respuesta se cachea.",
            "Repite la petición sin cabecera desde otra sesión/IP.",
            "Verifica que el contenido envenenado afecta a otros usuarios.",
            "Normaliza cabeceras en el edge y excluye respuestas con entrada reflejada.",
        ],
        "tools": [],
    },
    "prototype_pollution": {
        "kind": "guided",
        "title": "Validación de prototype pollution",
        "risk": "medium",
        "summary": "Un sink en un bundle no confirma explotación; hay que demostrar el flujo desde entrada a objeto.",
        "steps": [
            "Localiza el flujo exacto desde location/hash/cookie hasta el sink.",
            "Prueba __proto__/constructor[prototype] en un navegador aislado.",
            "Comprueba si afecta a objetos globales o solo a una copia local.",
            "Bloquea claves peligrosas y evita merges recursivos.",
        ],
        "tools": [],
    },
    "waf_bypass": {
        "kind": "guided",
        "title": "Validación de WAF",
        "risk": "medium",
        "summary": "Confirma qué reglas bloquean y cuáles no, sin enviar payloads destructivos.",
        "steps": [
            "Compara la misma petición con y sin codificación.",
            "Documenta la variante que atraviesa el WAF.",
            "Añade reglas al WAF y valida de nuevo.",
        ],
        "tools": ["nuclei"],
    },
    "request_smuggling": {
        "kind": "manual",
        "title": "Request smuggling: solo laboratorio",
        "risk": "high",
        "summary": "No se automatiza contra producción: puede desincronizar el frontend/backend y afectar a otros usuarios.",
        "steps": [
            "Reproduce únicamente en un entorno de laboratorio aislado.",
            "Documenta la discrepancia Content-Length/Transfer-Encoding.",
            "Corrige la normalización en el proxy y el servidor.",
        ],
        "tools": [],
    },
    "deserialization": {
        "kind": "manual",
        "title": "Deserialización: solo laboratorio",
        "risk": "high",
        "summary": "La explotación puede ejecutar código o corromper estado; requiere un entorno aislado y revisión manual.",
        "steps": [
            "Identifica el formato y la librería exactos.",
            "Valida en laboratorio con un gadget inocuo.",
            "Sustituye la deserialización nativa por JSON firmado/validado.",
        ],
        "tools": [],
    },
    "race_conditions": {
        "kind": "manual",
        "title": "Race condition: validación controlada",
        "risk": "high",
        "summary": "Las pruebas concurrentes pueden crear estados duplicados; no se automatizan en producción.",
        "steps": [
            "Diseña una prueba con límite de concurrencia y datos de auditoría.",
            "Comprueba invariantes y limpieza.",
            "Añade idempotencia, locks o restricciones únicas.",
        ],
        "tools": [],
    },
    "business_logic": {
        "kind": "manual",
        "title": "Lógica de negocio: revisión manual",
        "risk": "medium",
        "summary": "Requiere entender reglas, roles y flujos; no hay un payload genérico seguro.",
        "steps": [
            "Modela el flujo legítimo y sus invariantes.",
            "Prueba saltos de estado, límites y roles.",
            "Documenta el impacto económico o de datos.",
        ],
        "tools": [],
    },
}


def playbook_for(plugin_name: str) -> dict[str, Any] | None:
    return PLAYBOOKS.get(plugin_name)
