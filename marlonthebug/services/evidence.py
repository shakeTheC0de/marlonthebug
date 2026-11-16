"""Human-readable justification and evidence documents for exploitation runs."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from marlonthebug.exploit.trace import curl_commands, evidence_hash


def build_justification(
    *,
    finding: Any,
    module_key: str,
    risk: str,
    status: str,
    trace_steps: list[dict[str, Any]],
    output: str,
    operator: str,
    workspace: Any,
) -> dict[str, Any]:
    evidence = getattr(finding, "evidence", {}) or {}
    parameter = evidence.get("parameter") if isinstance(evidence, dict) else ""
    detected_payload = evidence.get("payload") if isinstance(evidence, dict) else ""
    return {
        "finding": {
            "id": getattr(finding, "id", ""),
            "title": getattr(finding, "title", ""),
            "plugin": getattr(finding, "plugin_name", ""),
            "severity": getattr(finding, "severity", ""),
            "cvss": getattr(finding, "cvss_score", 0),
            "cvss_vector": getattr(finding, "cvss_vector", ""),
            "cwe": getattr(finding, "cwe", ""),
            "owasp": getattr(finding, "owasp", ""),
            "endpoint": getattr(finding, "endpoint", ""),
            "target": getattr(finding, "target_host", ""),
            "parameter": parameter,
            "detected_payload": detected_payload,
            "kev": getattr(finding, "kev", False),
            "epss": getattr(finding, "epss", 0),
        },
        "authorization": {
            "workspace": getattr(workspace, "name", ""),
            "workspace_id": getattr(workspace, "id", ""),
            "allow_exploitation": getattr(workspace, "allow_exploitation", False),
            "scope": getattr(workspace, "scope", {}),
            "operator": operator,
            "confirmation": "EXPLOTAR",
            "authorized_use": "Solo sistemas propios o con autorización escrita",
        },
        "method": {
            "module": module_key,
            "risk": risk,
            "status": status,
            "steps": len(trace_steps),
            "http_steps": sum(1 for step in trace_steps if step.get("phase") == "http_request"),
        },
        "result": {
            "status": status,
            "summary": (output or "")[:1500],
        },
        "impact": {
            "severity": getattr(finding, "severity", ""),
            "cvss": getattr(finding, "cvss_score", 0),
            "cwe": getattr(finding, "cwe", ""),
            "owasp": getattr(finding, "owasp", ""),
            "remediation": getattr(finding, "remediation", ""),
            "description": getattr(finding, "description", ""),
        },
        "reproduction": {
            "curl": curl_commands(trace_steps),
            "note": "Sustituye los valores redactados por los de tu entorno autorizado.",
        },
    }


def extract_highlights(evidence: dict[str, Any]) -> list[str]:
    highlights: list[str] = []
    for key in ("matches", "matched"):
        value = evidence.get(key)
        if isinstance(value, list) and value:
            highlights.append(f"{key}: {', '.join(str(item) for item in value[:8])}")
    for key in (
        "technique",
        "engine",
        "parameter",
        "payload",
        "expected",
        "test_url",
        "ssrf_target",
        "location",
        "status",
        "reflected",
        "rendered",
        "response_snippet",
    ):
        value = evidence.get(key)
        if value not in (None, "", [], {}):
            highlights.append(f"{key}: {str(value)[:400]}")
    if credentials := evidence.get("credentials"):
        highlights.append(f"credenciales obtenidas: {len(credentials)}")
    if access := evidence.get("access"):
        highlights.append(f"accesos obtenidos: {len(access)}")
    return highlights[:15]


def finalize_evidence(
    evidence: dict[str, Any],
    justification: dict[str, Any],
    trace_steps: list[dict[str, Any]],
) -> dict[str, Any]:
    payload = {
        **evidence,
        "trace": trace_steps,
        "justification": justification,
    }
    payload["integrity"] = {
        "algorithm": "sha256",
        "hash": evidence_hash(payload),
        "generated_at": datetime.now().astimezone().isoformat(),
    }
    return payload


def to_markdown(run: Any) -> str:
    evidence = run.evidence or {}
    justification = evidence.get("justification", {})
    finding = justification.get("finding", {})
    authorization = justification.get("authorization", {})
    impact = justification.get("impact", {})
    reproduction = justification.get("reproduction", {})
    integrity = evidence.get("integrity", {})
    steps = evidence.get("trace", [])
    lines = [
        f"# Evidencia de explotación — {run.module_name}",
        "",
        f"**Estado:** {run.status}",
        f"**Riesgo:** {run.risk}",
        f"**Operador:** {run.operator}",
        f"**Inicio:** {_fmt(run.started_at)}",
        f"**Fin:** {_fmt(run.finished_at)}",
        f"**Hash de evidencia:** `{integrity.get('hash', '—')}`",
        "",
        "## 1. Hallazgo justificado",
        "",
        f"- **Título:** {finding.get('title', '—')}",
        f"- **Plugin:** {finding.get('plugin', '—')}",
        f"- **Severidad:** {finding.get('severity', '—')}",
        f"- **CVSS:** {finding.get('cvss', 0)} `{finding.get('cvss_vector', '')}`",
        f"- **CWE / OWASP:** {finding.get('cwe', '—')} / {finding.get('owasp', '—')}",
        f"- **Objetivo:** `{finding.get('target', '—')}`",
        f"- **Endpoint:** `{finding.get('endpoint', '—')}`",
        f"- **Parámetro:** `{finding.get('parameter', '—')}`",
        f"- **Payload detectado:** `{finding.get('detected_payload', '—')}`",
        f"- **KEV:** {'Sí' if finding.get('kev') else 'No'} · **EPSS:** {finding.get('epss', 0)}",
        "",
        "## 2. Autorización y alcance",
        "",
        f"- **Proyecto:** {authorization.get('workspace', '—')}",
        f"- **Explotación habilitada:** {'Sí' if authorization.get('allow_exploitation') else 'No'}",
        f"- **Operador:** {authorization.get('operator', '—')}",
        f"- **Confirmación:** {authorization.get('confirmation', '—')}",
        f"- **Alcance:** `{json.dumps(authorization.get('scope', {}), ensure_ascii=False)}`",
        "",
        "## 3. Proceso paso a paso",
        "",
    ]
    for step in steps:
        if step.get("phase") == "http_request":
            lines += [
                f"### Paso {step.get('index')} — {step.get('method')} {step.get('url')}",
                "",
                f"- **Hora:** {step.get('at')}",
                f"- **Estado HTTP:** {step.get('status', '—')}",
                f"- **Duración:** {step.get('elapsed', '—')} s",
                f"- **Longitud:** {step.get('content_length', '—')}",
                "",
                "**Cabeceras de petición:**",
                "```http",
                *(f"{key}: {value}" for key, value in (step.get("request_headers") or {}).items()),
                "```",
            ]
            if step.get("request_body"):
                lines += ["**Cuerpo de petición:**", "```", str(step["request_body"]), "```"]
            lines += [
                "**Respuesta (fragmento):**",
                "```http",
                str(step.get("response_snippet", ""))[:1500],
                "```",
                "",
            ]
        elif step.get("phase") in {"docker", "tool", "remote", "local"}:
            backend = step.get("backend", step.get("phase", "tool"))
            lines += [
                f"### Paso {step.get('index')} — {str(backend).capitalize()} / {step.get('tool', 'herramienta')}",
                "",
                f"- **Comando:** `{step.get('command', '')}`",
                f"- **Return code:** {step.get('returncode', '—')}",
                f"- **Duración:** {step.get('duration', '—')} s",
                "",
            ]
        elif step.get("message"):
            lines += [f"### Paso {step.get('index')} — {step.get('phase')}", "", step.get("message", ""), ""]
    highlights = evidence.get("highlights", [])
    lines += [
        "## 4. Resultado",
        "",
    ]
    if highlights:
        lines += ["**Hallazgos clave:**", ""]
        lines += [f"- `{item}`" for item in highlights]
        lines += [""]
    lines += [
        "```",
        str(run.output or run.error or "Sin salida")[:5000],
        "```",
        "",
    ]
    credentials = evidence.get("credentials", [])
    access = evidence.get("access", [])
    if credentials or access:
        lines += [
            "## 5. Credenciales y accesos obtenidos",
            "",
            "> Material sensible. El contenedor efímero solo exportó estos artefactos, no su estado.",
            "",
        ]
        if credentials:
            lines += [
                "**Credenciales y secretos:**",
                "",
                "| Tipo | Usuario | Secreto | Host | Módulo |",
                "|---|---|---|---|---|",
            ]
            for item in credentials:
                lines.append(
                    "| {type} | {username} | {secret} | {host} | {module} |".format(
                        type=_cell(item.get("type", "")),
                        username=_cell(item.get("username", "")),
                        secret=_cell(item.get("password") or item.get("value") or ""),
                        host=_cell(item.get("host") or item.get("target") or ""),
                        module=_cell(item.get("module", "")),
                    )
                )
            lines.append("")
        if access:
            lines += [
                "**Accesos:**",
                "",
                "| Tipo | Objetivo | Detalle |",
                "|---|---|---|",
            ]
            for item in access:
                lines.append(
                    "| {type} | {target} | {detail} |".format(
                        type=_cell(item.get("type", "")),
                        target=_cell(item.get("target") or item.get("url") or item.get("via") or ""),
                        detail=_cell(
                            item.get("detail")
                            or item.get("username")
                            or item.get("database")
                            or item.get("command")
                            or item.get("payload")
                            or ""
                        ),
                    )
                )
            lines.append("")
    lines += [
        "## 6. Impacto y remediación",
        "",
        f"- **Impacto:** {impact.get('description', '—')}",
        f"- **Remediación:** {impact.get('remediation', '—')}",
        "",
        "## 7. Reproducción",
        "",
    ]
    for command in reproduction.get("curl", []):
        lines += ["```bash", command, "```", ""]
    lines += [
        "## 8. Integridad",
        "",
        f"- **Algoritmo:** {integrity.get('algorithm', 'sha256')}",
        f"- **Hash:** `{integrity.get('hash', '—')}`",
        f"- **Generado:** {integrity.get('generated_at', '—')}",
        "",
        "> Documento generado automáticamente por MarlonTheBug. Uso exclusivo en sistemas autorizados.",
        "",
    ]
    return "\n".join(lines)


def _cell(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")[:300]


def _fmt(value: Any) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value or "—")
