"""SSL/TLS configuration analyzer — cipher suites, certificate validation, protocol versions."""

from __future__ import annotations

import contextlib
import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger("marlonthebug.utils.ssl")


@dataclass
class SSLAnalysis:
    host: str
    port: int = 443
    supports_tls_1_0: bool = False
    supports_tls_1_1: bool = False
    supports_tls_1_2: bool = False
    supports_tls_1_3: bool = False
    certificate_valid: bool = False
    certificate_expiry: datetime | None = None
    certificate_issuer: str = ""
    certificate_subject: str = ""
    certificate_san: list[str] = field(default_factory=list)
    hsts_enabled: bool = False
    hsts_max_age: int = 0
    hsts_include_subdomains: bool = False
    hsts_preload: bool = False
    supported_ciphers: list[str] = field(default_factory=list)
    weak_ciphers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


WEAK_CIPHERS = {
    "RC4",
    "DES",
    "3DES",
    "MD5",
    "NULL",
    "anon",
    "EXPORT",
    "RC2",
    "IDEA",
    "SEED",
    "CAMELLIA",
}


def analyze_ssl(host: str, port: int = 443) -> SSLAnalysis:
    analysis = SSLAnalysis(host=host, port=port)

    for tls_version, attr_name, min_version, max_version in [
        ("TLS 1.0", "supports_tls_1_0", ssl.TLSVersion.MINIMUM_SUPPORTED, ssl.TLSVersion.TLSv1),
        ("TLS 1.1", "supports_tls_1_1", ssl.TLSVersion.MINIMUM_SUPPORTED, ssl.TLSVersion.TLSv1_1),
        ("TLS 1.2", "supports_tls_1_2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
        ("TLS 1.3", "supports_tls_1_3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = min_version
            ctx.maximum_version = max_version
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with (
                socket.create_connection((host, port), timeout=5) as sock,
                ctx.wrap_socket(sock, server_hostname=host) as ssock,
            ):
                setattr(analysis, attr_name, True)
                cipher = ssock.cipher()
                if cipher:
                    analysis.supported_ciphers.append(cipher[0])
                    if any(w in cipher[0] for w in WEAK_CIPHERS):
                        analysis.weak_ciphers.append(cipher[0])
        except Exception as e:
            logger.debug("%s check failed for %s: %s", tls_version, host, e)

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        import certifi

        ctx.load_verify_locations(certifi.where())

        with (
            socket.create_connection((host, port), timeout=5) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as ssock,
        ):
            cert = ssock.getpeercert()
            analysis.certificate_valid = True
            if cert:
                analysis.certificate_issuer = str(cert.get("issuer", ""))
                analysis.certificate_subject = str(cert.get("subject", ""))
                not_after = cert.get("notAfter", "")
                if not_after:
                    from dateutil.parser import parse as parse_date

                    with contextlib.suppress(Exception):
                        analysis.certificate_expiry = parse_date(not_after)
                san = cert.get("subjectAltName", [])
                analysis.certificate_san = [s[1] for s in san if isinstance(s, tuple) and len(s) > 1]
    except Exception as e:
        analysis.errors.append(f"Certificate validation: {e}")

    try:
        import httpx

        client = httpx.Client(timeout=5, verify=False, follow_redirects=True)
        response = client.get(f"https://{host}", headers={"Host": host})
        hsts = response.headers.get("Strict-Transport-Security", "")
        if hsts:
            analysis.hsts_enabled = True
            parts = dict(
                item.strip().split("=", 1) if "=" in item else (item.strip(), None) for item in hsts.split(";")
            )
            if parts.get("max-age"):
                with contextlib.suppress(ValueError):
                    analysis.hsts_max_age = int(parts["max-age"])
            analysis.hsts_include_subdomains = "includesubdomains" in hsts.lower()
            analysis.hsts_preload = "preload" in hsts.lower()
        client.close()
    except Exception:
        pass

    return analysis


def ssl_report(analysis: SSLAnalysis) -> dict[str, object]:
    return {
        "host": analysis.host,
        "tls_1_0": analysis.supports_tls_1_0,
        "tls_1_1": analysis.supports_tls_1_1,
        "tls_1_2": analysis.supports_tls_1_2,
        "tls_1_3": analysis.supports_tls_1_3,
        "certificate_valid": analysis.certificate_valid,
        "certificate_expiry": analysis.certificate_expiry.isoformat() if analysis.certificate_expiry else None,
        "certificate_issuer": analysis.certificate_issuer,
        "weak_ciphers": analysis.weak_ciphers,
        "hsts_enabled": analysis.hsts_enabled,
        "hsts_max_age": analysis.hsts_max_age,
        "errors": analysis.errors,
    }
