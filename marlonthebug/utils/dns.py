"""Async DNS resolver wrapper utilities."""

import asyncio
import logging
from typing import Any

from dns.asyncresolver import resolve as dns_resolve
from dns.rdatatype import A, AAAA, CNAME, MX, NS, SOA, TXT

logger = logging.getLogger("marlonthebug.utils.dns")

RECORD_TYPES: dict[str, Any] = {
    "A": A,
    "AAAA": AAAA,
    "CNAME": CNAME,
    "MX": MX,
    "NS": NS,
    "SOA": SOA,
    "TXT": TXT,
}


async def dns_lookup(domain: str, record_type: str = "A") -> list[str]:
    rdtype = RECORD_TYPES.get(record_type.upper(), A)
    try:
        answers = await dns_resolve(domain, rdtype)
        return [str(a) for a in answers]
    except Exception as e:
        logger.debug("DNS lookup failed for %s (%s): %s", domain, record_type, e)
        return []


async def dns_lookup_all(domain: str, record_types: list[str] | None = None) -> dict[str, list[str]]:
    record_types = record_types or list(RECORD_TYPES.keys())
    results: dict[str, list[str]] = {}
    for rtype in record_types:
        records = await dns_lookup(domain, rtype)
        if records:
            results[rtype] = records
    return results


async def resolve_ptr(ip: str) -> str | None:
    try:
        parts = ip.split(".")
        parts.reverse()
        ptr = ".".join(parts) + ".in-addr.arpa"
        answers = await dns_resolve(ptr, "PTR")
        return str(answers[0]) if answers else None
    except Exception:
        return None


async def check_zone_transfer(domain: str) -> tuple[list[str], list[str]]:
    try:
        ns_records = await dns_lookup(domain, "NS")
        records: list[str] = []
        errors: list[str] = []
        for ns in ns_records:
            try:
                answers = await dns_resolve(domain, "AXFR")
                records.extend(str(a) for a in answers)
            except Exception as e:
                errors.append(f"{ns}: {e}")
        return records, errors
    except Exception as e:
        return [], [str(e)]
