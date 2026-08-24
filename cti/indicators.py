"""Normalization and privacy classification for supported security references."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


HASH_PATTERNS = {
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
}
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
# Synthetic workbook values sometimes use a wider alphabet than production
# GitHub advisories. OSV remains the authority on whether the ID exists.
GHSA_PATTERN = re.compile(r"^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def classify_indicator(value: str) -> tuple[str, str]:
    """Return a normalized value and a portable indicator/reference type."""

    normalized = value.strip()
    if not normalized:
        raise ValueError("Indicator cannot be empty.")

    prefixed_hash = re.fullmatch(r"(?i)(sha256|sha1|md5):([a-f0-9]+)", normalized)
    if prefixed_hash:
        hash_type, digest = prefixed_hash.groups()
        pattern = HASH_PATTERNS[hash_type.lower()]
        if pattern.fullmatch(digest):
            return digest.lower(), hash_type.lower()

    if CVE_PATTERN.fullmatch(normalized):
        return normalized.upper(), "cve"
    if GHSA_PATTERN.fullmatch(normalized):
        return normalized.upper(), "ghsa"

    parsed = urlparse(normalized)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return normalized, "url"

    try:
        address = ipaddress.ip_address(normalized)
        return str(address), "ipv4" if address.version == 4 else "ipv6"
    except ValueError:
        pass

    for hash_type, pattern in HASH_PATTERNS.items():
        if pattern.fullmatch(normalized):
            return normalized.lower(), hash_type

    domain = normalized.rstrip(".").lower()
    if DOMAIN_PATTERN.fullmatch(domain):
        return domain, "domain"

    raise ValueError(
        "Supported references are IPv4/IPv6 addresses, domains, URLs, MD5, SHA-1, "
        "SHA-256, CVE, and GHSA identifiers."
    )


def is_public_indicator(value: str, indicator_type: str) -> bool:
    if indicator_type in {"cve", "ghsa"}:
        return True
    if indicator_type not in {"ipv4", "ipv6"}:
        if indicator_type == "domain":
            return value not in {"localhost"} and not value.endswith((".local", ".internal", ".lan"))
        return True

    return ipaddress.ip_address(value).is_global
