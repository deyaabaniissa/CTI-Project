"""Privacy-preserving extraction of security indicators from IoMT events.

Only explicitly security-relevant fields are examined.  Patient context, free
text clinical notes, and arbitrary metadata are intentionally never parsed or
submitted to external intelligence providers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from cti.intelligence import classify_indicator, is_public_indicator


# Keep this allow-list narrow.  Add a field only after documenting that it is
# telemetry, not clinical/patient content.
INDICATOR_FIELDS = (
    "indicator",
    "src_ip",
    "dst_ip",
    "source_ip",
    "destination_ip",
    "domain",
    "hostname",
    "url",
    "file_hash",
    "threat_reference_id",
    "sha256",
    "sha1",
    "md5",
    "cve",
    "cve_id",
    "indicators",
)


@dataclass(frozen=True)
class ExtractedIndicator:
    value: str
    indicator_type: str
    field: str
    is_public: bool


def extract_indicators(event: Mapping[str, Any]) -> list[ExtractedIndicator]:
    """Extract, normalize, and de-duplicate supported indicators.

    Invalid values and missing fields are skipped rather than failing a whole
    hospital event.  The output maintains field provenance for audit storage.
    """

    extracted: list[ExtractedIndicator] = []
    seen: set[tuple[str, str]] = set()
    for field in INDICATOR_FIELDS:
        raw_value = event.get(field)
        if raw_value is None:
            continue
        raw_values = raw_value if field == "indicators" and isinstance(raw_value, (list, tuple, set)) else [raw_value]
        for raw_item in raw_values:
            value = str(raw_item).strip()
            if not value or value.lower() in {"nan", "none", "null"}:
                continue
            try:
                normalized, indicator_type = classify_indicator(value)
            except ValueError:
                continue
            identity = (indicator_type, normalized)
            if identity in seen:
                continue
            seen.add(identity)
            extracted.append(
                ExtractedIndicator(
                    value=normalized,
                    indicator_type=indicator_type,
                    field=field,
                    is_public=is_public_indicator(normalized, indicator_type),
                )
            )
    return extracted
