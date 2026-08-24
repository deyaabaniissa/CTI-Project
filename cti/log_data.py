"""Shared feature contract for the three hospital operational log sources.

Direct identifiers, free-text descriptions, database-provider names, and the
provided threat references are deliberately excluded from the behavioural
model.  Threat references are evaluated separately by the live intelligence
layer so analysts can distinguish model evidence from database evidence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

import pandas as pd


CATEGORICAL_FEATURES = [
    "log_type",
    "location",
    "department",
    "actor_role",
    "action",
    "object_type",
    "device_type",
    "protocol",
    "severity",
    "status",
]
NUMERIC_FEATURES = ["hour", "day_of_week", "source_port", "dest_port"]
MODEL_FEATURES = [*CATEGORICAL_FEATURES, *NUMERIC_FEATURES]

EXCLUDED_SENSITIVE_OR_LEAKY_FIELDS = [
    "patient_id",
    "accessed_by_employee_id",
    "employee_id",
    "employee_name",
    "device_id",
    "workstation_id",
    "description",
    "ip_address",
    "source_ip",
    "destination_ip",
    "threat_db_match",
    "source_db_match_label",
    "threat_source",
    "threat_reference_id",
    "indicator",
    "synthetic_label",
    "synthetic_attack_type",
    "synthetic_confidence",
    "label_rule_id",
    "label_reason",
    "rule_risk_score",
    "label_source",
    "analyst_label",
    "analyst_attack_type",
    "analyst_confidence",
    "analyst_reason",
    "review_status",
    "reviewed_by",
    "reviewed_at",
]


def _first_value(event: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        value = event.get(name)
        if value is None:
            continue
        try:
            if pd.isna(value):
                continue
        except (TypeError, ValueError):
            pass
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return default


def _text(event: Mapping[str, Any], *names: str, default: str = "unknown") -> str:
    value = _first_value(event, *names, default=default)
    text = str(value).strip().lower()
    return text if text and text not in {"nan", "none", "null"} else default


def _number(event: Mapping[str, Any], *names: str) -> float:
    value = _first_value(event, *names, default=0)
    try:
        number = float(value)
        return number if pd.notna(number) else 0.0
    except (TypeError, ValueError):
        return 0.0


def _timestamp_parts(event: Mapping[str, Any]) -> tuple[int, int]:
    raw = _first_value(event, "event_time", "timestamp")
    if raw is None:
        return 0, 0
    if isinstance(raw, datetime):
        return raw.hour, raw.weekday()
    parsed = pd.to_datetime(raw, errors="coerce")
    if pd.isna(parsed):
        return 0, 0
    return int(parsed.hour), int(parsed.dayofweek)


def feature_record(event: Mapping[str, Any]) -> dict[str, Any]:
    """Return one normalized, privacy-minimized model input record."""

    hour, day_of_week = _timestamp_parts(event)
    return {
        "log_type": _text(event, "log_type", "category"),
        "location": _text(event, "location"),
        "department": _text(event, "department", "device_context", "location"),
        "actor_role": _text(event, "actor_role", "accessed_by_role", "role"),
        "action": _text(event, "action", "access_type", "event_type", "attack_category"),
        "object_type": _text(event, "object_type", "data_field_accessed", "traffic_class"),
        "device_type": _text(event, "device_type", "device_used"),
        "protocol": _text(event, "protocol"),
        "severity": _text(event, "severity"),
        "status": _text(event, "status"),
        "hour": hour,
        "day_of_week": day_of_week,
        "source_port": _number(event, "source_port", "src_port"),
        "dest_port": _number(event, "dest_port", "dst_port", "destination_port"),
    }


def feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Normalize a dataframe using the same contract used at inference time."""

    records = [feature_record(row) for row in frame.to_dict("records")]
    return pd.DataFrame.from_records(records, columns=MODEL_FEATURES)
