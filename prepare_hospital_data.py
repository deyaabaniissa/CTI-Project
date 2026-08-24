"""Normalize the three supplied hospital log workbooks for safe model use.

The original workbooks remain unchanged under ``data/raw``.  The processed
event file removes names, direct patient/employee/device identifiers, free-text
descriptions, and raw workstation IDs.  Stable one-way tokens are retained for
local audit correlation, but are not model features or external CTI inputs.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

import pandas as pd

from cti.indicators import classify_indicator


PROJECT_ROOT = Path(__file__).resolve().parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
OUTPUT_PATH = PROCESSED_DIR / "hospital_log_events.csv"
SUMMARY_PATH = PROCESSED_DIR / "hospital_log_summary.json"

INPUTS = {
    "patient_access": RAW_DIR / "patient_information_logs.xlsx",
    "employee_activity": RAW_DIR / "employee_logs.xlsx",
    "system_device": RAW_DIR / "hospital_system_device_logs.xlsx",
}

REQUIRED_COLUMNS = {
    "patient_access": {
        "log_id", "timestamp", "patient_id", "accessed_by_employee_id",
        "accessed_by_role", "access_type", "data_field_accessed", "device_used",
        "ip_address", "location", "status", "threat_db_match", "threat_source",
        "threat_reference_id", "description",
    },
    "employee_activity": {
        "log_id", "timestamp", "employee_id", "employee_name", "department", "role",
        "action", "workstation_id", "ip_address", "location", "status",
        "threat_db_match", "threat_source", "threat_reference_id", "description",
    },
    "system_device": {
        "log_id", "timestamp", "device_id", "device_type", "location", "ip_address",
        "event_type", "protocol", "source_port", "dest_port", "severity", "status",
        "threat_db_match", "threat_source", "threat_reference_id", "description",
    },
}

OUTPUT_COLUMNS = [
    "event_id", "event_time", "event_source", "log_type", "actor_token", "subject_token",
    "location", "department", "actor_role", "action", "object_type", "device_type",
    "source_ip", "source_port", "destination_ip", "dest_port", "protocol", "severity",
    "status", "indicator", "indicator_type", "threat_source", "label",
]


def token(kind: str, value: Any) -> str:
    text = "" if value is None or pd.isna(value) else str(value).strip()
    if not text:
        return ""
    return hashlib.sha256(f"hospital-log-local:{kind}:{text}".encode("utf-8")).hexdigest()[:20]


def clean_text(value: Any, default: str = "") -> str:
    if value is None or pd.isna(value):
        return default
    text = str(value).strip()
    return text if text and text.lower() not in {"nan", "none", "null"} else default


def indicator_parts(value: Any) -> tuple[str, str]:
    raw = clean_text(value)
    if not raw:
        return "", ""
    try:
        return classify_indicator(raw)
    except ValueError:
        # Retain an invalid synthetic reference locally for audit, but give it
        # no type so the extraction layer will never send it externally.
        return raw, "unsupported"


def labels(frame: pd.DataFrame, source_name: str) -> pd.Series:
    normalized = frame["threat_db_match"].astype(str).str.strip().str.lower()
    unexpected = sorted(set(normalized) - {"yes", "no"})
    if unexpected:
        raise ValueError(f"{source_name} has unsupported threat_db_match values: {unexpected}")
    return normalized.eq("yes").astype(int)


def validate_frame(frame: pd.DataFrame, source_name: str) -> None:
    missing = REQUIRED_COLUMNS[source_name] - set(frame.columns)
    if missing:
        raise ValueError(f"{source_name} schema is missing columns: {sorted(missing)}")
    if frame["log_id"].isna().any() or frame["log_id"].duplicated().any():
        raise ValueError(f"{source_name} requires unique, non-empty log_id values")


def common_row(row: pd.Series, source_name: str, label: int) -> dict[str, Any]:
    indicator, indicator_type = indicator_parts(row.get("threat_reference_id"))
    return {
        "event_id": clean_text(row.get("log_id")),
        "event_time": pd.to_datetime(row.get("timestamp"), errors="raise").isoformat(),
        "event_source": INPUTS[source_name].name,
        "log_type": source_name,
        "location": clean_text(row.get("location"), "unknown"),
        "source_ip": clean_text(row.get("ip_address")),
        "destination_ip": "",
        "status": clean_text(row.get("status"), "unknown"),
        "indicator": indicator,
        "indicator_type": indicator_type,
        "threat_source": clean_text(row.get("threat_source")),
        "label": int(label),
    }


def patient_row(row: pd.Series, label: int) -> dict[str, Any]:
    return {
        **common_row(row, "patient_access", label),
        "actor_token": token("employee", row.get("accessed_by_employee_id")),
        "subject_token": token("patient", row.get("patient_id")),
        "department": clean_text(row.get("location"), "unknown"),
        "actor_role": clean_text(row.get("accessed_by_role"), "unknown"),
        "action": clean_text(row.get("access_type"), "unknown"),
        "object_type": clean_text(row.get("data_field_accessed"), "unknown"),
        "device_type": clean_text(row.get("device_used"), "unknown"),
        "source_port": 0,
        "dest_port": 0,
        "protocol": "unknown",
        "severity": "unknown",
    }


def employee_row(row: pd.Series, label: int) -> dict[str, Any]:
    return {
        **common_row(row, "employee_activity", label),
        "actor_token": token("employee", row.get("employee_id")),
        "subject_token": "",
        "department": clean_text(row.get("department"), "unknown"),
        "actor_role": clean_text(row.get("role"), "unknown"),
        "action": clean_text(row.get("action"), "unknown"),
        "object_type": "employee activity",
        "device_type": "workstation",
        "source_port": 0,
        "dest_port": 0,
        "protocol": "unknown",
        "severity": "unknown",
    }


def device_row(row: pd.Series, label: int) -> dict[str, Any]:
    return {
        **common_row(row, "system_device", label),
        "actor_token": token("device", row.get("device_id")),
        "subject_token": "",
        "department": clean_text(row.get("location"), "unknown"),
        "actor_role": "system device",
        "action": clean_text(row.get("event_type"), "unknown"),
        "object_type": "system event",
        "device_type": clean_text(row.get("device_type"), "unknown"),
        "source_port": int(row.get("source_port") or 0),
        "dest_port": int(row.get("dest_port") or 0),
        "protocol": clean_text(row.get("protocol"), "unknown"),
        "severity": clean_text(row.get("severity"), "unknown"),
    }


NORMALIZERS: dict[str, Callable[[pd.Series, int], dict[str, Any]]] = {
    "patient_access": patient_row,
    "employee_activity": employee_row,
    "system_device": device_row,
}


def prepare_events() -> dict[str, Any]:
    all_rows: list[dict[str, Any]] = []
    source_summary: dict[str, Any] = {}
    seen_ids: set[str] = set()

    for source_name, source_path in INPUTS.items():
        if not source_path.exists():
            raise FileNotFoundError(f"Missing supplied workbook: {source_path}")
        frame = pd.read_excel(source_path)
        validate_frame(frame, source_name)
        target = labels(frame, source_name)
        rows = [NORMALIZERS[source_name](row, int(target.iloc[position])) for position, (_, row) in enumerate(frame.iterrows())]
        duplicate_ids = seen_ids.intersection(item["event_id"] for item in rows)
        if duplicate_ids:
            raise ValueError(f"Event IDs overlap across workbooks: {sorted(duplicate_ids)[:5]}")
        seen_ids.update(item["event_id"] for item in rows)
        all_rows.extend(rows)
        source_summary[source_name] = {
            "file": source_path.name,
            "sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
            "rows": len(rows),
            "threat_rows": int(target.sum()),
            "not_threat_rows": int((1 - target).sum()),
        }

    output = pd.DataFrame.from_records(all_rows, columns=OUTPUT_COLUMNS)
    output = output.sort_values(["event_time", "event_id"], kind="stable").reset_index(drop=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    output.to_csv(OUTPUT_PATH, index=False, quoting=csv.QUOTE_MINIMAL)

    summary = {
        "total_events": len(output),
        "threat_events": int(output["label"].sum()),
        "not_threat_events": int((1 - output["label"]).sum()),
        "sources": source_summary,
        "processed_columns": OUTPUT_COLUMNS,
        "privacy": {
            "direct_names_in_processed_output": False,
            "direct_patient_or_employee_ids_in_processed_output": False,
            "free_text_descriptions_in_processed_output": False,
            "external_lookup_allowlist": ["indicator"],
        },
    }
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare the supplied hospital log workbooks.")
    parser.parse_args()
    summary = prepare_events()
    print(json.dumps(summary, indent=2))
    print(f"Wrote {OUTPUT_PATH.relative_to(PROJECT_ROOT)}")
    print(f"Wrote {SUMMARY_PATH.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
