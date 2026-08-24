"""Import the project’s static healthcare datasets into PostgreSQL.

The import is repeatable: completed batches with the same SHA-256 are skipped,
and unique event/patient keys prevent duplicate rows when a forced import runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from cti.db.models import (
    Asset,
    AssetInterface,
    AssetType,
    CTIProvider,
    DataSource,
    DataSourceType,
    EventIndicator,
    HospitalEvent,
    Indicator,
    IndicatorType,
    ImportBatch,
    ImportStatus,
    ModelVersion,
    ProviderName,
    SyntheticPatientContext,
)
from cti.db.session import get_session_factory


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SECURITY_EVENTS_PATH = PROJECT_ROOT / "data" / "processed" / "hospital_log_events.csv"
PATIENT_CONTEXT_PATH = PROJECT_ROOT / "data" / "processed" / "synthetic_patient_context.csv"
DEMO_INDICATORS_PATH = PROJECT_ROOT / "data" / "demo" / "public_indicator_scenarios.csv"
MODEL_METRICS_PATH = PROJECT_ROOT / "model_metrics.json"

STATIC_EVENT_START = datetime(2024, 1, 1, tzinfo=timezone.utc)
PROVIDER_URLS = {
    ProviderName.otx: "https://otx.alienvault.com/api/v1",
    ProviderName.virustotal: "https://www.virustotal.com/api/v3",
    ProviderName.nvd: "https://services.nvd.nist.gov/rest/json/cves/2.0",
    ProviderName.osv: "https://api.osv.dev/v1",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def number_or_none(value: Any) -> int | float | None:
    if value is None or pd.isna(value):
        return None
    if hasattr(value, "item"):
        value = value.item()
    return value if isinstance(value, (int, float)) else float(value)


def integer_or_none(value: Any) -> int | None:
    number = number_or_none(value)
    return int(number) if number is not None else None


def text_or_none(value: Any) -> str | None:
    if value is None or pd.isna(value):
        return None
    text = str(value).strip()
    return text or None


def get_or_create_source(
    session: Session, name: str, source_type: DataSourceType, source_url: str, description: str
) -> DataSource:
    source = session.scalar(select(DataSource).where(DataSource.name == name))
    if source is None:
        source = DataSource(name=name, source_type=source_type, source_url=source_url, description=description)
        session.add(source)
        session.flush()
    return source


def completed_batch(session: Session, source: DataSource, file_hash: str) -> ImportBatch | None:
    return session.scalar(
        select(ImportBatch).where(
            ImportBatch.data_source_id == source.id,
            ImportBatch.file_sha256 == file_hash,
            ImportBatch.status == ImportStatus.completed,
        )
    )


def get_or_create_asset(session: Session) -> Asset:
    asset = session.scalar(select(Asset).where(Asset.asset_tag == "HOSPITAL-LOG-DATASETS"))
    if asset is None:
        asset = Asset(
            asset_tag="HOSPITAL-LOG-DATASETS",
            asset_type=AssetType.gateway,
            manufacturer="Hospital operational log import",
            model="Patient, employee, and system/device logs",
            criticality=0.8,
            department="hospital security operations",
            metadata_json={
                "data_sources": [
                    "patient_information_logs.xlsx",
                    "employee_logs.xlsx",
                    "hospital_system_device_logs.xlsx",
                ]
            },
        )
        session.add(asset)
        session.flush()
    return asset


def get_or_create_demo_asset(session: Session) -> Asset:
    asset = session.scalar(select(Asset).where(Asset.asset_tag == "SIM-CTI-EXTERNAL-GATEWAY"))
    if asset is None:
        asset = Asset(
            asset_tag="SIM-CTI-EXTERNAL-GATEWAY",
            asset_type=AssetType.gateway,
            manufacturer="Static CTI demonstration",
            model="External indicator gateway",
            criticality=0.9,
            department="simulated hospital network edge",
            metadata_json={"synthetic": True, "purpose": "live OTX and VirusTotal demonstrations"},
        )
        session.add(asset)
        session.flush()
    return asset


def seed_providers(session: Session) -> int:
    created = 0
    for provider, base_url in PROVIDER_URLS.items():
        existing = session.scalar(select(CTIProvider).where(CTIProvider.name == provider))
        if existing is None:
            session.add(CTIProvider(name=provider, base_url=base_url))
            created += 1
    return created


def create_event_rows(frame: pd.DataFrame, batch: ImportBatch, asset: Asset) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    model_columns = [
        "log_type", "location", "department", "actor_role", "action", "object_type",
        "device_type", "protocol", "severity", "status", "source_port", "dest_port",
        "indicator", "indicator_type", "threat_source",
    ]
    for _, row in frame.iterrows():
        flow_features = {
            column: (
                number_or_none(row.get(column))
                if column in {"source_port", "dest_port"}
                else text_or_none(row.get(column))
            )
            for column in model_columns
        }
        flow_features["event_source"] = text_or_none(row.get("event_source"))
        rows.append(
            {
                "import_batch_id": batch.id,
                "asset_id": asset.id,
                "external_event_id": text_or_none(row.get("event_id")),
                "event_time": pd.to_datetime(row.get("event_time"), utc=True).to_pydatetime(),
                "source_ip": text_or_none(row.get("source_ip")),
                "destination_ip": text_or_none(row.get("destination_ip")),
                "source_port": integer_or_none(row.get("source_port")),
                "destination_port": integer_or_none(row.get("dest_port")),
                "protocol": text_or_none(row.get("protocol")),
                "traffic_type": text_or_none(row.get("action")),
                "bytes_transferred": None,
                "packets": None,
                "flow_features": flow_features,
                "dataset_label": integer_or_none(row.get("label")),
            }
        )
    return rows


def import_security_events(session: Session, force: bool) -> dict[str, Any]:
    if not SECURITY_EVENTS_PATH.exists():
        raise FileNotFoundError(f"Prepared security events not found: {SECURITY_EVENTS_PATH}")
    source = get_or_create_source(
        session,
        "Hospital operational log workbooks",
        DataSourceType.telemetry,
        "local://data/raw/hospital-log-workbooks",
        "Patient access, employee activity, and system/device logs supplied as three Excel workbooks.",
    )
    file_hash = sha256_file(SECURITY_EVENTS_PATH)
    previous = completed_batch(session, source, file_hash)
    if previous and not force:
        return {"status": "skipped", "reason": "matching completed import batch", "events": previous.row_count or 0}

    frame = pd.read_csv(SECURITY_EVENTS_PATH, low_memory=False)
    batch = ImportBatch(
        data_source_id=source.id,
        file_name=SECURITY_EVENTS_PATH.name,
        file_sha256=file_hash,
        row_count=len(frame),
        status=ImportStatus.pending,
    )
    session.add(batch)
    session.flush()
    asset = get_or_create_asset(session)
    rows = create_event_rows(frame, batch, asset)
    inserted = 0
    for start in range(0, len(rows), 1000):
        statement = insert(HospitalEvent).values(rows[start : start + 1000])
        statement = statement.on_conflict_do_nothing(index_elements=["external_event_id"])
        statement = statement.returning(HospitalEvent.id)
        result = session.execute(statement)
        inserted += len(result.scalars().all())

    known_ips = set(
        value
        for value in frame["source_ip"].dropna().astype(str).tolist()
        + frame["destination_ip"].dropna().astype(str).tolist()
        if value and value.lower() != "nan"
    )
    existing_ips = {
        str(ip_address)
        for ip_address in session.scalars(
            select(AssetInterface.ip_address).where(AssetInterface.asset_id == asset.id)
        )
    }
    for ip_address in known_ips - existing_ips:
        session.add(AssetInterface(asset_id=asset.id, ip_address=ip_address, network_zone="simulated-iomt"))

    batch.status = ImportStatus.completed
    batch.imported_at = datetime.now(timezone.utc)
    return {"status": "completed", "events": len(rows), "inserted_events": inserted, "batch_id": str(batch.id)}


def import_patient_context(session: Session, force: bool) -> dict[str, Any]:
    if not PATIENT_CONTEXT_PATH.exists():
        raise FileNotFoundError(f"Prepared patient context not found: {PATIENT_CONTEXT_PATH}")
    source = get_or_create_source(
        session,
        "Synthea FHIR R4 synthetic sample",
        DataSourceType.synthetic_patient,
        "https://synthea.mitre.org/downloads",
        "Tokenized synthetic patient context. This data is not used as an attack-model feature.",
    )
    file_hash = sha256_file(PATIENT_CONTEXT_PATH)
    previous = completed_batch(session, source, file_hash)
    if previous and not force:
        return {"status": "skipped", "reason": "matching completed import batch", "patients": previous.row_count or 0}

    frame = pd.read_csv(PATIENT_CONTEXT_PATH, low_memory=False)
    batch = ImportBatch(
        data_source_id=source.id,
        file_name=PATIENT_CONTEXT_PATH.name,
        file_sha256=file_hash,
        row_count=len(frame),
        status=ImportStatus.pending,
    )
    session.add(batch)
    session.flush()
    rows = [
        {
            "data_source_id": source.id,
            "patient_token": str(row.patient_token),
            "administrative_gender": text_or_none(row.administrative_gender),
            "condition_count": integer_or_none(row.condition_count) or 0,
            "observation_count": integer_or_none(row.observation_count) or 0,
            "encounter_count": integer_or_none(row.encounter_count) or 0,
        }
        for row in frame.itertuples(index=False)
    ]
    statement = insert(SyntheticPatientContext).values(rows)
    statement = statement.on_conflict_do_nothing(constraint="uq_synthetic_patient_token")
    statement = statement.returning(SyntheticPatientContext.id)
    result = session.execute(statement)
    batch.status = ImportStatus.completed
    batch.imported_at = datetime.now(timezone.utc)
    return {"status": "completed", "patients": len(rows), "inserted_patients": len(result.scalars().all()), "batch_id": str(batch.id)}


def import_public_indicator_scenarios(session: Session, force: bool) -> dict[str, Any]:
    if not DEMO_INDICATORS_PATH.exists():
        raise FileNotFoundError(f"Public indicator scenarios not found: {DEMO_INDICATORS_PATH}")
    source = get_or_create_source(
        session,
        "Static public indicator scenarios",
        DataSourceType.cti,
        "local://data/demo/public_indicator_scenarios.csv",
        "Harmless static public indicators used to demonstrate live OTX and VirusTotal enrichment.",
    )
    file_hash = sha256_file(DEMO_INDICATORS_PATH)
    previous = completed_batch(session, source, file_hash)
    if previous and not force:
        return {"status": "skipped", "reason": "matching completed import batch", "scenarios": previous.row_count or 0}

    frame = pd.read_csv(DEMO_INDICATORS_PATH, low_memory=False)
    batch = ImportBatch(
        data_source_id=source.id,
        file_name=DEMO_INDICATORS_PATH.name,
        file_sha256=file_hash,
        row_count=len(frame),
        status=ImportStatus.pending,
    )
    session.add(batch)
    session.flush()
    asset = get_or_create_demo_asset(session)
    rows = []
    for position, row in frame.iterrows():
        rows.append(
            {
                "import_batch_id": batch.id,
                "asset_id": asset.id,
                "external_event_id": str(row["event_id"]),
                "event_time": STATIC_EVENT_START + timedelta(days=60, seconds=position),
                "source_ip": str(row["source_ip"]),
                "destination_ip": str(row["destination_ip"]),
                "source_port": int(row["src_port"]),
                "destination_port": int(row["dst_port"]),
                "protocol": "https" if str(row["indicator_type"]) in {"ipv4", "domain"} else "file_transfer",
                "traffic_type": str(row["attack_category"]),
                "bytes_transferred": int(row["total_bytes"]),
                "packets": int(row["total_packets"]),
                "flow_features": {
                    "indicator": str(row["indicator"]),
                    "indicator_type": str(row["indicator_type"]),
                    "scenario_note": str(row["scenario_note"]),
                    "src_port": int(row["src_port"]),
                    "dst_port": int(row["dst_port"]),
                    "total_bytes": int(row["total_bytes"]),
                    "total_packets": int(row["total_packets"]),
                },
                "dataset_label": int(row["label"]),
            }
        )
    statement = insert(HospitalEvent).values(rows).on_conflict_do_nothing(index_elements=["external_event_id"])
    session.execute(statement)
    for _, row in frame.iterrows():
        indicator_type = IndicatorType(str(row["indicator_type"]))
        indicator_value = str(row["indicator"]).strip().lower().rstrip(".")
        is_public = indicator_type in {IndicatorType.ipv4, IndicatorType.domain, IndicatorType.url, IndicatorType.md5, IndicatorType.sha1, IndicatorType.sha256}
        indicator = session.scalar(
            select(Indicator).where(
                Indicator.indicator_type == indicator_type,
                Indicator.normalized_value == indicator_value,
            )
        )
        if indicator is None:
            indicator = Indicator(
                indicator_type=indicator_type,
                normalized_value=indicator_value,
                is_public=is_public,
                first_seen_at=datetime.now(timezone.utc),
                last_seen_at=datetime.now(timezone.utc),
            )
            session.add(indicator)
            session.flush()
        event = session.scalar(select(HospitalEvent).where(HospitalEvent.external_event_id == str(row["event_id"])))
        if event and session.scalar(
            select(EventIndicator).where(
                EventIndicator.event_id == event.id,
                EventIndicator.indicator_id == indicator.id,
                EventIndicator.extraction_field == "demo_indicator",
            )
        ) is None:
            session.add(EventIndicator(event_id=event.id, indicator_id=indicator.id, extraction_field="demo_indicator"))
    batch.status = ImportStatus.completed
    batch.imported_at = datetime.now(timezone.utc)
    return {"status": "completed", "scenarios": len(rows), "batch_id": str(batch.id)}


def import_model_version(session: Session) -> dict[str, Any]:
    if not MODEL_METRICS_PATH.exists():
        return {"status": "skipped", "reason": "model_metrics.json is missing"}
    metrics = json.loads(MODEL_METRICS_PATH.read_text(encoding="utf-8"))
    artifact_path = str((PROJECT_ROOT / "threat_model.pkl").resolve())
    version = session.scalar(select(ModelVersion).where(ModelVersion.artifact_path == artifact_path))
    trained_at = datetime.fromisoformat(metrics["trained_at"].replace("Z", "+00:00"))
    values = {
        "name": "hospital-threat-model",
        "algorithm": metrics.get("algorithm", "unknown"),
        "feature_schema": {"features": metrics.get("features", [])},
        "metrics": metrics,
        "artifact_path": artifact_path,
        "trained_at": trained_at,
    }
    if version is None:
        session.add(ModelVersion(**values))
        return {"status": "created"}
    for key, value in values.items():
        setattr(version, key, value)
    return {"status": "updated"}


def run_import(force: bool = False) -> dict[str, Any]:
    factory = get_session_factory()
    with factory() as session:
        try:
            summary = {
                "providers_created": seed_providers(session),
                "hospital_log_events": import_security_events(session, force),
                "model_version": import_model_version(session),
            }
            session.commit()
            return summary
        except Exception:
            session.rollback()
            raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Import static CTI project data into PostgreSQL.")
    parser.add_argument("--force", action="store_true", help="Record a new import batch; existing event/patient IDs remain deduplicated.")
    args = parser.parse_args()
    print(json.dumps(run_import(force=args.force), indent=2))


if __name__ == "__main__":
    main()
