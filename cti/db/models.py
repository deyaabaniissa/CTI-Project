"""SQLAlchemy ORM schema for IoMT network-flow investigations and CTI evidence."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import INET as PG_INET
from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


# Keep the production PostgreSQL column types while allowing the same schema to
# run locally on SQLite before Docker Desktop is installed.
JSONB = JSON().with_variant(PG_JSONB(), "postgresql")
INET = String(45).with_variant(PG_INET(), "postgresql")


def UUID(*, as_uuid: bool = True) -> Uuid:
    return Uuid(as_uuid=as_uuid)


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DataSourceType(str, enum.Enum):
    telemetry = "telemetry"
    asset_inventory = "asset_inventory"
    sbom = "sbom"
    cti = "cti"


class ImportStatus(str, enum.Enum):
    pending = "pending"
    completed = "completed"
    failed = "failed"


class AssetType(str, enum.Enum):
    medical_device = "medical_device"
    server = "server"
    workstation = "workstation"
    gateway = "gateway"
    network_device = "network_device"
    application = "application"


class IndicatorType(str, enum.Enum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"
    domain = "domain"
    url = "url"
    sha256 = "sha256"
    sha1 = "sha1"
    md5 = "md5"
    cve = "cve"
    ghsa = "ghsa"
    purl = "purl"


class ProviderName(str, enum.Enum):
    otx = "otx"
    virustotal = "virustotal"
    nvd = "nvd"
    osv = "osv"


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertClassification(str, enum.Enum):
    active_attack = "active_attack"
    security_vulnerability = "security_vulnerability"
    unauthorized_access = "unauthorized_access"
    malicious_ip = "malicious_ip"
    benign = "benign"
    needs_review = "needs_review"


class AlertStatus(str, enum.Enum):
    open = "open"
    investigating = "investigating"
    resolved = "resolved"
    false_positive = "false_positive"


class Role(str, enum.Enum):
    analyst = "analyst"
    administrator = "administrator"


class UUIDPrimaryKey:
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


class Timestamped:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class DataSource(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "data_sources"

    name: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    source_type: Mapped[DataSourceType] = mapped_column(Enum(DataSourceType, native_enum=False), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(2048))
    description: Mapped[str | None] = mapped_column(Text)


class ImportBatch(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "import_batches"

    data_source_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("data_sources.id", ondelete="RESTRICT"), nullable=False)
    file_name: Mapped[str] = mapped_column(String(512), nullable=False)
    file_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    row_count: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[ImportStatus] = mapped_column(Enum(ImportStatus, native_enum=False), default=ImportStatus.pending, nullable=False)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)


class Asset(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "assets"

    asset_tag: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType, native_enum=False), nullable=False)
    manufacturer: Mapped[str | None] = mapped_column(String(160))
    model: Mapped[str | None] = mapped_column(String(160))
    firmware_version: Mapped[str | None] = mapped_column(String(160))
    criticality: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    department: Mapped[str | None] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(64), default="active", nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class AssetInterface(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "asset_interfaces"
    __table_args__ = (Index("ix_asset_interfaces_ip_address", "ip_address"),)

    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    mac_address: Mapped[str | None] = mapped_column(String(32))
    hostname: Mapped[str | None] = mapped_column(String(255))
    network_zone: Mapped[str | None] = mapped_column(String(128))


class SoftwareComponent(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "software_components"
    __table_args__ = (UniqueConstraint("purl", name="uq_software_components_purl"), Index("ix_software_components_cpe", "cpe_uri"))

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(160))
    version: Mapped[str | None] = mapped_column(String(160))
    purl: Mapped[str | None] = mapped_column(String(2048))
    cpe_uri: Mapped[str | None] = mapped_column(String(2048))
    component_type: Mapped[str] = mapped_column(String(64), default="application", nullable=False)


class AssetSoftware(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "asset_software"
    __table_args__ = (UniqueConstraint("asset_id", "software_component_id", name="uq_asset_software"),)

    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    software_component_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("software_components.id", ondelete="RESTRICT"), nullable=False)
    installed_version: Mapped[str | None] = mapped_column(String(160))
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Sbom(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "sboms"

    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    import_batch_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("import_batches.id", ondelete="SET NULL"))
    sbom_format: Mapped[str] = mapped_column(String(64), nullable=False)
    file_name: Mapped[str] = mapped_column(String(512), nullable=False)
    file_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw_document: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class SbomComponent(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "sbom_components"

    sbom_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sboms.id", ondelete="CASCADE"), nullable=False)
    software_component_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("software_components.id", ondelete="SET NULL"))
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    package_version: Mapped[str | None] = mapped_column(String(160))
    purl: Mapped[str | None] = mapped_column(String(2048))


class HospitalEvent(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "hospital_events"
    __table_args__ = (
        Index("ix_hospital_events_event_time", "event_time"),
        Index("ix_hospital_events_source_ip", "source_ip"),
        Index("ix_hospital_events_destination_ip", "destination_ip"),
    )

    import_batch_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("import_batches.id", ondelete="SET NULL"))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    external_event_id: Mapped[str | None] = mapped_column(String(160), unique=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(INET)
    destination_ip: Mapped[str | None] = mapped_column(INET)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(32))
    traffic_type: Mapped[str | None] = mapped_column(String(128))
    bytes_transferred: Mapped[int | None] = mapped_column(Integer)
    packets: Mapped[int | None] = mapped_column(Integer)
    flow_features: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    dataset_label: Mapped[int | None] = mapped_column(Integer)


class Indicator(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("indicator_type", "normalized_value", name="uq_indicators_type_value"), Index("ix_indicators_value", "normalized_value"))

    indicator_type: Mapped[IndicatorType] = mapped_column(Enum(IndicatorType, native_enum=False), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    value_hash: Mapped[str | None] = mapped_column(String(64))
    is_public: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EventIndicator(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "event_indicators"
    __table_args__ = (UniqueConstraint("event_id", "indicator_id", "extraction_field", name="uq_event_indicator"),)

    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("hospital_events.id", ondelete="CASCADE"), nullable=False)
    indicator_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("indicators.id", ondelete="RESTRICT"), nullable=False)
    extraction_field: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)


class CTIProvider(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "cti_providers"

    name: Mapped[ProviderName] = mapped_column(Enum(ProviderName, native_enum=False), unique=True, nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    rate_limit_per_minute: Mapped[int | None] = mapped_column(Integer)


class CTILookupResult(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "cti_lookup_results"
    __table_args__ = (Index("ix_cti_lookup_results_expires_at", "expires_at"),)

    provider_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cti_providers.id", ondelete="RESTRICT"), nullable=False)
    indicator_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("indicators.id", ondelete="SET NULL"))
    lookup_type: Mapped[str] = mapped_column(String(64), nullable=False)
    verdict: Mapped[str] = mapped_column(String(64), default="unknown", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    queried_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw_response: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class Vulnerability(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (UniqueConstraint("cve_id", name="uq_vulnerabilities_cve_id"), Index("ix_vulnerabilities_osv_id", "osv_id"))

    cve_id: Mapped[str | None] = mapped_column(String(32))
    osv_id: Mapped[str | None] = mapped_column(String(128))
    title: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[Severity | None] = mapped_column(Enum(Severity, native_enum=False))
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class AssetVulnerability(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "asset_vulnerabilities"
    __table_args__ = (UniqueConstraint("asset_id", "software_component_id", "vulnerability_id", name="uq_asset_vulnerability"),)

    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    software_component_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("software_components.id", ondelete="SET NULL"))
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False)
    match_source: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(64), default="open", nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CTIMatch(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "cti_matches"

    lookup_result_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cti_lookup_results.id", ondelete="CASCADE"), nullable=False)
    event_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("hospital_events.id", ondelete="CASCADE"))
    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="SET NULL"))
    match_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, native_enum=False), default=Severity.info, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)


class ModelVersion(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "model_versions"

    name: Mapped[str] = mapped_column(String(160), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(160), nullable=False)
    feature_schema: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    artifact_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ModelPrediction(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "model_predictions"
    __table_args__ = (Index("ix_model_predictions_event", "event_id"),)

    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("hospital_events.id", ondelete="CASCADE"), nullable=False)
    model_version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("model_versions.id", ondelete="RESTRICT"), nullable=False)
    probability: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[Severity] = mapped_column(Enum(Severity, native_enum=False), nullable=False)
    predicted_class: Mapped[str] = mapped_column(String(64), nullable=False)
    feature_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    predicted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ModelEvaluationSample(UUIDPrimaryKey, Timestamped, Base):
    """A held-out dataset row used only for transparent model evaluation."""

    __tablename__ = "model_evaluation_samples"
    __table_args__ = (
        UniqueConstraint("sample_key", name="uq_model_evaluation_samples_sample_key"),
        Index("ix_model_evaluation_samples_true_family", "true_family"),
        Index("ix_model_evaluation_samples_correct", "correct"),
    )

    model_version_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("model_versions.id", ondelete="CASCADE"), nullable=False
    )
    sample_key: Mapped[str] = mapped_column(String(64), nullable=False)
    dataset_name: Mapped[str] = mapped_column(String(160), nullable=False)
    dataset_split: Mapped[str] = mapped_column(String(128), nullable=False)
    source_file: Mapped[str] = mapped_column(String(512), nullable=False)
    source_row_number: Mapped[int] = mapped_column(Integer, nullable=False)
    attack_subclass: Mapped[str] = mapped_column(String(160), nullable=False)
    true_family: Mapped[str] = mapped_column(String(64), nullable=False)
    predicted_family: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    correct: Mapped[bool] = mapped_column(Boolean, nullable=False)
    feature_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    class_probabilities: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class Alert(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_status_created", "status", "created_at"),)

    event_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("hospital_events.id", ondelete="SET NULL"))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    classification: Mapped[AlertClassification] = mapped_column(Enum(AlertClassification, native_enum=False), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, native_enum=False), nullable=False)
    status: Mapped[AlertStatus] = mapped_column(Enum(AlertStatus, native_enum=False), default=AlertStatus.open, nullable=False)
    final_score: Mapped[float] = mapped_column(Float, nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AlertEvidence(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "alert_evidence"

    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_table: Mapped[str | None] = mapped_column(String(128))
    source_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    weight: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)


class User(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role, native_enum=False), default=Role.analyst, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class AlertStatusHistory(UUIDPrimaryKey, Base):
    __tablename__ = "alert_status_history"

    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    old_status: Mapped[AlertStatus | None] = mapped_column(Enum(AlertStatus, native_enum=False))
    new_status: Mapped[AlertStatus] = mapped_column(Enum(AlertStatus, native_enum=False), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditLog(UUIDPrimaryKey, Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_entity", "entity_type", "entity_id"),)

    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
