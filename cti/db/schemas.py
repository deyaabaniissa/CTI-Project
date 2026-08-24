"""Validated data contracts for the persistence layer.

These schemas are intentionally separate from ORM models so API/import code
cannot write arbitrary provider responses or unsafe indicator values by mistake.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cti.db.models import AlertClassification, AlertStatus, AssetType, IndicatorType, ProviderName, Severity


class ORMReadModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class AssetCreate(BaseModel):
    asset_tag: str = Field(min_length=1, max_length=128)
    asset_type: AssetType
    manufacturer: str | None = Field(default=None, max_length=160)
    model: str | None = Field(default=None, max_length=160)
    firmware_version: str | None = Field(default=None, max_length=160)
    criticality: float = Field(default=0.5, ge=0, le=1)
    department: str | None = Field(default=None, max_length=160)


class HospitalEventCreate(BaseModel):
    external_event_id: str | None = Field(default=None, max_length=160)
    event_time: datetime
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=32)
    traffic_type: str | None = Field(default=None, max_length=128)
    bytes_transferred: int | None = Field(default=None, ge=0)
    packets: int | None = Field(default=None, ge=0)
    flow_features: dict[str, Any] = Field(default_factory=dict)
    dataset_label: int | None = Field(default=None, ge=0, le=1)
    asset_id: UUID | None = None


class IndicatorCreate(BaseModel):
    indicator_type: IndicatorType
    normalized_value: str = Field(min_length=1, max_length=2048)
    is_public: bool = False

    @field_validator("normalized_value")
    @classmethod
    def normalize_value(cls, value: str) -> str:
        return value.strip().lower().rstrip(".")


class CTILookupResultCreate(BaseModel):
    provider: ProviderName
    indicator_id: UUID | None = None
    lookup_type: str = Field(min_length=1, max_length=64)
    verdict: str = Field(default="unknown", max_length=64)
    confidence: float = Field(default=0.0, ge=0, le=1)
    queried_at: datetime
    expires_at: datetime | None = None
    raw_response: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityUpsert(BaseModel):
    cve_id: str | None = Field(default=None, max_length=32)
    osv_id: str | None = Field(default=None, max_length=128)
    title: str | None = Field(default=None, max_length=512)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    severity: Severity | None = None
    known_exploited: bool = False
    raw_data: dict[str, Any] = Field(default_factory=dict)


class AlertCreate(BaseModel):
    event_id: UUID | None = None
    asset_id: UUID | None = None
    classification: AlertClassification
    severity: Severity
    final_score: float = Field(ge=0, le=1)
    title: str = Field(min_length=1, max_length=512)
    description: str | None = None
    status: AlertStatus = AlertStatus.open


class AlertRead(ORMReadModel):
    id: UUID
    classification: AlertClassification
    severity: Severity
    status: AlertStatus
    final_score: float
    title: str
    created_at: datetime
