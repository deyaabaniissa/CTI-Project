"""Persistence for Flask CatBoost investigations on SQLite or PostgreSQL."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from sqlalchemy import func, inspect, select

from cti.db.models import (
    Alert,
    AlertClassification,
    AlertEvidence,
    AlertStatus,
    Asset,
    AssetType,
    Base,
    CTILookupResult,
    CTIMatch,
    CTIProvider,
    EventIndicator,
    HospitalEvent,
    Indicator,
    IndicatorType,
    ModelPrediction,
    ModelVersion,
    ProviderName,
    Severity,
)
from cti.db.session import create_database_engine, database_url, get_session_factory
from cti.intelligence import classify_indicator, is_public_indicator


PROVIDER_URLS = {
    ProviderName.otx: "https://otx.alienvault.com/api/v1",
    ProviderName.virustotal: "https://www.virustotal.com/api/v3",
    ProviderName.osv: "https://api.osv.dev/v1",
    ProviderName.nvd: "https://services.nvd.nist.gov/rest/json/cves/2.0",
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def severity(value: str | None) -> Severity:
    normalized = str(value or "info").lower()
    return Severity(normalized) if normalized in Severity._value2member_map_ else Severity.info


class SitePersistenceService:
    """Store each end-to-end investigation and rebuild dashboard alerts."""

    def __init__(self, model_metadata: Mapping[str, Any], artifact_path: str) -> None:
        self.model_metadata = json_safe(model_metadata)
        self.artifact_path = artifact_path

    def initialize(self) -> dict[str, Any]:
        engine = create_database_engine()
        Base.metadata.create_all(engine)
        factory = get_session_factory()
        with factory() as session:
            for provider_name, base_url in PROVIDER_URLS.items():
                provider = session.scalar(select(CTIProvider).where(CTIProvider.name == provider_name))
                if provider is None:
                    session.add(CTIProvider(name=provider_name, base_url=base_url, enabled=True))
            model_name = str(self.model_metadata.get("model_name") or "ciciomt2024-catboost")
            model = session.scalar(select(ModelVersion).where(ModelVersion.name == model_name))
            if model is None:
                model = ModelVersion(
                    name=model_name,
                    algorithm="CatBoostClassifier",
                    feature_schema={"features": self.model_metadata.get("features", [])},
                    metrics=self.model_metadata.get("metrics", {}),
                    artifact_path=self.artifact_path,
                    trained_at=utcnow(),
                )
                session.add(model)
            else:
                model.feature_schema = {"features": self.model_metadata.get("features", [])}
                model.metrics = self.model_metadata.get("metrics", {})
                model.artifact_path = self.artifact_path
            session.commit()
        return self.status()

    def status(self) -> dict[str, Any]:
        engine = create_database_engine()
        backend = engine.url.get_backend_name()
        tables = inspect(engine).get_table_names()
        counts: dict[str, int] = {}
        if tables:
            factory = get_session_factory()
            with factory() as session:
                for name, model in {
                    "hospital_events": HospitalEvent,
                    "model_predictions": ModelPrediction,
                    "cti_lookup_results": CTILookupResult,
                    "alerts": Alert,
                }.items():
                    counts[name] = int(session.scalar(select(func.count()).select_from(model)) or 0)
        return {
            "status": "ready",
            "backend": backend,
            "url": "local SQLite" if backend == "sqlite" else "configured PostgreSQL",
            "table_count": len(tables),
            "counts": counts,
        }

    @staticmethod
    def _get_or_create_asset(session, event: Mapping[str, Any]) -> Asset | None:
        asset_tag = str(event.get("asset_id") or "").strip()
        if not asset_tag:
            return None
        asset = session.scalar(select(Asset).where(Asset.asset_tag == asset_tag))
        if asset is None:
            asset = Asset(
                asset_tag=asset_tag,
                asset_type=AssetType.gateway,
                manufacturer=str(event.get("vendor") or "Unknown")[:160],
                model=str(event.get("asset_type") or "IoMT gateway")[:160],
                firmware_version=str(event.get("product_version") or "")[:160] or None,
                criticality=min(max(float(event.get("asset_criticality", 0.8)), 0.0), 1.0),
                department=str(event.get("department") or "Hospital SOC")[:160],
                metadata_json={"sample_origin": event.get("sample_origin")},
            )
            session.add(asset)
            session.flush()
        return asset

    @staticmethod
    def _get_or_create_indicator(session, raw_value: str) -> Indicator:
        normalized, kind = classify_indicator(raw_value)
        indicator_type = IndicatorType(kind)
        row = session.scalar(
            select(Indicator).where(
                Indicator.indicator_type == indicator_type,
                Indicator.normalized_value == normalized,
            )
        )
        if row is None:
            row = Indicator(
                indicator_type=indicator_type,
                normalized_value=normalized,
                is_public=is_public_indicator(normalized, kind),
                first_seen_at=utcnow(),
                last_seen_at=utcnow(),
            )
            session.add(row)
            session.flush()
        else:
            row.last_seen_at = utcnow()
        return row

    @staticmethod
    def _provider_result(provider: ProviderName, payload: Mapping[str, Any]) -> tuple[str, float, bool]:
        if not payload.get("available"):
            return "unavailable", 0.0, False
        if provider is ProviderName.otx:
            matches = int(payload.get("pulse_count", 0) or 0)
            return ("malicious" if matches else "clean"), min(matches / 4, 1.0), matches > 0
        if provider is ProviderName.virustotal:
            malicious = int(payload.get("malicious", 0) or 0)
            suspicious = int(payload.get("suspicious", 0) or 0)
            total = max(int(payload.get("total_engines", 0) or 0), 1)
            confidence = min((malicious + suspicious * 0.5) / total * 4, 1.0)
            matched = malicious > 0 or suspicious > 1
            return ("malicious" if matched else "clean"), confidence, matched
        found = bool(payload.get("found") or payload.get("records"))
        return ("vulnerable" if found else "not_found"), (0.8 if found else 0.0), found

    def persist(
        self,
        event: Mapping[str, Any],
        result: Mapping[str, Any],
        dashboard_log: Mapping[str, Any],
    ) -> str:
        factory = get_session_factory()
        with factory() as session:
            try:
                asset = self._get_or_create_asset(session, event)
                investigation_id = str(result["investigation_id"])
                stored_event = HospitalEvent(
                    asset_id=asset.id if asset else None,
                    external_event_id=investigation_id,
                    event_time=utcnow(),
                    source_ip=event.get("source_ip") or event.get("src_ip"),
                    destination_ip=event.get("destination_ip") or event.get("dst_ip"),
                    protocol=str(event.get("protocol") or event.get("Protocol Type") or "")[:32] or None,
                    traffic_type=str(result["prediction"]["predicted_family"])[:128],
                    bytes_transferred=int(float(event.get("Tot sum", 0) or 0)),
                    packets=int(float(event.get("Number", 0) or 0)),
                    flow_features=json_safe(result["prediction"].get("features", {})),
                    dataset_label=None,
                )
                session.add(stored_event)
                session.flush()

                model_name = str(result["prediction"].get("model") or self.model_metadata.get("model_name"))
                model = session.scalar(select(ModelVersion).where(ModelVersion.name == model_name))
                if model is None:
                    raise RuntimeError("The CatBoost model version was not initialized in the database.")
                prediction = ModelPrediction(
                    event_id=stored_event.id,
                    model_version_id=model.id,
                    probability=float(result["prediction"]["confidence"]),
                    risk_level=severity(str(result.get("risk_level"))),
                    predicted_class=str(result["prediction"]["predicted_family"]),
                    feature_snapshot=json_safe(result["prediction"].get("features", {})),
                    predicted_at=utcnow(),
                )
                session.add(prediction)
                session.flush()

                lookup_rows: list[tuple[CTILookupResult, bool]] = []
                for evidence in result.get("indicator_evidence", []):
                    raw_indicator = str(evidence.get("indicator") or "").strip()
                    if not raw_indicator:
                        continue
                    indicator = self._get_or_create_indicator(session, raw_indicator)
                    session.add(EventIndicator(
                        event_id=stored_event.id,
                        indicator_id=indicator.id,
                        extraction_field=str(evidence.get("field") or "indicator")[:128],
                    ))
                    for provider_id, payload in (evidence.get("sources") or {}).items():
                        if provider_id not in ProviderName._value2member_map_:
                            continue
                        provider_name = ProviderName(provider_id)
                        provider = session.scalar(select(CTIProvider).where(CTIProvider.name == provider_name))
                        verdict, confidence, matched = self._provider_result(provider_name, payload)
                        lookup = CTILookupResult(
                            provider_id=provider.id,
                            indicator_id=indicator.id,
                            lookup_type=indicator.indicator_type.value,
                            verdict=verdict,
                            confidence=confidence,
                            queried_at=utcnow(),
                            expires_at=utcnow() + timedelta(minutes=15),
                            raw_response=json_safe(payload),
                        )
                        session.add(lookup)
                        session.flush()
                        lookup_rows.append((lookup, matched))
                        if matched:
                            session.add(CTIMatch(
                                lookup_result_id=lookup.id,
                                event_id=stored_event.id,
                                match_type="vulnerability" if verdict == "vulnerable" else "ioc_reputation",
                                severity=severity(str(result.get("risk_level"))),
                                summary=f"{provider_name.value} returned {verdict} evidence.",
                            ))

                if result.get("is_threat"):
                    has_vulnerability = any(row.verdict == "vulnerable" and matched for row, matched in lookup_rows)
                    has_malicious_ioc = any(row.verdict == "malicious" and matched for row, matched in lookup_rows)
                    classification = (
                        AlertClassification.security_vulnerability
                        if has_vulnerability
                        else AlertClassification.active_attack
                        if has_malicious_ioc
                        else AlertClassification.needs_review
                    )
                    alert = Alert(
                        event_id=stored_event.id,
                        asset_id=asset.id if asset else None,
                        classification=classification,
                        severity=severity(str(result.get("risk_level"))),
                        status=AlertStatus.open,
                        final_score=float(result.get("risk_score", 0.0)) / 100.0,
                        title=f"{result['prediction']['predicted_family']} detected — {result.get('risk_level', 'review').title()}",
                        description="CatBoost prediction fused with live OTX, VirusTotal, OSV, and NVD evidence.",
                    )
                    session.add(alert)
                    session.flush()
                    session.add_all([
                        AlertEvidence(
                            alert_id=alert.id,
                            evidence_type="model_prediction",
                            source_table="model_predictions",
                            source_id=prediction.id,
                            weight=float(result["prediction"]["confidence"]),
                            summary=f"CatBoost predicted {result['prediction']['predicted_family']}.",
                            details=json_safe(result["prediction"]),
                        ),
                        AlertEvidence(
                            alert_id=alert.id,
                            evidence_type="dashboard_snapshot",
                            source_table="flask_investigation",
                            weight=float(result.get("risk_score", 0.0)) / 100.0,
                            summary="Complete dashboard alert and recommended actions.",
                            details={"dashboard_log": json_safe(dashboard_log)},
                        ),
                    ])
                session.commit()
                return investigation_id
            except Exception:
                session.rollback()
                raise

    def list_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        factory = get_session_factory()
        with factory() as session:
            rows = session.execute(
                select(Alert, HospitalEvent.external_event_id)
                .outerjoin(HospitalEvent, Alert.event_id == HospitalEvent.id)
                .order_by(Alert.created_at.desc())
                .limit(limit)
            ).all()
            return [
                {
                    "id": str(alert.id),
                    "event_id": event_id,
                    "classification": alert.classification.value,
                    "severity": alert.severity.value,
                    "status": alert.status.value,
                    "final_score": float(alert.final_score),
                    "title": alert.title,
                    "description": alert.description,
                    "created_at": alert.created_at.isoformat(),
                }
                for alert, event_id in rows
            ]

    def list_dashboard_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        factory = get_session_factory()
        with factory() as session:
            alerts = session.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(limit)).all()
            output: list[dict[str, Any]] = []
            for alert in alerts:
                snapshot = session.scalar(
                    select(AlertEvidence).where(
                        AlertEvidence.alert_id == alert.id,
                        AlertEvidence.evidence_type == "dashboard_snapshot",
                    )
                )
                if snapshot and snapshot.details.get("dashboard_log"):
                    output.append(snapshot.details["dashboard_log"])
                else:
                    output.append({
                        "log_id": str(alert.id),
                        "date": alert.created_at.strftime("%Y-%m-%d"),
                        "timestamp": alert.created_at.strftime("%H:%M:%S"),
                        "traffic_class": alert.classification.value,
                        "risk_level": alert.severity.value,
                        "risk_probability": alert.final_score,
                        "is_threat": 1,
                        "recommended_actions": [],
                    })
            return output
