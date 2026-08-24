"""Persist live CTI enrichment, model scores, CVE posture, and alerts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from cti.db.models import (
    Alert,
    AlertClassification,
    AlertEvidence,
    AlertStatus,
    Asset,
    AssetType,
    AssetVulnerability,
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
    Vulnerability,
)
from cti.db.session import get_session_factory
from cti.intelligence import classify_indicator, is_public_indicator
from cti.extraction import extract_indicators


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def severity_from_value(value: str | float | None) -> Severity:
    if isinstance(value, (int, float)):
        if value >= 9:
            return Severity.critical
        if value >= 7:
            return Severity.high
        if value >= 4:
            return Severity.medium
        if value > 0:
            return Severity.low
        return Severity.info
    normalized = str(value or "").lower()
    return Severity(normalized) if normalized in Severity._value2member_map_ else Severity.info


class CTIPersistenceService:
    """Small synchronous repository used from async routes through ``to_thread``."""

    def _provider(self, session: Session, name: ProviderName) -> CTIProvider:
        provider = session.scalar(select(CTIProvider).where(CTIProvider.name == name))
        if provider is None:
            raise RuntimeError(f"CTI provider {name.value} has not been seeded. Run import_static_data.py.")
        return provider

    def _indicator(self, session: Session, raw_value: str) -> Indicator:
        value, kind = classify_indicator(raw_value)
        indicator_type = IndicatorType(kind)
        public = is_public_indicator(value, kind)
        indicator = session.scalar(
            select(Indicator).where(
                Indicator.indicator_type == indicator_type,
                Indicator.normalized_value == value,
            )
        )
        if indicator is None:
            indicator = Indicator(
                indicator_type=indicator_type,
                normalized_value=value,
                is_public=public,
                first_seen_at=now_utc(),
                last_seen_at=now_utc(),
            )
            session.add(indicator)
            session.flush()
        else:
            indicator.last_seen_at = now_utc()
        return indicator

    def _reference_indicator(
        self, session: Session, indicator_type: IndicatorType, normalized_value: str
    ) -> Indicator:
        """Create local OSV/NVD reference indicators without external IoC handling."""
        indicator = session.scalar(
            select(Indicator).where(
                Indicator.indicator_type == indicator_type,
                Indicator.normalized_value == normalized_value,
            )
        )
        if indicator is None:
            indicator = Indicator(
                indicator_type=indicator_type,
                normalized_value=normalized_value,
                is_public=False,
                first_seen_at=now_utc(),
                last_seen_at=now_utc(),
            )
            session.add(indicator)
            session.flush()
        else:
            indicator.last_seen_at = now_utc()
        return indicator

    @staticmethod
    def _provider_verdict(provider: ProviderName, result: Mapping[str, Any]) -> tuple[str, float, bool]:
        if not result.get("available"):
            return "unavailable", 0.0, False
        if provider is ProviderName.otx:
            pulses = int(result.get("pulse_count", 0) or 0)
            return ("malicious" if pulses else "clean"), min(1.0, pulses / 4), pulses > 0
        if provider is ProviderName.virustotal:
            malicious = int(result.get("malicious", 0) or 0)
            suspicious = int(result.get("suspicious", 0) or 0)
            total = max(1, int(result.get("total_engines", 0) or 0))
            confidence = min(1.0, (malicious + 0.5 * suspicious) / total * 4)
            return ("malicious" if malicious or suspicious > 1 else "clean"), confidence, bool(malicious or suspicious > 1)
        if provider is ProviderName.osv:
            found = bool(result.get("found"))
            return ("vulnerable" if found else "not_found"), (0.65 if found else 0.0), found
        if provider is ProviderName.nvd:
            records = result.get("records") or []
            found = bool(result.get("found") or records)
            max_cvss = max((float(item.get("cvss", 0.0) or 0.0) for item in records), default=0.0)
            known_exploited = any(bool(item.get("known_exploited")) for item in records)
            confidence = max(0.55, min(0.95, 0.5 + 0.35 * (max_cvss / 10.0) + (0.1 if known_exploited else 0.0))) if found else 0.0
            return ("vulnerable" if found else "not_found"), confidence, found
        return "unknown", 0.0, False

    def _upsert_lookup(
        self,
        session: Session,
        provider_name: ProviderName,
        indicator: Indicator,
        payload: Mapping[str, Any],
    ) -> tuple[CTILookupResult, bool]:
        provider = self._provider(session, provider_name)
        verdict, confidence, matched = self._provider_verdict(provider_name, payload)
        result = session.scalar(
            select(CTILookupResult)
            .where(
                CTILookupResult.provider_id == provider.id,
                CTILookupResult.indicator_id == indicator.id,
            )
            .order_by(CTILookupResult.queried_at.desc())
        )
        values = {
            "lookup_type": indicator.indicator_type.value,
            "verdict": verdict,
            "confidence": confidence,
            "queried_at": now_utc(),
            "expires_at": now_utc() + timedelta(minutes=15),
            "raw_response": dict(payload),
        }
        if result is None:
            result = CTILookupResult(provider_id=provider.id, indicator_id=indicator.id, **values)
            session.add(result)
            session.flush()
        else:
            for key, value in values.items():
                setattr(result, key, value)
        return result, matched

    def _upsert_reference_lookup(
        self,
        session: Session,
        provider_name: ProviderName,
        indicator: Indicator,
        verdict: str,
        confidence: float,
        payload: Mapping[str, Any],
    ) -> CTILookupResult:
        provider = self._provider(session, provider_name)
        result = session.scalar(
            select(CTILookupResult)
            .where(
                CTILookupResult.provider_id == provider.id,
                CTILookupResult.indicator_id == indicator.id,
            )
            .order_by(CTILookupResult.queried_at.desc())
        )
        values = {
            "lookup_type": indicator.indicator_type.value,
            "verdict": verdict,
            "confidence": min(max(confidence, 0.0), 1.0),
            "queried_at": now_utc(),
            "expires_at": now_utc() + timedelta(hours=6),
            "raw_response": dict(payload),
        }
        if result is None:
            result = CTILookupResult(provider_id=provider.id, indicator_id=indicator.id, **values)
            session.add(result)
            session.flush()
        else:
            for key, value in values.items():
                setattr(result, key, value)
        return result

    def persist_indicator_lookup(self, raw_indicator: str, enrichment: Mapping[str, Any]) -> None:
        """Store a direct public lookup even when it is not attached to an event."""
        factory = get_session_factory()
        with factory() as session:
            try:
                indicator = self._indicator(session, raw_indicator)
                for source_name, payload in (enrichment.get("sources") or {}).items():
                    provider_name = ProviderName(source_name)
                    self._upsert_lookup(session, provider_name, indicator, payload)
                session.commit()
            except Exception:
                session.rollback()
                raise

    def list_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return a safe analyst view of persisted fusion alerts and evidence."""
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
                    "event_id": external_event_id,
                    "classification": alert.classification.value,
                    "severity": alert.severity.value,
                    "status": alert.status.value,
                    "final_score": round(float(alert.final_score), 4),
                    "title": alert.title,
                    "description": alert.description,
                    "created_at": alert.created_at.isoformat() if alert.created_at else None,
                    "updated_at": alert.updated_at.isoformat() if alert.updated_at else None,
                }
                for alert, external_event_id in rows
            ]

    def persist_assessment(
        self,
        event: Mapping[str, Any],
        enrichment: Mapping[str, Any],
        score: Mapping[str, Any],
        indicator_enrichments: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        external_event_id = str(event.get("event_id") or "").strip()
        if not external_event_id:
            return

        factory = get_session_factory()
        with factory() as session:
            try:
                stored_event = session.scalar(
                    select(HospitalEvent).where(HospitalEvent.external_event_id == external_event_id)
                )
                if stored_event is None:
                    return

                for candidate in extract_indicators(event):
                    indicator = self._indicator(session, candidate.value)
                    link = session.scalar(
                        select(EventIndicator).where(
                            EventIndicator.event_id == stored_event.id,
                            EventIndicator.indicator_id == indicator.id,
                            EventIndicator.extraction_field == candidate.field,
                        )
                    )
                    if link is None:
                        session.add(
                            EventIndicator(
                                event_id=stored_event.id,
                                indicator_id=indicator.id,
                                extraction_field=candidate.field,
                            )
                        )

                lookup_results: list[tuple[CTILookupResult, bool]] = []
                lookup_evidence = indicator_enrichments or [enrichment]
                seen_lookup_keys: set[tuple[ProviderName, object]] = set()
                for lookup in lookup_evidence:
                    lookup_value = str(lookup.get("indicator") or "")
                    if not lookup_value:
                        continue
                    try:
                        source_indicator = self._indicator(session, lookup_value)
                        if source_indicator.is_public:
                            for source_name, payload in (lookup.get("sources") or {}).items():
                                provider_name = ProviderName(source_name)
                                dedupe_key = (provider_name, source_indicator.id)
                                if dedupe_key in seen_lookup_keys:
                                    continue
                                seen_lookup_keys.add(dedupe_key)
                                lookup_results.append(
                                    self._upsert_lookup(session, provider_name, source_indicator, payload)
                                )
                    except ValueError:
                        pass

                model = session.scalar(select(ModelVersion).order_by(ModelVersion.trained_at.desc()))
                prediction: ModelPrediction | None = None
                if model is not None:
                    prediction = session.scalar(
                        select(ModelPrediction).where(
                            ModelPrediction.event_id == stored_event.id,
                            ModelPrediction.model_version_id == model.id,
                        )
                    )
                    prediction_values = {
                        "probability": float(score.get("probability", 0.0)),
                        "risk_level": severity_from_value(score.get("risk_level")),
                        "predicted_class": "threat" if score.get("is_threat") else "benign",
                        "feature_snapshot": dict(event),
                        "predicted_at": now_utc(),
                    }
                    if prediction is None:
                        prediction = ModelPrediction(event_id=stored_event.id, model_version_id=model.id, **prediction_values)
                        session.add(prediction)
                        session.flush()
                    else:
                        for key, value in prediction_values.items():
                            setattr(prediction, key, value)

                self._persist_alert(session, stored_event, enrichment, score, lookup_results, prediction)
                session.commit()
            except Exception:
                session.rollback()
                raise

    def _persist_alert(
        self,
        session: Session,
        event: HospitalEvent,
        enrichment: Mapping[str, Any],
        score: Mapping[str, Any],
        lookup_results: list[tuple[CTILookupResult, bool]],
        prediction: ModelPrediction | None,
    ) -> None:
        probability = float(score.get("probability", 0.0))
        if probability < 0.35:
            return
        provider_matches = [entry for entry in lookup_results if entry[1]]
        provider_names = {entry[0].provider_id for entry in provider_matches}
        indicator_type = str(enrichment.get("type") or "")
        if enrichment.get("verdict") == "malicious" and (
            indicator_type in {"md5", "sha1", "sha256", "url", "domain"}
            or len(provider_names) >= 2
        ):
            classification = AlertClassification.active_attack
        elif enrichment.get("verdict") == "malicious" and indicator_type in {"ipv4", "ipv6"}:
            classification = AlertClassification.malicious_ip
        elif probability >= 0.65:
            classification = AlertClassification.unauthorized_access
        else:
            classification = AlertClassification.needs_review
        severity = severity_from_value(score.get("risk_level"))
        alert = session.scalar(
            select(Alert).where(
                Alert.event_id == event.id,
                Alert.status.in_([AlertStatus.open, AlertStatus.investigating]),
            )
        )
        title = f"{classification.value.replace('_', ' ').title()} — {event.traffic_type or 'hospital telemetry'}"
        if alert is None:
            alert = Alert(
                event_id=event.id,
                asset_id=event.asset_id,
                classification=classification,
                severity=severity,
                final_score=probability,
                title=title,
                description="Automated CTI fusion classification from static telemetry and live intelligence.",
            )
            session.add(alert)
            session.flush()
        else:
            alert.classification = classification
            alert.severity = severity
            alert.final_score = probability
            alert.title = title
            alert.updated_at = now_utc()

        evidence = [("telemetry_model", "model_predictions", prediction.id if prediction else None, float(score.get("base_probability", 0.0)), "ML telemetry assessment")]
        for result, matched in lookup_results:
            if matched:
                cti_match = session.scalar(
                    select(CTIMatch).where(
                        CTIMatch.lookup_result_id == result.id,
                        CTIMatch.event_id == event.id,
                    )
                )
                if cti_match is None:
                    session.add(
                        CTIMatch(
                            lookup_result_id=result.id,
                            event_id=event.id,
                            match_type="ioc_reputation",
                            severity=severity,
                            summary=f"Live CTI provider classified the event indicator as {result.verdict}.",
                        )
                    )
            evidence.append(
                (
                    "cti_match" if matched else "cti_lookup",
                    "cti_lookup_results",
                    result.id,
                    result.confidence,
                    f"{result.verdict.title()} result from live CTI provider",
                )
            )
        for evidence_type, source_table, source_id, weight, summary in evidence:
            existing = session.scalar(
                select(AlertEvidence).where(
                    AlertEvidence.alert_id == alert.id,
                    AlertEvidence.evidence_type == evidence_type,
                    AlertEvidence.source_id == source_id,
                )
            )
            if existing is None:
                session.add(
                    AlertEvidence(
                        alert_id=alert.id,
                        evidence_type=evidence_type,
                        source_table=source_table,
                        source_id=source_id,
                        weight=weight,
                        summary=summary,
                    )
                )

    def sync_vulnerability_posture(self, posture: Mapping[str, Any]) -> None:
        """Persist OSV/NVD results produced by the dependency posture refresh."""
        if posture.get("state") != "ready":
            return
        factory = get_session_factory()
        with factory() as session:
            try:
                asset = session.scalar(select(Asset).where(Asset.asset_tag == "CTI-APPLICATION"))
                if asset is None:
                    asset = Asset(
                        asset_tag="CTI-APPLICATION",
                        asset_type=AssetType.application,
                        manufacturer="Healthcare CTI Fusion",
                        model="application dependency inventory",
                        criticality=0.9,
                        department="security operations",
                        metadata_json={"purpose": "OSV/NVD dependency posture"},
                    )
                    session.add(asset)
                    session.flush()
                for item in posture.get("vulnerabilities") or []:
                    aliases = item.get("aliases") or []
                    cve_id = next((alias for alias in aliases if str(alias).upper().startswith("CVE-")), None)
                    osv_id = item.get("id")
                    vulnerability = session.scalar(select(Vulnerability).where(Vulnerability.osv_id == osv_id)) if osv_id else None
                    if vulnerability is None and cve_id:
                        vulnerability = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
                    nvd_records = item.get("nvd") or []
                    nvd = nvd_records[0] if nvd_records else {}
                    values = {
                        "cve_id": cve_id,
                        "osv_id": osv_id,
                        "title": item.get("summary"),
                        "description": item.get("summary"),
                        "cvss_score": nvd.get("cvss", item.get("max_cvss")),
                        "severity": severity_from_value(nvd.get("severity") or item.get("max_cvss")),
                        "known_exploited": bool(nvd.get("known_exploited") or item.get("known_exploited")),
                        "raw_data": dict(item),
                    }
                    if vulnerability is None:
                        vulnerability = Vulnerability(**values)
                        session.add(vulnerability)
                        session.flush()
                    else:
                        for key, value in values.items():
                            setattr(vulnerability, key, value)
                    package = item.get("package") or {}
                    package_name = str(package.get("name") or "unknown")
                    package_version = str(package.get("version") or "unknown")
                    ecosystem = str(package.get("ecosystem") or "generic").lower()
                    package_reference = f"pkg:{ecosystem}/{package_name}@{package_version}"
                    osv_indicator = self._reference_indicator(session, IndicatorType.purl, package_reference)
                    self._upsert_reference_lookup(
                        session,
                        ProviderName.osv,
                        osv_indicator,
                        "affected",
                        1.0,
                        item,
                    )
                    if cve_id:
                        cve_indicator = self._reference_indicator(session, IndicatorType.cve, cve_id)
                        self._upsert_reference_lookup(
                            session,
                            ProviderName.nvd,
                            cve_indicator,
                            str(nvd.get("severity") or "unknown").lower(),
                            float(nvd.get("cvss", 0.0) or 0.0) / 10,
                            nvd or {"cve_id": cve_id},
                        )
                    exposure = session.scalar(
                        select(AssetVulnerability).where(
                            AssetVulnerability.asset_id == asset.id,
                            AssetVulnerability.vulnerability_id == vulnerability.id,
                        )
                    )
                    if exposure is None:
                        session.add(
                            AssetVulnerability(
                                asset_id=asset.id,
                                vulnerability_id=vulnerability.id,
                                match_source="osv_nvd",
                            )
                        )
                session.commit()
            except Exception:
                session.rollback()
                raise
