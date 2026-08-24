from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Mapping

import joblib
import pandas as pd

from cti.log_data import MODEL_FEATURES, feature_record
from cti.rules import RuleAssessment, assess_rules


FEATURES = MODEL_FEATURES
LABEL_CLASSES = ["benign", "suspicious", "threat"]


def safe_number(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
        return default if math.isnan(number) or math.isinf(number) else number
    except (TypeError, ValueError):
        return default


def extract_features(event: Mapping[str, Any]) -> dict[str, Any]:
    return feature_record(event)


class ThreatRiskEngine:
    """Three behavioral models fused with auditable rules and live CTI."""

    def __init__(self, artifact_path: Path):
        self.artifact_path = artifact_path
        self.models: dict[str, Any] = {}
        self.label_classes = LABEL_CLASSES
        self.metadata: dict[str, Any] = {
            "status": "fallback",
            "message": "No compatible trained model artifact is loaded.",
            "features": FEATURES,
        }
        self.reload()

    def reload(self) -> None:
        try:
            artifact = joblib.load(self.artifact_path)
            if not isinstance(artifact, dict) or "models" not in artifact:
                raise ValueError("Legacy single-model artifact; run train_model.py to replace it.")
            if artifact.get("features") != FEATURES:
                raise ValueError("Model feature schema does not match the active hospital log dataset.")
            expected = {"patient_access", "employee_activity", "system_device"}
            if set(artifact["models"]) != expected:
                raise ValueError("Model artifact must contain patient, employee, and system/device models.")
            self.models = artifact["models"]
            self.label_classes = artifact.get("label_classes", LABEL_CLASSES)
            self.metadata = {
                **artifact.get("metadata", {}),
                "status": "trained",
                "features": FEATURES,
                "artifact": str(self.artifact_path),
            }
        except Exception as exc:
            self.models = {}
            self.metadata = {
                "status": "fallback",
                "message": str(exc),
                "features": FEATURES,
                "artifact": str(self.artifact_path),
            }

    @staticmethod
    def _log_type(event: Mapping[str, Any], record: Mapping[str, Any]) -> str | None:
        raw = str(record.get("log_type") or "").strip().lower()
        aliases = {
            "patient access logs": "patient_access",
            "employee activity logs": "employee_activity",
            "system and device logs": "system_device",
        }
        raw = aliases.get(raw, raw)
        if raw in {"patient_access", "employee_activity", "system_device"}:
            return raw
        if str(event.get("device_type") or "").strip() and str(event.get("protocol") or "").strip():
            return "system_device"
        if str(event.get("data_field_accessed") or "").strip():
            return "patient_access"
        if str(event.get("role") or event.get("actor_role") or "").strip():
            return "employee_activity"
        return None

    def behavioral_prediction(self, event: Mapping[str, Any]) -> dict[str, Any]:
        record = extract_features(event)
        log_type = self._log_type(event, record)
        if log_type and log_type in self.models:
            model = self.models[log_type]
            values = pd.DataFrame.from_records([record], columns=FEATURES)
            probabilities_raw = model.predict_proba(values)[0]
            probabilities = {
                str(label): round(float(probabilities_raw[position]), 6)
                for position, label in enumerate(model.classes_)
            }
            predicted_label = max(probabilities, key=probabilities.get)
            signal = min(
                1.0,
                safe_number(probabilities.get("threat"))
                + 0.5 * safe_number(probabilities.get("suspicious")),
            )
            return {
                "log_type": log_type,
                "predicted_label": predicted_label,
                "probabilities": probabilities,
                "risk_signal": round(signal, 6),
                "model_available": True,
            }

        rule = assess_rules(event)
        fallback_probabilities = {
            "benign": 0.9 if rule.label == "benign" else 0.05,
            "suspicious": 0.9 if rule.label == "suspicious" else 0.05,
            "threat": 0.9 if rule.label == "threat" else 0.05,
        }
        return {
            "log_type": log_type or "unknown",
            "predicted_label": rule.label,
            "probabilities": fallback_probabilities,
            "risk_signal": rule.risk_score,
            "model_available": False,
        }

    def base_probability(self, event: Mapping[str, Any]) -> float:
        return float(self.behavioral_prediction(event)["risk_signal"])

    @staticmethod
    def _rule_payload(rule: RuleAssessment) -> dict[str, Any]:
        return {
            "label": rule.label,
            "attack_type": rule.attack_type,
            "confidence": rule.confidence,
            "rule_id": rule.rule_id,
            "reason": rule.reason,
            "risk_score": rule.risk_score,
            "label_source": "Rule engine v1 (synthetic; pending human validation)",
        }

    def score(
        self,
        event: Mapping[str, Any],
        enrichment: Mapping[str, Any] | None,
        posture: Mapping[str, Any] | None,
        asset_criticality: float = 0.5,
    ) -> dict[str, Any]:
        behavioral = self.behavioral_prediction(event)
        rule = assess_rules(event)
        behavioral_signal = min(
            max(float(behavioral["risk_signal"]), float(rule.risk_score)), 1.0
        )
        enrichment = enrichment or {}
        posture = posture or {}
        external_confidence = min(max(safe_number(enrichment.get("confidence")), 0.0), 1.0)
        intel_verdict = str(enrichment.get("verdict") or "unknown").lower()
        if intel_verdict == "malicious":
            external_signal = 0.92 * external_confidence
        elif intel_verdict == "vulnerable":
            # A vulnerable package/asset needs remediation, but is not proof of
            # an active attack on this particular log event.
            external_signal = 0.35 * external_confidence
        else:
            external_signal = 0.0

        vulnerability_count = int(posture.get("vulnerability_count", 0) or 0)
        max_cvss = safe_number(posture.get("max_cvss"), 0.0) / 10.0
        known_exploited = int(posture.get("known_exploited_count", 0) or 0)
        criticality = min(max(safe_number(asset_criticality, 0.5), 0.0), 1.0)
        posture_signal = min(
            0.3,
            (0.12 * max_cvss + (0.13 if known_exploited else 0.0)) * criticality
            if vulnerability_count
            else 0.0,
        )

        probability = 1 - (1 - behavioral_signal) * (1 - external_signal) * (1 - posture_signal)
        probability = round(min(max(probability, 0.0), 1.0), 4)
        if probability >= 0.85:
            risk_level = "critical"
        elif probability >= 0.65:
            risk_level = "high"
        elif probability >= 0.35:
            risk_level = "medium"
        else:
            risk_level = "low"

        is_threat = int(
            rule.label == "threat"
            or (intel_verdict == "malicious" and external_confidence >= 0.3)
            or probability >= 0.65
        )
        final_classification = "threat" if is_threat else ("suspicious" if probability >= 0.35 else "benign")
        reasons = [
            f"{behavioral['log_type']} model classification: {behavioral['predicted_label']} "
            f"(behavioral signal {float(behavioral['risk_signal']):.1%}).",
            f"Rule {rule.rule_id}: {rule.reason}",
        ]
        if intel_verdict == "malicious":
            reasons.append(f"Live IOC intelligence confirmed malicious evidence at {external_confidence:.1%} confidence.")
        elif intel_verdict == "vulnerable":
            reasons.append(f"Live vulnerability databases confirmed exposure at {external_confidence:.1%} confidence; this is not treated as proof of an active attack.")
        if known_exploited:
            reasons.append(f"Project posture contains {known_exploited} CISA known-exploited CVE(s).")
        elif vulnerability_count:
            reasons.append(f"Project posture contains {vulnerability_count} dependency vulnerability finding(s).")

        return {
            "probability": probability,
            "base_probability": round(behavioral_signal, 4),
            "behavioral_model": behavioral,
            "rule_assessment": self._rule_payload(rule),
            "final_classification": final_classification,
            "risk_level": risk_level,
            "is_threat": is_threat,
            "reasons": reasons,
            "evidence": {
                "behavioral_model": round(float(behavioral["risk_signal"]), 4),
                "rule_signal": round(float(rule.risk_score), 4),
                "external_intelligence": round(external_signal, 4),
                "external_verdict": intel_verdict,
                "project_posture": round(posture_signal, 4),
                "asset_criticality": criticality,
            },
        }
