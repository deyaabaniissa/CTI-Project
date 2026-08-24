from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Mapping

import joblib
import numpy as np
import pandas as pd


DEFAULT_FEATURES = [
    "IAT",
    "rst_count",
    "Number",
    "Tot size",
    "psh_flag_number",
    "Min",
    "Rate",
    "Header_Length",
    "ack_count",
    "Protocol Type",
    "Tot sum",
    "Max",
]


def _finite_number(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Expected a numeric value, received {value!r}.") from exc
    if math.isnan(number) or math.isinf(number):
        raise ValueError("Feature values must be finite numbers.")
    return number


class CatBoostIDSService:
    """Load the Kaggle artifact once and expose a small prediction API."""

    def __init__(self, artifact_path: Path):
        self.artifact_path = artifact_path.resolve()
        self.model: Any | None = None
        self.features: list[str] = DEFAULT_FEATURES.copy()
        self.classes: list[str] = []
        self.metrics: dict[str, float] = {}
        self.metadata: dict[str, Any] = {}
        self.reload()

    def reload(self) -> None:
        if not self.artifact_path.is_file():
            raise FileNotFoundError(f"CatBoost artifact not found: {self.artifact_path}")

        artifact = joblib.load(self.artifact_path)
        if not isinstance(artifact, dict) or "model" not in artifact:
            raise ValueError("The CatBoost artifact must be a dictionary containing 'model'.")

        self.model = artifact["model"]
        self.features = list(
            artifact.get("selected_features")
            or artifact.get("feature_columns")
            or artifact.get("features")
            or DEFAULT_FEATURES
        )
        if len(self.features) != 12:
            raise ValueError(f"Expected 12 model features, found {len(self.features)}.")

        label_encoder = artifact.get("label_encoder")
        if label_encoder is not None and hasattr(label_encoder, "classes_"):
            self.classes = [str(value) for value in label_encoder.classes_]
        elif hasattr(self.model, "classes_"):
            self.classes = [str(value) for value in self.model.classes_]
        else:
            self.classes = ["Benign", "DDoS", "DoS", "MQTT", "Recon", "Spoofing"]

        self.metrics = {
            key: float(value)
            for key, value in (artifact.get("metrics") or {}).items()
            if isinstance(value, (int, float, np.number))
        }
        feature_importance: list[dict[str, Any]] = []
        if hasattr(self.model, "get_feature_importance"):
            raw_importance = np.asarray(self.model.get_feature_importance()).reshape(-1)
            feature_importance = [
                {"feature": feature, "importance": round(float(raw_importance[index]), 6)}
                for index, feature in enumerate(self.features)
                if index < len(raw_importance)
            ]
            feature_importance.sort(key=lambda row: row["importance"], reverse=True)

        balance_audit: list[dict[str, Any]] = []
        raw_balance = artifact.get("balance_audit")
        if isinstance(raw_balance, pd.DataFrame):
            for row in raw_balance.to_dict(orient="records"):
                balance_audit.append({
                    "family": str(row.get("family", "Unknown")),
                    "source_rows": int(row.get("source_rows", 0)),
                    "balanced_rows": int(row.get("balanced_rows", 0)),
                    "oversampled": bool(row.get("oversampled", False)),
                })

        self.metadata = {
            "status": "trained",
            "artifact": str(self.artifact_path),
            "model_name": artifact.get("model_name", "CICIoMT2024 CatBoost"),
            "features": self.features,
            "classes": self.classes,
            "metrics": self.metrics,
            "feature_importance": feature_importance,
            "training_dataset": {
                "name": "CICIoMT2024",
                "balance_audit": balance_audit,
                "target_rows_per_family": int(artifact.get("target_rows_per_family") or 0),
                "train_attack_subclasses": len(artifact.get("train_attack_names") or []),
                "test_attack_subclasses": len(artifact.get("test_attack_names") or []),
                "zero_row_rule": str(artifact.get("zero_row_rule") or ""),
            },
            "excluded_family": artifact.get("excluded_family"),
            "profile_train_files": len(artifact.get("profile_train_files") or []),
            "profile_holdout_files": len(artifact.get("profile_holdout_files") or []),
        }

    def _record(self, event: Mapping[str, Any]) -> dict[str, float]:
        nested = event.get("features")
        source: Mapping[str, Any] = nested if isinstance(nested, Mapping) else event
        missing = [feature for feature in self.features if feature not in source]
        if missing:
            raise ValueError("Missing CatBoost features: " + ", ".join(missing))
        return {feature: _finite_number(source[feature]) for feature in self.features}

    def predict(self, event: Mapping[str, Any]) -> dict[str, Any]:
        if self.model is None:
            raise RuntimeError("CatBoost model is not loaded.")
        record = self._record(event)
        frame = pd.DataFrame([record], columns=self.features, dtype="float32")
        raw_prediction = np.asarray(self.model.predict(frame)).reshape(-1)[0]
        probabilities_raw = np.asarray(self.model.predict_proba(frame))[0]

        try:
            predicted_index = int(float(raw_prediction))
            predicted_family = self.classes[predicted_index]
        except (TypeError, ValueError, IndexError):
            predicted_family = str(raw_prediction)
            predicted_index = (
                self.classes.index(predicted_family)
                if predicted_family in self.classes
                else int(np.argmax(probabilities_raw))
            )

        probabilities = {
            family: round(float(probabilities_raw[index]), 6)
            for index, family in enumerate(self.classes)
            if index < len(probabilities_raw)
        }
        confidence = float(probabilities_raw[predicted_index])
        return {
            "predicted_family": predicted_family,
            "confidence": round(confidence, 6),
            "probabilities": probabilities,
            "features": record,
            "model": self.metadata["model_name"],
        }
