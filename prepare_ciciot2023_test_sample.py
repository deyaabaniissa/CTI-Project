"""Create and evaluate a reproducible 200-row CICIoT2023 TEST sample.

The external sample is never used for training, validation, balancing, feature
selection, or threshold selection. It contains 40 rows from each family that
can be mapped honestly to the six-family CICIoMT2024 CatBoost label space:
Benign, DDoS, DoS, Recon, and Spoofing. MQTT is absent from CICIoT2023.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    f1_score,
)


PROJECT_ROOT = Path(__file__).resolve().parent
SOURCE_PATH = PROJECT_ROOT / "test_23.csv"
MODEL_PATH = PROJECT_ROOT / "official_ciciomt2024_catboost_12_features_6_classes.joblib"
OUTPUT_DIR = PROJECT_ROOT / "data" / "evaluation"
SAMPLE_PATH = OUTPUT_DIR / "ciciot2023_test_200.csv"
PREDICTIONS_PATH = OUTPUT_DIR / "ciciot2023_test_200_predictions.csv"
METRICS_PATH = OUTPUT_DIR / "ciciot2023_test_200_metrics.json"

ROWS_PER_FAMILY = 40
SEED = 42
TARGET_FAMILIES = ("Benign", "DDoS", "DoS", "Recon", "Spoofing")


def map_external_family(label: str) -> str | None:
    """Map only labels with a defensible equivalent in the trained model."""
    normalized = str(label).strip()
    if normalized == "BenignTraffic":
        return "Benign"
    if normalized.startswith("DDoS-"):
        return "DDoS"
    if normalized.startswith("DoS-"):
        return "DoS"
    if normalized.startswith("Recon-") or normalized == "VulnerabilityScan":
        return "Recon"
    if normalized in {"DNS_Spoofing", "MITM-ArpSpoofing"}:
        return "Spoofing"
    return None


def select_balanced_sample(features: list[str]) -> tuple[pd.DataFrame, dict[str, int], int]:
    rng = np.random.default_rng(SEED)
    reservoirs: dict[str, pd.DataFrame] = {}
    available_counts = {family: 0 for family in TARGET_FAMILIES}
    removed_invalid = 0
    required_columns = set(features) | {"label"}

    for chunk in pd.read_csv(
        SOURCE_PATH,
        usecols=lambda column: str(column).strip() in required_columns,
        chunksize=100_000,
        low_memory=False,
    ):
        chunk = chunk.rename(columns={column: str(column).strip() for column in chunk.columns})
        chunk["original_label"] = chunk["label"].astype(str).str.strip()
        chunk["true_family"] = chunk["original_label"].map(map_external_family)
        chunk = chunk.loc[chunk["true_family"].notna()].copy()
        if chunk.empty:
            continue

        chunk["source_row_number"] = chunk.index.astype("int64") + 2
        for feature in features:
            chunk[feature] = pd.to_numeric(chunk[feature], errors="coerce")
        chunk[features] = chunk[features].replace([np.inf, -np.inf], np.nan).fillna(0.0)
        valid = chunk[features].ne(0).any(axis=1)
        removed_invalid += int((~valid).sum())
        chunk = chunk.loc[valid]

        for family in TARGET_FAMILIES:
            candidates = chunk.loc[chunk["true_family"] == family].copy()
            available_counts[family] += len(candidates)
            if candidates.empty:
                continue
            candidates["__priority__"] = rng.random(len(candidates))
            combined = pd.concat(
                [reservoirs.get(family, candidates.iloc[0:0]), candidates],
                ignore_index=True,
            )
            reservoirs[family] = combined.nsmallest(ROWS_PER_FAMILY, "__priority__")

    missing = [family for family in TARGET_FAMILIES if len(reservoirs.get(family, [])) < ROWS_PER_FAMILY]
    if missing:
        raise RuntimeError(f"Not enough valid TEST rows for: {', '.join(missing)}")

    sample = pd.concat([reservoirs[family] for family in TARGET_FAMILIES], ignore_index=True)
    sample = sample.drop(columns=["label", "__priority__"])
    sample = sample.sample(frac=1.0, random_state=SEED).reset_index(drop=True)
    sample.insert(0, "sample_id", [f"CIC23-TEST-{number:03d}" for number in range(1, len(sample) + 1)])
    sample.insert(1, "source_dataset", "CICIoT2023")
    sample.insert(2, "source_split", "TEST")
    return sample, available_counts, removed_invalid


def main() -> None:
    if not SOURCE_PATH.is_file():
        raise FileNotFoundError(f"Missing external TEST file: {SOURCE_PATH}")
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"Missing CatBoost artifact: {MODEL_PATH}")

    artifact = joblib.load(MODEL_PATH)
    features = list(artifact["selected_features"])
    model = artifact["model"]
    label_encoder = artifact["label_encoder"]
    sample, available_counts, removed_invalid = select_balanced_sample(features)

    matrix = sample[features].astype("float32")
    encoded_predictions = np.asarray(model.predict(matrix)).astype(int).ravel()
    predicted_families = label_encoder.inverse_transform(encoded_predictions)
    probabilities = np.asarray(model.predict_proba(matrix))

    predictions = sample.copy()
    predictions["predicted_family"] = predicted_families
    predictions["confidence"] = probabilities.max(axis=1)
    predictions["correct"] = predictions["true_family"] == predictions["predicted_family"]

    y_true = predictions["true_family"]
    y_pred = predictions["predicted_family"]
    labels = list(TARGET_FAMILIES)
    metrics = {
        "training_dataset": "CICIoMT2024",
        "external_dataset": "CICIoT2023",
        "external_split": "TEST",
        "source_file": SOURCE_PATH.name,
        "sample_rows": len(predictions),
        "rows_per_true_family": ROWS_PER_FAMILY,
        "sampling_seed": SEED,
        "features": features,
        "available_compatible_rows": available_counts,
        "invalid_rows_removed": removed_invalid,
        "excluded_external_labels": "Mirai, Web, brute-force, malware, and upload labels have no trained family equivalent.",
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0)),
        "classification_report": classification_report(
            y_true,
            y_pred,
            labels=labels,
            output_dict=True,
            zero_division=0,
        ),
        "prediction_distribution": predictions["predicted_family"].value_counts().to_dict(),
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    sample.to_csv(SAMPLE_PATH, index=False)
    predictions.to_csv(PREDICTIONS_PATH, index=False)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"Saved sample      : {SAMPLE_PATH}")
    print(f"Saved predictions : {PREDICTIONS_PATH}")
    print(f"Saved metrics     : {METRICS_PATH}")
    print(f"Rows              : {len(predictions)}")
    print(f"Accuracy          : {metrics['accuracy']:.4f}")
    print(f"Balanced accuracy : {metrics['balanced_accuracy']:.4f}")
    print(f"Macro F1          : {metrics['macro_f1']:.4f}")
    print(f"Weighted F1       : {metrics['weighted_f1']:.4f}")
    print("Prediction distribution:")
    print(predictions["predicted_family"].value_counts().to_string())


if __name__ == "__main__":
    main()
