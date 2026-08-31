"""Evaluate the saved CICIoT2024 CatBoost model on the cleaned CICIoT2023 sample."""

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
    confusion_matrix,
    f1_score,
)


ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "official_ciciomt2024_catboost_12_features_6_classes.joblib"
WORKBOOK_PATH = (
    ROOT
    / "outputs"
    / "ciciot2023_cleaned_excel"
    / "CICIoT2023_TEST_cleaned_200.xlsx"
)
SHEET_NAME = "Cleaned_TEST_200"


def main() -> None:
    artifact = joblib.load(MODEL_PATH)
    features = list(artifact["selected_features"])
    frame = pd.read_excel(WORKBOOK_PATH, sheet_name=SHEET_NAME)

    missing = [column for column in [*features, "Label"] if column not in frame.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    inputs = frame[features].apply(pd.to_numeric, errors="coerce")
    inputs = inputs.replace([np.inf, -np.inf], np.nan)
    invalid_rows = int(inputs.isna().any(axis=1).sum())
    all_zero_rows = int(inputs.fillna(0).eq(0).all(axis=1).sum())
    inputs = inputs.fillna(0).astype("float32")

    encoded = np.asarray(artifact["model"].predict(inputs)).astype(int).ravel()
    predictions = artifact["label_encoder"].inverse_transform(encoded)
    truth = frame["Label"].astype(str).str.strip().to_numpy()
    represented_labels = ["Benign", "DDoS", "DoS", "Recon", "Spoofing"]
    model_labels = ["Benign", "DDoS", "DoS", "MQTT", "Recon", "Spoofing"]

    result = {
        "rows": int(len(frame)),
        "features": features,
        "label_used_as_feature": "Label" in features,
        "invalid_feature_rows": invalid_rows,
        "all_zero_feature_rows": all_zero_rows,
        "true_distribution": pd.Series(truth).value_counts().sort_index().to_dict(),
        "prediction_distribution": pd.Series(predictions).value_counts().to_dict(),
        "accuracy": float(accuracy_score(truth, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(truth, predictions)),
        "macro_f1_represented_classes": float(
            f1_score(
                truth,
                predictions,
                labels=represented_labels,
                average="macro",
                zero_division=0,
            )
        ),
        "macro_f1_all_model_classes": float(
            f1_score(
                truth,
                predictions,
                labels=model_labels,
                average="macro",
                zero_division=0,
            )
        ),
        "weighted_f1": float(
            f1_score(
                truth,
                predictions,
                labels=model_labels,
                average="weighted",
                zero_division=0,
            )
        ),
        "classification_report": classification_report(
            truth, predictions, labels=model_labels, output_dict=True, zero_division=0
        ),
        "confusion_matrix": confusion_matrix(
            truth, predictions, labels=model_labels
        ).tolist(),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
