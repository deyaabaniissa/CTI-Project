from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler, label_binarize

from cti.log_data import (
    CATEGORICAL_FEATURES,
    EXCLUDED_SENSITIVE_OR_LEAKY_FIELDS,
    MODEL_FEATURES,
    NUMERIC_FEATURES,
    feature_frame,
)


DATASET = Path("data/processed/hospital_rule_labeled_events.csv")
HUMAN_LABELS = Path("data/processed/human_reviewed_labels.csv")
LABEL_CLASSES = ["benign", "suspicious", "threat"]
DISPLAY_NAMES = {
    "patient_access": "Patient-access model",
    "employee_activity": "Employee-activity model",
    "system_device": "System/device model",
}
TARGETS = {
    "threat_recall": 0.85,
    "threat_precision": 0.70,
    "max_threat_false_positive_rate": 0.10,
}


def build_training_frame(label_mode: str, human_labels_path: Path) -> tuple[pd.DataFrame, str]:
    source_path = human_labels_path if label_mode == "human" else DATASET
    if not source_path.exists():
        if label_mode == "human":
            raise FileNotFoundError("Human-reviewed labels are missing; run import_analyst_reviews.py first.")
        raise FileNotFoundError("Labeled dataset is missing; run label_hospital_events.py first.")
    frame = pd.read_csv(source_path, low_memory=False)
    if label_mode == "human":
        if "analyst_label" not in frame:
            raise ValueError("Human label file must contain analyst_label")
        frame["synthetic_label"] = frame["analyst_label"].astype(str).str.strip().str.lower()
        label_source = "Human-reviewed analyst labels"
    else:
        label_source = "Rule engine v1 (synthetic; pending human validation)"
    required = {"event_time", "event_source", "log_type", "synthetic_label"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"Labeled dataset is missing columns: {sorted(missing)}")
    unexpected = sorted(set(frame["synthetic_label"]) - set(LABEL_CLASSES))
    if unexpected:
        raise ValueError(f"Unsupported labels: {unexpected}")
    frame["event_time"] = pd.to_datetime(frame["event_time"], errors="raise")
    for log_type, group in frame.groupby("log_type"):
        counts = group["synthetic_label"].value_counts()
        if set(counts.index) != set(LABEL_CLASSES):
            raise ValueError(f"{log_type} must contain all three label classes")
        if label_mode == "human" and int(counts.min()) < 100:
            raise ValueError(
                f"{log_type} needs at least 100 human-reviewed rows in each class; got {counts.to_dict()}"
            )
    return frame.sort_values(["event_time", "event_id"], kind="stable").reset_index(drop=True), label_source


def build_pipeline(seed: int) -> Pipeline:
    categorical = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore", min_frequency=3)),
        ]
    )
    numeric = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scale", StandardScaler()),
        ]
    )
    preprocessor = ColumnTransformer(
        transformers=[
            ("categorical", categorical, CATEGORICAL_FEATURES),
            ("numeric", numeric, NUMERIC_FEATURES),
        ]
    )
    classifier = RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=seed,
    )
    return Pipeline(steps=[("preprocessor", preprocessor), ("classifier", classifier)])


def source_metrics(
    log_type: str,
    train: pd.DataFrame,
    test: pd.DataFrame,
    model: Pipeline,
) -> tuple[dict[str, object], pd.DataFrame]:
    X_test = feature_frame(test)
    y_test = test["synthetic_label"].astype(str)
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)
    classes = list(model.classes_)
    threat_index = classes.index("threat")
    threat_truth = (y_test == "threat").astype(int)
    threat_prediction = (predictions == "threat").astype(int)
    non_threat_count = max(1, int((threat_truth == 0).sum()))
    false_positive_rate = float(((threat_prediction == 1) & (threat_truth == 0)).sum() / non_threat_count)

    report = classification_report(
        y_test,
        predictions,
        labels=LABEL_CLASSES,
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(y_test, predictions, labels=LABEL_CLASSES)
    binarized = label_binarize(y_test, classes=classes)
    roc_auc = roc_auc_score(binarized, probabilities, average="macro", multi_class="ovr")
    metrics: dict[str, object] = {
        "name": DISPLAY_NAMES[log_type],
        "log_type": log_type,
        "training_rows": len(train),
        "test_rows": len(test),
        "evaluation_split": "chronological final 25% holdout",
        "train_period": [train["event_time"].min().isoformat(), train["event_time"].max().isoformat()],
        "test_period": [test["event_time"].min().isoformat(), test["event_time"].max().isoformat()],
        "class_distribution": {
            label: int(count) for label, count in pd.concat([train, test])["synthetic_label"].value_counts().items()
        },
        "accuracy": round(float(accuracy_score(y_test, predictions)), 5),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_test, predictions)), 5),
        "macro_f1": round(float(f1_score(y_test, predictions, average="macro", zero_division=0)), 5),
        "macro_roc_auc": round(float(roc_auc), 5),
        "threat_precision": round(float(precision_score(threat_truth, threat_prediction, zero_division=0)), 5),
        "threat_recall": round(float(recall_score(threat_truth, threat_prediction, zero_division=0)), 5),
        "threat_pr_auc": round(float(average_precision_score(threat_truth, probabilities[:, threat_index])), 5),
        "threat_false_positive_rate": round(false_positive_rate, 5),
        "per_class": {
            label: {
                "precision": round(float(report[label]["precision"]), 5),
                "recall": round(float(report[label]["recall"]), 5),
                "f1": round(float(report[label]["f1-score"]), 5),
                "support": int(report[label]["support"]),
            }
            for label in LABEL_CLASSES
        },
        "confusion_matrix": {
            truth: {prediction: int(matrix[row, col]) for col, prediction in enumerate(LABEL_CLASSES)}
            for row, truth in enumerate(LABEL_CLASSES)
        },
    }
    metrics["target_checks"] = {
        "threat_recall_at_least_85_percent": bool(metrics["threat_recall"] >= TARGETS["threat_recall"]),
        "threat_precision_at_least_70_percent": bool(metrics["threat_precision"] >= TARGETS["threat_precision"]),
        "threat_false_positive_rate_at_most_10_percent": bool(
            metrics["threat_false_positive_rate"] <= TARGETS["max_threat_false_positive_rate"]
        ),
    }
    scored = test[["event_id", "event_time", "log_type", "synthetic_label"]].copy()
    scored["predicted_label"] = predictions
    for position, label in enumerate(classes):
        scored[f"probability_{label}"] = probabilities[:, position]
    return metrics, scored


def main() -> None:
    parser = argparse.ArgumentParser(description="Train three hospital log behavioral classifiers.")
    parser.add_argument("--output", default="threat_model.pkl")
    parser.add_argument("--metrics", default="model_metrics.json")
    parser.add_argument("--predictions", default="data/processed/model_test_predictions.csv")
    parser.add_argument("--test-fraction", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--label-mode", choices=["synthetic", "human"], default="synthetic")
    parser.add_argument("--human-labels", type=Path, default=HUMAN_LABELS)
    args = parser.parse_args()
    if not 0.2 <= args.test_fraction <= 0.3:
        raise ValueError("--test-fraction must be between 0.2 and 0.3")

    frame, label_source = build_training_frame(args.label_mode, args.human_labels)
    models: dict[str, Pipeline] = {}
    metrics_by_source: dict[str, object] = {}
    scored_frames = []
    for position, (log_type, source) in enumerate(frame.groupby("log_type", sort=True)):
        source = source.sort_values(["event_time", "event_id"], kind="stable").reset_index(drop=True)
        split_at = int(len(source) * (1 - args.test_fraction))
        train = source.iloc[:split_at].copy()
        test = source.iloc[split_at:].copy()
        if set(train["synthetic_label"]) != set(LABEL_CLASSES) or set(test["synthetic_label"]) != set(LABEL_CLASSES):
            raise ValueError(f"Chronological split for {log_type} must contain all label classes.")
        model = build_pipeline(args.seed + position)
        model.fit(feature_frame(train), train["synthetic_label"].astype(str))
        metrics, scored = source_metrics(log_type, train, test, model)
        models[log_type] = model
        metrics_by_source[log_type] = metrics
        scored_frames.append(scored)

    scored_all = pd.concat(scored_frames, ignore_index=True)
    truth = scored_all["synthetic_label"]
    predictions = scored_all["predicted_label"]
    aggregate_threat_truth = (truth == "threat").astype(int)
    aggregate_threat_predictions = (predictions == "threat").astype(int)
    aggregate_non_threat_count = max(1, int((aggregate_threat_truth == 0).sum()))
    aggregate_false_positive_rate = float(
        ((aggregate_threat_predictions == 1) & (aggregate_threat_truth == 0)).sum()
        / aggregate_non_threat_count
    )
    aggregate = {
        "test_rows": len(scored_all),
        "accuracy": round(float(accuracy_score(truth, predictions)), 5),
        "balanced_accuracy": round(float(balanced_accuracy_score(truth, predictions)), 5),
        "macro_f1": round(float(f1_score(truth, predictions, average="macro", zero_division=0)), 5),
        "threat_precision": round(float(precision_score(aggregate_threat_truth, aggregate_threat_predictions, zero_division=0)), 5),
        "threat_recall": round(float(recall_score(aggregate_threat_truth, aggregate_threat_predictions, zero_division=0)), 5),
        "threat_false_positive_rate": round(aggregate_false_positive_rate, 5),
    }
    aggregate["target_checks"] = {
        "threat_recall_at_least_85_percent": bool(aggregate["threat_recall"] >= TARGETS["threat_recall"]),
        "threat_precision_at_least_70_percent": bool(aggregate["threat_precision"] >= TARGETS["threat_precision"]),
        "threat_false_positive_rate_at_most_10_percent": bool(
            aggregate["threat_false_positive_rate"] <= TARGETS["max_threat_false_positive_rate"]
        ),
    }
    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "Three source-specific OneHotEncoder + balanced RandomForest classifiers",
        "label_source": label_source,
        "label_classes": LABEL_CLASSES,
        "features": MODEL_FEATURES,
        "excluded_fields": EXCLUDED_SENSITIVE_OR_LEAKY_FIELDS,
        "targets": TARGETS,
        "models": metrics_by_source,
        "aggregate": aggregate,
        "human_validation": {
            "status": "complete for current training input" if args.label_mode == "human" else "required",
            "review_sample_rows": 3_000,
            "minimum_acceptance": "Repeat evaluation after analysts complete the review workbook; synthetic-rule performance is not production validation.",
        },
        "evaluation_note": (
            "These models measure how well observable fields reproduce transparent synthetic rules. "
            "High scores demonstrate implementation consistency, not real-world hospital threat-detection accuracy. "
            "Operational approval requires independently reviewed labels and a newly untouched test set."
            if args.label_mode == "synthetic"
            else "Metrics use imported analyst labels. Production approval still requires an independently collected future-time holdout."
        ),
    }
    artifact = {
        "models": models,
        "features": MODEL_FEATURES,
        "label_classes": LABEL_CLASSES,
        "metadata": metrics,
    }
    joblib.dump(artifact, args.output)
    Path(args.metrics).write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    predictions_path = Path(args.predictions)
    predictions_path.parent.mkdir(parents=True, exist_ok=True)
    scored_all.to_csv(predictions_path, index=False)
    print(json.dumps(metrics, indent=2))
    print(f"Saved three-model artifact to {args.output}")
    print(f"Saved untouched test predictions to {predictions_path}")


if __name__ == "__main__":
    main()
