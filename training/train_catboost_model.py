"""Trains the two-stage CICIoMT2024 CatBoost model and saves it to model/. Run: python training/train_catboost_model.py"""

from __future__ import annotations

import json
import re
import shutil
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from catboost import CatBoostClassifier
from sklearn.metrics import (
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight

TRAINING_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TRAINING_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))

from cti.catboost_ids import DEFAULT_FEATURES as FEATURES, TwoStageCatBoost  # noqa: E402

KAGGLE_DATASET = "limamateus/cic-iomt-2024-wifi-mqtt"
SEED = 42
MODEL_DIR = PROJECT_ROOT / "model"
DATA_DIR = PROJECT_ROOT / "data" / "raw" / "ciciomt2024"
CATBOOST_LOG_DIR = TRAINING_DIR / "catboost_info"
ARTIFACT_PATH = MODEL_DIR / "ciciomt2024_catboost_12_features_6_classes.joblib"
TRAINING_REPORT_JSON = TRAINING_DIR / "training_report.json"

FAMILY_ORDER = ["Benign", "DDoS", "DoS", "MQTT", "Recon", "Spoofing"]
ATTACK_FAMILIES = ["DDoS", "DoS", "MQTT", "Recon", "Spoofing"]
# DDoS/DoS get far more real rows than the rarer families; measurably improves precision everywhere.
STAGE2_ROW_CAPS = {"DDoS": 300_000, "DoS": 300_000, "MQTT": 30_000, "Recon": 30_000, "Spoofing": 30_000}


def attack_name_from_label(label: str) -> str:
    name = re.sub(r"_(train|test)$", "", str(label), flags=re.IGNORECASE)
    name = re.sub(r"(?<=[A-Za-z])\d+$", "", name)  # merge shards: ...UDP1, ...UDP2 -> ...UDP
    return name


def family_from_attack_name(name: str) -> str:
    if name == "Benign":
        return "Benign"
    if name.startswith("MQTT"):
        return "MQTT"
    if name.startswith("Recon"):
        return "Recon"
    if "Spoofing" in name:
        return "Spoofing"
    if "DDoS" in name:
        return "DDoS"
    if "DoS" in name:
        return "DoS"
    raise ValueError(f"Could not map attack name {name!r} to a known family.")


def load_split(csv_path: Path) -> pd.DataFrame:
    print(f"Loading {csv_path.name} ...")
    start = time.time()
    df = pd.read_csv(csv_path, usecols=FEATURES + ["label"])
    df[FEATURES] = df[FEATURES].apply(pd.to_numeric, errors="coerce")
    df[FEATURES] = df[FEATURES].replace([np.inf, -np.inf], np.nan)

    df["attack_name"] = df["label"].map(attack_name_from_label)
    df["family"] = df["attack_name"].map(family_from_attack_name)

    zero_or_missing = df[FEATURES].isna() | (df[FEATURES] == 0)
    drop_mask = zero_or_missing.all(axis=1)
    dropped = int(drop_mask.sum())
    df = df.loc[~drop_mask].reset_index(drop=True)

    print(
        f"  {len(df):,} usable rows ({dropped:,} dropped, all-zero/missing) "
        f"in {(time.time() - start):.1f}s"
    )
    return df


def sample_family(df: pd.DataFrame, family: str, n: int, seed: int) -> pd.DataFrame:
    """Undersample without replacement if there's enough data, else oversample with replacement."""
    pool = df[df["family"] == family]
    if len(pool) == 0:
        raise ValueError(f"No rows found for family {family!r}.")
    if len(pool) >= n:
        return pool.sample(n=n, random_state=seed)
    extra = pool.sample(n=n - len(pool), replace=True, random_state=seed)
    return pd.concat([pool, extra], ignore_index=True)


def build_stage1_data(train_raw: pd.DataFrame, seed: int) -> pd.DataFrame:
    """All Benign rows vs an equal-sized sample spread evenly across the 5 attack families."""
    benign_all = train_raw[train_raw["family"] == "Benign"]
    per_family = len(benign_all) // len(ATTACK_FAMILIES)
    attack_parts = [sample_family(train_raw, fam, per_family, seed) for fam in ATTACK_FAMILIES]
    attack_matched = pd.concat(attack_parts, ignore_index=True)

    stage1_df = pd.concat(
        [benign_all.assign(is_attack=0), attack_matched.assign(is_attack=1)], ignore_index=True
    )
    return stage1_df.sample(frac=1, random_state=seed).reset_index(drop=True)


def build_stage2_data(train_raw: pd.DataFrame, seed: int) -> tuple[pd.DataFrame, list[dict]]:
    """Attack-only rows, balanced per STAGE2_ROW_CAPS."""
    attack_only = train_raw[train_raw["family"] != "Benign"]
    audit: list[dict] = []
    parts = []
    for family, cap in STAGE2_ROW_CAPS.items():
        pool = attack_only[attack_only["family"] == family]
        balanced = sample_family(attack_only, family, cap, seed)
        parts.append(balanced)
        audit.append({
            "family": family,
            "source_rows": len(pool),
            "balanced_rows": len(balanced),
            "oversampled": len(pool) < cap,
        })
        print(f"  {family:10s} source={len(pool):>9,}  balanced={len(balanced):>7,}  oversampled={len(pool) < cap}")

    result = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)
    return result, audit


def ensure_dataset() -> tuple[Path, Path]:
    """Return (train_csv, test_csv), downloading into DATA_DIR only if missing."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    train_csv = next(DATA_DIR.glob("*_train.csv"), None)
    test_csv = next(DATA_DIR.glob("*_test.csv"), None)
    if train_csv and test_csv:
        print(f"Using cached dataset in {DATA_DIR}")
        return train_csv, test_csv

    import kagglehub

    print(f"Dataset not cached locally, downloading {KAGGLE_DATASET} via kagglehub ...")
    dataset_dir = Path(kagglehub.dataset_download(KAGGLE_DATASET))
    train_csv = next(dataset_dir.glob("*_train.csv"))
    test_csv = next(dataset_dir.glob("*_test.csv"))

    train_dest = DATA_DIR / train_csv.name
    test_dest = DATA_DIR / test_csv.name
    shutil.copy2(train_csv, train_dest)
    shutil.copy2(test_csv, test_dest)
    return train_dest, test_dest


def main() -> None:
    train_csv, test_csv = ensure_dataset()

    train_raw = load_split(train_csv)
    test_raw = load_split(test_csv)

    print("\nRaw family distribution (train):")
    print(train_raw["family"].value_counts().reindex(FAMILY_ORDER).to_string())

    (CATBOOST_LOG_DIR / "stage1").mkdir(parents=True, exist_ok=True)
    (CATBOOST_LOG_DIR / "stage2").mkdir(parents=True, exist_ok=True)

    # Stage 1: Benign vs Attack
    print("\nBuilding Stage 1 data (Benign vs Attack) ...")
    stage1_df = build_stage1_data(train_raw, SEED)
    print(f"  {len(stage1_df):,} rows ({(stage1_df['is_attack'] == 0).sum():,} Benign, "
          f"{(stage1_df['is_attack'] == 1).sum():,} Attack)")

    X1 = stage1_df[FEATURES].astype("float32")
    y1 = stage1_df["is_attack"].values
    X1_train, X1_val, y1_train, y1_val = train_test_split(
        X1, y1, test_size=0.10, random_state=SEED, stratify=y1
    )
    stage1 = CatBoostClassifier(
        loss_function="Logloss",
        eval_metric="F1",
        iterations=2000,
        learning_rate=0.08,
        depth=8,
        l2_leaf_reg=3.0,
        random_seed=SEED,
        thread_count=-1,
        early_stopping_rounds=100,
        use_best_model=True,
        verbose=200,
        train_dir=str(CATBOOST_LOG_DIR / "stage1"),
    )
    print("\nTraining Stage 1 (Benign vs Attack) ...")
    start = time.time()
    stage1.fit(X1_train, y1_train, eval_set=(X1_val, y1_val))
    stage1_minutes = (time.time() - start) / 60
    print(f"Stage 1 training time: {stage1_minutes:.1f} minutes")

    # Stage 2: attack-family classifier, attack rows only
    print(f"\nBuilding Stage 2 data (attack family, caps={STAGE2_ROW_CAPS}) ...")
    stage2_df, stage2_audit = build_stage2_data(train_raw, SEED)

    attack_label_encoder = LabelEncoder()
    attack_label_encoder.fit(ATTACK_FAMILIES)
    X2 = stage2_df[FEATURES].astype("float32")
    y2 = attack_label_encoder.transform(stage2_df["family"])
    X2_train, X2_val, y2_train, y2_val = train_test_split(
        X2, y2, test_size=0.10, random_state=SEED, stratify=y2
    )
    sample_weight = compute_sample_weight(class_weight="balanced", y=y2_train)

    stage2 = CatBoostClassifier(
        loss_function="MultiClass",
        eval_metric="TotalF1:average=Macro",
        iterations=3000,
        learning_rate=0.08,
        depth=8,
        l2_leaf_reg=3.0,
        random_seed=SEED,
        thread_count=-1,
        early_stopping_rounds=100,
        use_best_model=True,
        verbose=200,
        train_dir=str(CATBOOST_LOG_DIR / "stage2"),
    )
    print("\nTraining Stage 2 (attack family) ...")
    start = time.time()
    stage2.fit(X2_train, y2_train, sample_weight=sample_weight, eval_set=(X2_val, y2_val))
    stage2_minutes = (time.time() - start) / 60
    print(f"Stage 2 training time: {stage2_minutes:.1f} minutes")

    # Evaluate the combined pipeline on the full untouched official TEST split
    print("\nEvaluating combined two-stage pipeline on the FULL untouched official TEST split ...")
    combined_model = TwoStageCatBoost(stage1=stage1, stage2=stage2, family_order=FAMILY_ORDER)
    label_encoder = LabelEncoder()
    label_encoder.fit(FAMILY_ORDER)

    X_test = test_raw[FEATURES].astype("float32")
    y_test = label_encoder.transform(test_raw["family"])
    y_pred_encoded = combined_model.predict(X_test)

    accuracy = float((y_pred_encoded == y_test).mean())
    macro_f1 = float(f1_score(y_test, y_pred_encoded, average="macro"))
    weighted_f1 = float(f1_score(y_test, y_pred_encoded, average="weighted"))
    balanced_acc = float(balanced_accuracy_score(y_test, y_pred_encoded))

    report = classification_report(
        y_test, y_pred_encoded, target_names=label_encoder.classes_, digits=4, zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred_encoded, labels=range(len(label_encoder.classes_)))

    print(f"\nAccuracy          : {accuracy:.4f}")
    print(f"Macro F1          : {macro_f1:.4f}")
    print(f"Weighted F1       : {weighted_f1:.4f}")
    print(f"Balanced accuracy : {balanced_acc:.4f}")
    print()
    print(report)
    print(cm)

    feature_importance = combined_model.get_feature_importance()
    importance_rows = sorted(
        (
            {"feature": feature, "importance": float(value)}
            for feature, value in zip(FEATURES, feature_importance)
        ),
        key=lambda row: row["importance"],
        reverse=True,
    )

    train_attack_names = sorted(train_raw.loc[train_raw["family"] != "Benign", "attack_name"].unique())
    test_attack_names = sorted(test_raw.loc[test_raw["family"] != "Benign", "attack_name"].unique())

    artifact = {
        "architecture": "two_stage",
        "stage1_model": stage1,
        "stage2_model": stage2,
        "family_order": FAMILY_ORDER,
        "attack_family_order": ATTACK_FAMILIES,
        "label_encoder": label_encoder,
        "feature_columns": FEATURES,
        "selected_features": FEATURES,
        "task": "multiclass-two-stage",
        "dataset": "CICIoMT2024 / WiFI_and_MQTT (Kaggle mirror: limamateus/cic-iomt-2024-wifi-mqtt)",
        "model_name": "CICIoMT2024 CatBoost (two-stage: Benign/Attack -> family)",
        "metrics": {
            "accuracy": accuracy,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "balanced_accuracy": balanced_acc,
            "stage1_training_minutes": stage1_minutes,
            "stage2_training_minutes": stage2_minutes,
        },
        "balance_audit": pd.DataFrame(stage2_audit),
        "stage1_balance": {
            "benign_rows": int((stage1_df["is_attack"] == 0).sum()),
            "attack_rows_matched": int((stage1_df["is_attack"] == 1).sum()),
        },
        "target_rows_per_family": max(STAGE2_ROW_CAPS.values()),
        "stage2_row_caps": STAGE2_ROW_CAPS,
        "train_attack_names": train_attack_names,
        "test_attack_names": test_attack_names,
        "zero_row_rule": "A row is removed only when all 12 selected features are zero or missing.",
        "excluded_family": None,
        "profile_train_files": [train_csv.name],
        "profile_holdout_files": [test_csv.name],
        "official_test_rows": int(len(test_raw)),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, ARTIFACT_PATH)
    print(f"\nSaved artifact: {ARTIFACT_PATH} ({ARTIFACT_PATH.stat().st_size / 1e6:.1f} MB)")

    TRAINING_REPORT_JSON.write_text(
        json.dumps(
            {
                "metrics": artifact["metrics"],
                "stage2_balance_audit": stage2_audit,
                "stage1_balance": artifact["stage1_balance"],
                "classification_report": report,
                "confusion_matrix": cm.tolist(),
                "classes": list(label_encoder.classes_),
                "feature_importance": importance_rows,
                "official_test_rows": artifact["official_test_rows"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Saved report   : {TRAINING_REPORT_JSON}")


if __name__ == "__main__":
    main()
