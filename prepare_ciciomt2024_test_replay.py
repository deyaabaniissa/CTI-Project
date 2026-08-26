from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent
TEST_ROOT = PROJECT_ROOT / "CIC dataset" / "WiFi_and_MQTT" / "attacks" / "CSV" / "test"
MODEL_PATH = PROJECT_ROOT / "official_ciciomt2024_catboost_12_features_6_classes.joblib"
OUTPUT_PATH = PROJECT_ROOT / "data" / "evaluation" / "ciciomt2024_test_300_predictions.csv"
SEED = 42
ROWS_PER_FAMILY = 50


def family_from_filename(path: Path) -> str:
    name = path.name
    if name.startswith("Benign"):
        return "Benign"
    if name.startswith("ARP_Spoofing"):
        return "Spoofing"
    if name.startswith("MQTT-"):
        return "MQTT"
    if name.startswith("Recon-"):
        return "Recon"
    if name.startswith("TCP_IP-DDoS-"):
        return "DDoS"
    if name.startswith("TCP_IP-DoS-"):
        return "DoS"
    raise ValueError(f"Unsupported official TEST file: {path.name}")


def clean_file(path: Path, features: list[str]) -> pd.DataFrame:
    frame = pd.read_csv(path, usecols=features, low_memory=False)
    frame = frame.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
    # Match the training notebook: remove only rows for which every selected
    # model feature is zero or missing.
    frame = frame.loc[frame.ne(0).any(axis=1)].copy()
    frame["source_row_number"] = frame.index + 2  # CSV header occupies line 1.
    frame["source_file"] = path.name
    frame["attack_subclass"] = path.name.removesuffix("_test.pcap.csv")
    return frame.reset_index(drop=True)


def sample_family(files: list[Path], features: list[str], family: str) -> pd.DataFrame:
    rng = np.random.default_rng(SEED + sum(ord(letter) for letter in family))
    base_quota, remainder = divmod(ROWS_PER_FAMILY, len(files))
    selected: list[pd.DataFrame] = []

    for index, path in enumerate(files):
        frame = clean_file(path, features)
        quota = base_quota + (1 if index < remainder else 0)
        if len(frame) < quota:
            raise ValueError(f"{path.name} has only {len(frame)} clean rows; {quota} are required.")
        choices = rng.choice(len(frame), size=quota, replace=False)
        selected.append(frame.iloc[choices].copy())

    family_frame = pd.concat(selected, ignore_index=True)
    family_frame["true_family"] = family
    return family_frame


def main() -> None:
    artifact = joblib.load(MODEL_PATH)
    model = artifact["model"]
    label_encoder = artifact["label_encoder"]
    features = list(artifact["selected_features"])
    classes = [str(value) for value in label_encoder.classes_]

    grouped: dict[str, list[Path]] = {family: [] for family in classes}
    for path in sorted(TEST_ROOT.glob("*.csv")):
        grouped[family_from_filename(path)].append(path)

    missing = [family for family, files in grouped.items() if not files]
    if missing:
        raise FileNotFoundError("Missing official TEST files for: " + ", ".join(missing))

    sampled = pd.concat(
        [sample_family(grouped[family], features, family) for family in classes],
        ignore_index=True,
    )
    sampled = sampled.sample(frac=1.0, random_state=SEED).reset_index(drop=True)

    prediction_ids = np.asarray(model.predict(sampled[features])).reshape(-1).astype(int)
    probabilities = np.asarray(model.predict_proba(sampled[features]), dtype=float)
    sampled["predicted_family"] = label_encoder.inverse_transform(prediction_ids)
    sampled["confidence"] = probabilities.max(axis=1)
    sampled["correct"] = sampled["predicted_family"].eq(sampled["true_family"])
    for index, family in enumerate(classes):
        sampled[f"probability_{family}"] = probabilities[:, index]

    sampled.insert(0, "sample_id", [f"CIC24-TEST-{index:03d}" for index in range(1, len(sampled) + 1)])
    sampled.insert(1, "source_dataset", "CICIoMT2024")
    sampled.insert(2, "source_split", "Official TEST")

    ordered = [
        "sample_id",
        "source_dataset",
        "source_split",
        "source_file",
        "source_row_number",
        "attack_subclass",
        "true_family",
        "predicted_family",
        "confidence",
        "correct",
        *[f"probability_{family}" for family in classes],
        *features,
    ]
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    sampled[ordered].to_csv(OUTPUT_PATH, index=False)

    counts = sampled.groupby("true_family").size().to_dict()
    accuracy = float(sampled["correct"].mean())
    print(f"Saved {len(sampled)} unique official TEST rows to {OUTPUT_PATH}")
    print(f"Per-family counts: {counts}")
    print(f"Replay accuracy: {accuracy:.4f}")


if __name__ == "__main__":
    main()
