"""Validate completed analyst-review sheets and export human-confirmed labels."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_WORKBOOK = (
    PROJECT_ROOT
    / "outputs"
    / "019fbe91-0d15-71b2-a287-a62f3e533db9"
    / "hospital_log_analyst_review.xlsx"
)
OUTPUT_PATH = PROJECT_ROOT / "data" / "processed" / "human_reviewed_labels.csv"
SHEETS = ["Patient Review", "Employee Review", "Device Review"]
LABELS = {"benign", "suspicious", "threat"}
CONFIDENCE = {"low", "medium", "high"}
REQUIRED = {
    "event_id", "log_type", "analyst_label", "analyst_attack_type", "analyst_confidence",
    "analyst_reason", "review_status", "reviewed_by", "reviewed_at",
}


def normalized_text(series: pd.Series) -> pd.Series:
    return series.fillna("").astype(str).str.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Import completed analyst labels from the review workbook.")
    parser.add_argument("--workbook", type=Path, default=DEFAULT_WORKBOOK)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    args = parser.parse_args()
    if not args.workbook.exists():
        raise FileNotFoundError(f"Review workbook not found: {args.workbook}")

    reviewed_frames = []
    for sheet_name in SHEETS:
        frame = pd.read_excel(args.workbook, sheet_name=sheet_name)
        missing = REQUIRED - set(frame.columns)
        if missing:
            raise ValueError(f"{sheet_name} is missing required columns: {sorted(missing)}")
        status = normalized_text(frame["review_status"]).str.lower()
        reviewed = frame[status.eq("reviewed")].copy()
        if reviewed.empty:
            continue
        labels = normalized_text(reviewed["analyst_label"]).str.lower()
        invalid_labels = sorted(set(labels) - LABELS)
        if invalid_labels:
            raise ValueError(f"{sheet_name} has invalid analyst labels: {invalid_labels}")
        confidence = normalized_text(reviewed["analyst_confidence"]).str.lower()
        invalid_confidence = sorted(set(confidence) - CONFIDENCE)
        if invalid_confidence:
            raise ValueError(f"{sheet_name} has invalid confidence values: {invalid_confidence}")
        if normalized_text(reviewed["reviewed_by"]).eq("").any():
            raise ValueError(f"{sheet_name} has Reviewed rows without reviewed_by")
        reviewed_at = pd.to_datetime(reviewed["reviewed_at"], errors="coerce")
        if reviewed_at.isna().any():
            raise ValueError(f"{sheet_name} has Reviewed rows without a valid reviewed_at timestamp")
        reviewed["analyst_label"] = labels
        reviewed["analyst_confidence"] = confidence.str.title()
        reviewed["reviewed_at"] = reviewed_at
        reviewed_frames.append(reviewed)

    if not reviewed_frames:
        raise ValueError("No rows are marked Reviewed. Complete analyst fields before importing labels.")
    output = pd.concat(reviewed_frames, ignore_index=True)
    if output["event_id"].duplicated().any():
        duplicates = output.loc[output["event_id"].duplicated(), "event_id"].head(5).tolist()
        raise ValueError(f"Duplicate reviewed event IDs: {duplicates}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(args.output, index=False)
    print(f"Imported {len(output):,} human-reviewed labels to {args.output}")


if __name__ == "__main__":
    main()
