"""Apply auditable synthetic rules and create a privacy-safe review sample."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pandas as pd

from cti.rules import LABELING_RULES, assess_rules


PROJECT_ROOT = Path(__file__).resolve().parent
INPUT_PATH = PROJECT_ROOT / "data" / "processed" / "hospital_log_events.csv"
LABELED_PATH = PROJECT_ROOT / "data" / "processed" / "hospital_rule_labeled_events.csv"
REVIEW_SAMPLE_PATH = PROJECT_ROOT / "data" / "processed" / "analyst_review_sample.csv"
RULES_PATH = PROJECT_ROOT / "data" / "processed" / "labeling_rules.json"
SUMMARY_PATH = PROJECT_ROOT / "data" / "processed" / "labeling_summary.json"

REVIEW_COLUMNS = [
    "event_id", "event_time", "event_source", "log_type", "location", "department",
    "actor_role", "action", "object_type", "device_type", "source_port", "dest_port",
    "protocol", "severity", "status", "synthetic_label", "synthetic_attack_type",
    "synthetic_confidence", "label_rule_id", "label_reason", "analyst_label",
    "analyst_attack_type", "analyst_confidence", "analyst_reason", "review_status",
    "reviewed_by", "reviewed_at",
]

COVERAGE_FIELDS = {
    "patient_access": ["actor_role", "action", "object_type", "device_type", "status", "location"],
    "employee_activity": ["department", "actor_role", "action", "status", "location"],
    "system_device": ["device_type", "action", "protocol", "severity", "status", "location"],
}


def apply_rules(frame: pd.DataFrame) -> pd.DataFrame:
    assessments = [assess_rules(row).to_dict() for row in frame.to_dict("records")]
    rules = pd.DataFrame.from_records(assessments)
    labeled = frame.copy()
    if "label" in labeled:
        labeled = labeled.rename(columns={"label": "source_db_match_label"})
    labeled["synthetic_label"] = rules["label"]
    labeled["synthetic_attack_type"] = rules["attack_type"]
    labeled["synthetic_confidence"] = rules["confidence"]
    labeled["label_rule_id"] = rules["rule_id"]
    labeled["label_reason"] = rules["reason"]
    labeled["rule_risk_score"] = rules["risk_score"]
    labeled["label_source"] = "Rule engine v1 (synthetic; pending human validation)"
    return labeled


def proportional_quotas(counts: pd.Series, total: int, minimum_per_class: int = 150) -> dict[str, int]:
    minimum_total = minimum_per_class * len(counts)
    if total < minimum_total:
        raise ValueError(
            f"Review sample needs at least {minimum_total} rows to include "
            f"{minimum_per_class} examples from each class."
        )
    if bool((counts < minimum_per_class).any()):
        raise ValueError(f"A label class has fewer than {minimum_per_class} source rows: {counts.to_dict()}")
    remaining = total - minimum_total
    raw = counts / counts.sum() * remaining
    quotas = {label: minimum_per_class + int(raw[label]) for label in counts.index}
    remainder = total - sum(quotas.values())
    order = (raw - raw.astype(int)).sort_values(ascending=False).index.tolist()
    cursor = 0
    while remainder:
        label = order[cursor % len(order)]
        if remainder > 0:
            quotas[label] += 1
            remainder -= 1
        elif quotas[label] > minimum_per_class:
            quotas[label] -= 1
            remainder += 1
        cursor += 1
    return quotas


def sample_source(frame: pd.DataFrame, rows: int, seed: int) -> pd.DataFrame:
    counts = frame["synthetic_label"].value_counts()
    quotas = proportional_quotas(counts, rows)
    sampled = [
        group.sample(n=quotas[label], random_state=seed + position)
        for position, (label, group) in enumerate(frame.groupby("synthetic_label", sort=True))
    ]
    result = pd.concat(sampled, ignore_index=False).sort_values(["event_time", "event_id"], kind="stable")
    if len(result) != rows:
        raise AssertionError(f"Expected {rows} review rows, generated {len(result)}")
    return result


def validate_sample_coverage(source: pd.DataFrame, sample: pd.DataFrame, log_type: str) -> dict[str, Any]:
    coverage: dict[str, Any] = {}
    for field in COVERAGE_FIELDS[log_type]:
        source_values = set(source[field].fillna("unknown").astype(str))
        sample_values = set(sample[field].fillna("unknown").astype(str))
        missing = sorted(source_values - sample_values)
        if missing:
            raise ValueError(f"Review sample for {log_type} misses {field} values: {missing}")
        coverage[field] = len(sample_values)
    return coverage


def build_review_sample(labeled: pd.DataFrame, rows_per_source: int, seed: int) -> tuple[pd.DataFrame, dict[str, Any]]:
    samples = []
    coverage: dict[str, Any] = {}
    for position, (log_type, group) in enumerate(labeled.groupby("log_type", sort=True)):
        sample = sample_source(group, rows_per_source, seed + position * 100)
        coverage[log_type] = validate_sample_coverage(group, sample, log_type)
        samples.append(sample)
    review = pd.concat(samples, ignore_index=True)
    review["analyst_label"] = ""
    review["analyst_attack_type"] = ""
    review["analyst_confidence"] = ""
    review["analyst_reason"] = ""
    review["review_status"] = "Pending"
    review["reviewed_by"] = ""
    review["reviewed_at"] = ""
    return review[REVIEW_COLUMNS], coverage


def main() -> None:
    parser = argparse.ArgumentParser(description="Create synthetic rule labels and an analyst review sample.")
    parser.add_argument("--rows-per-source", type=int, default=1_000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.rows_per_source < 450:
        raise ValueError("--rows-per-source must be at least 450 to cover all three classes")
    if not INPUT_PATH.exists():
        raise FileNotFoundError("Run prepare_hospital_data.py before labeling events.")

    frame = pd.read_csv(INPUT_PATH, low_memory=False)
    labeled = apply_rules(frame)
    review, coverage = build_review_sample(labeled, args.rows_per_source, args.seed)
    labeled.to_csv(LABELED_PATH, index=False)
    review.to_csv(REVIEW_SAMPLE_PATH, index=False)
    RULES_PATH.write_text(json.dumps(LABELING_RULES, indent=2), encoding="utf-8")

    summary = {
        "label_source": "Rule engine v1 (synthetic; pending human validation)",
        "human_review_status": "Not started",
        "total_labeled_rows": len(labeled),
        "review_sample_rows": len(review),
        "review_rows_per_source": args.rows_per_source,
        "label_distribution": {
            source: {str(label): int(count) for label, count in group["synthetic_label"].value_counts().items()}
            for source, group in labeled.groupby("log_type")
        },
        "review_distribution": {
            source: {str(label): int(count) for label, count in group["synthetic_label"].value_counts().items()}
            for source, group in review.groupby("log_type")
        },
        "sample_coverage": coverage,
        "privacy": {
            "direct_identifiers_in_review_sample": False,
            "free_text_descriptions_in_review_sample": False,
            "ip_addresses_in_review_sample": False,
            "source_database_claims_in_review_sample": False,
        },
        "warning": "Rule-generated labels are synthetic suggestions and must not be presented as human-confirmed incidents.",
    }
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"Wrote {LABELED_PATH.relative_to(PROJECT_ROOT)}")
    print(f"Wrote {REVIEW_SAMPLE_PATH.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
