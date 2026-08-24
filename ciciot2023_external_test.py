# =====================================================================
# 9) CROSS-DATASET TEST — CICIoT2023 REAL DDoS SAMPLE
# Run after cells 1 and 2.
#
# CICIoT2023 is an independent dataset and is NEVER used for training,
# validation, feature selection, balancing, or the official CICIoMT test.
# Kaggle Input required: himadri07/ciciot2023
# =====================================================================

EXTERNAL_DATASET_NAME = "CICIoT2023"
EXTERNAL_TRUE_FAMILY = "DDoS"
MAX_EXTERNAL_ROWS = 5_000


def find_ciciot2023_test_csv():
    roots = [
        path
        for path in Path("/kaggle/input").iterdir()
        if "ciciot2023" in path.name.lower()
    ]
    assert roots, (
        "CICIoT2023 input was not found. Add Kaggle dataset "
        "himadri07/ciciot2023, then rerun this cell."
    )

    csv_files = sorted(
        path
        for root in roots
        for path in root.rglob("*.csv")
    )
    assert csv_files, "No CICIoT2023 CSV files were found."

    label_names = {
        "label",
        "class",
        "target",
        "attack_type",
        "attack type",
        "category",
    }
    compatible = []

    for path in csv_files:
        raw_columns = pd.read_csv(path, nrows=0).columns.tolist()
        normalized = {
            str(column).strip().lower(): str(column)
            for column in raw_columns
        }
        label_key = next(
            (name for name in label_names if name in normalized),
            None,
        )
        normalized_feature_names = {
            str(column).strip()
            for column in raw_columns
        }
        if (
            label_key is not None
            and set(selected_features).issubset(normalized_feature_names)
        ):
            compatible.append((path, normalized[label_key]))

    assert compatible, (
        "No CICIoT2023 CSV has the selected 12 features and a label column."
    )

    # Prefer the dataset's official TEST file. Fall back only if its
    # uploader used a different file naming convention.
    compatible.sort(
        key=lambda item: (
            "test" not in item[0].name.lower(),
            str(item[0]),
        )
    )
    return compatible[0]


def load_external_ddos_sample(path, label_column, max_rows, seed):
    rng = np.random.default_rng(seed)
    needed_names = set(selected_features) | {str(label_column).strip()}
    kept = None
    matched_rows = 0
    removed_invalid_rows = 0

    for chunk in pd.read_csv(
        path,
        usecols=lambda column: str(column).strip() in needed_names,
        chunksize=100_000,
        low_memory=False,
    ):
        chunk = chunk.rename(
            columns={column: str(column).strip() for column in chunk.columns}
        )
        label_column_clean = str(label_column).strip()
        labels = chunk[label_column_clean].astype(str).str.strip()
        ddos_mask = labels.str.lower().str.startswith("ddos")
        chunk = chunk.loc[ddos_mask, selected_features].copy()
        matched_rows += len(chunk)

        for feature in selected_features:
            chunk[feature] = pd.to_numeric(
                chunk[feature],
                errors="coerce",
            )
        chunk = chunk.replace([np.inf, -np.inf], np.nan).fillna(0.0)

        valid_mask = chunk.ne(0).any(axis=1)
        removed_invalid_rows += int((~valid_mask).sum())
        chunk = chunk.loc[valid_mask]
        if chunk.empty:
            continue

        chunk["__priority__"] = rng.random(len(chunk))
        kept = (
            chunk
            if kept is None
            else pd.concat([kept, chunk], ignore_index=True)
        )
        if len(kept) > max_rows + 100_000:
            kept = kept.nsmallest(max_rows, "__priority__")

    assert matched_rows > 0, (
        "The selected CICIoT2023 file contains no DDoS-labelled rows."
    )
    assert kept is not None and not kept.empty, (
        "All external DDoS rows were invalid after numeric cleaning."
    )

    kept = kept.nsmallest(min(max_rows, len(kept)), "__priority__")
    kept = kept.drop(columns="__priority__").reset_index(drop=True)
    return kept.astype("float32"), matched_rows, removed_invalid_rows


ciciot2023_test_path, ciciot2023_label_column = (
    find_ciciot2023_test_csv()
)
external_X, external_matched_rows, external_removed_rows = (
    load_external_ddos_sample(
        ciciot2023_test_path,
        ciciot2023_label_column,
        MAX_EXTERNAL_ROWS,
        SEED + 900,
    )
)

external_prediction_encoded = (
    np.asarray(catboost_model.predict(external_X))
    .astype(int)
    .ravel()
)
external_prediction_family = label_encoder.inverse_transform(
    external_prediction_encoded
)
external_probabilities = np.asarray(
    catboost_model.predict_proba(external_X)
)
external_confidence = external_probabilities.max(axis=1)

ddos_index = int(
    np.where(label_encoder.classes_ == EXTERNAL_TRUE_FAMILY)[0][0]
)
external_ddos_probability = external_probabilities[:, ddos_index]

# The external sample contains one true family. Balanced accuracy and
# macro F1 are not appropriate for a one-class test, so report recalls.
attack_detection_recall = float(
    np.mean(external_prediction_family != "Benign")
)
exact_ddos_recall = float(
    np.mean(external_prediction_family == EXTERNAL_TRUE_FAMILY)
)
mean_confidence = float(np.mean(external_confidence))
mean_ddos_probability = float(np.mean(external_ddos_probability))
high_confidence_correct_rate = float(
    np.mean(
        (external_prediction_family == EXTERNAL_TRUE_FAMILY)
        & (external_confidence >= 0.80)
    )
)

external_metrics = {
    "training_dataset": "CICIoMT2024",
    "external_dataset": EXTERNAL_DATASET_NAME,
    "external_file": str(ciciot2023_test_path),
    "excluded_model_family": EXCLUDED_FAMILY,
    "true_family": EXTERNAL_TRUE_FAMILY,
    "sample_rows": len(external_X),
    "matched_ddos_rows_before_sampling": external_matched_rows,
    "invalid_rows_removed": external_removed_rows,
    "attack_detection_recall": attack_detection_recall,
    "exact_ddos_recall": exact_ddos_recall,
    "mean_prediction_confidence": mean_confidence,
    "mean_ddos_probability": mean_ddos_probability,
    "high_confidence_correct_rate": high_confidence_correct_rate,
}

print("\nCROSS-DATASET REAL ATTACK TEST")
print("Training dataset         : CICIoMT2024")
print("External dataset         :", EXTERNAL_DATASET_NAME)
print("External file            :", ciciot2023_test_path)
print("Label column             :", ciciot2023_label_column)
print("True external family     :", EXTERNAL_TRUE_FAMILY)
print("Sample rows              :", f"{len(external_X):,}")
print("Attack detection recall  :", f"{attack_detection_recall:.4f}")
print("Exact DDoS recall        :", f"{exact_ddos_recall:.4f}")
print("Mean confidence          :", f"{mean_confidence:.4f}")
print("Mean DDoS probability    :", f"{mean_ddos_probability:.4f}")
print(
    "Correct with conf >= .8 :",
    f"{high_confidence_correct_rate:.4f}",
)

prediction_distribution = (
    pd.Series(external_prediction_family, name="predicted_family")
    .value_counts(dropna=False)
    .rename_axis("predicted_family")
    .reset_index(name="rows")
)
prediction_distribution["percentage"] = (
    100 * prediction_distribution["rows"] / len(external_X)
)
print("\nPrediction distribution:")
display(prediction_distribution)

plt.figure(figsize=(8, 4))
sns.barplot(
    data=prediction_distribution,
    x="predicted_family",
    y="percentage",
    color="#2878B5",
)
plt.ylim(0, 105)
plt.ylabel("Percentage of CICIoT2023 DDoS rows")
plt.xlabel("Predicted family")
plt.title("Cross-dataset test: CICIoT2023 DDoS -> CICIoMT2024 CatBoost")
plt.tight_layout()
plt.show()

external_predictions = external_X.copy()
external_predictions["true_family"] = EXTERNAL_TRUE_FAMILY
external_predictions["predicted_family"] = external_prediction_family
external_predictions["confidence"] = external_confidence
external_predictions["ddos_probability"] = external_ddos_probability
external_predictions["correct_ddos"] = (
    external_prediction_family == EXTERNAL_TRUE_FAMILY
)

external_predictions_path = (
    "/kaggle/working/"
    "ciciot2023_external_ddos_predictions_5_classes.csv"
)
external_metrics_path = (
    "/kaggle/working/"
    "ciciot2023_external_ddos_metrics_5_classes.csv"
)
external_predictions.to_csv(external_predictions_path, index=False)
pd.DataFrame([external_metrics]).to_csv(
    external_metrics_path,
    index=False,
)

print("\nSaved cross-dataset predictions:", external_predictions_path)
print("Saved cross-dataset metrics:", external_metrics_path)

