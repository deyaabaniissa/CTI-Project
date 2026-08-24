# =====================================================================
# 9) UNSEEN REAL-ATTACK FILE TEST — CATBOOST FIVE-CLASS MODEL
# Run after cells 1 and 2.
#
# The evaluated rows come from one complete DDoS capture in the official
# CICIoMT2024 TEST directory. That file was removed from the normal test
# pool before preparation and was never used for training, validation,
# feature selection, threshold tuning, or the main test report.
# =====================================================================

external_X = external_attack_df[selected_features].astype("float32")
external_true_family = EXTERNAL_ATTACK_FAMILY

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

true_family_index = int(
    np.where(label_encoder.classes_ == external_true_family)[0][0]
)
true_family_probability = external_probabilities[:, true_family_index]

# With a one-family external attack set, balanced accuracy and macro F1
# would be misleading. Report the two operational recalls instead:
#   1) Was the row detected as any attack rather than Benign?
#   2) Was its exact attack family identified correctly as DDoS?
external_attack_detection_recall = float(
    np.mean(external_prediction_family != "Benign")
)
external_exact_family_recall = float(
    np.mean(external_prediction_family == external_true_family)
)
external_mean_confidence = float(np.mean(external_confidence))
external_mean_true_family_probability = float(
    np.mean(true_family_probability)
)
external_high_confidence_correct_rate = float(
    np.mean(
        (external_prediction_family == external_true_family)
        & (external_confidence >= 0.80)
    )
)

external_metrics = {
    "model": "CatBoost five-class",
    "excluded_family": EXCLUDED_FAMILY,
    "source_file": EXTERNAL_ATTACK_FILE.name,
    "true_family": external_true_family,
    "rows": len(external_X),
    "attack_detection_recall": external_attack_detection_recall,
    "exact_family_recall": external_exact_family_recall,
    "mean_prediction_confidence": external_mean_confidence,
    "mean_true_family_probability": (
        external_mean_true_family_probability
    ),
    "high_confidence_correct_rate": (
        external_high_confidence_correct_rate
    ),
}

print("\nUNSEEN FILE-LEVEL REAL ATTACK TEST")
print("Excluded class          :", EXCLUDED_FAMILY)
print("Source file             :", EXTERNAL_ATTACK_FILE.name)
print("True family             :", external_true_family)
print("Rows                    :", f"{len(external_X):,}")
print(
    "Attack detection recall :",
    f"{external_attack_detection_recall:.4f}",
)
print(
    "Exact family recall      :",
    f"{external_exact_family_recall:.4f}",
)
print(
    "Mean confidence          :",
    f"{external_mean_confidence:.4f}",
)
print(
    "Mean DDoS probability    :",
    f"{external_mean_true_family_probability:.4f}",
)
print(
    "Correct with conf >= 0.8 :",
    f"{external_high_confidence_correct_rate:.4f}",
)

external_prediction_distribution = (
    pd.Series(external_prediction_family, name="predicted_family")
    .value_counts(dropna=False)
    .rename_axis("predicted_family")
    .reset_index(name="rows")
)
external_prediction_distribution["percentage"] = (
    100
    * external_prediction_distribution["rows"]
    / len(external_X)
)
print("\nPrediction distribution:")
display(external_prediction_distribution)

plt.figure(figsize=(8, 4))
sns.barplot(
    data=external_prediction_distribution,
    x="predicted_family",
    y="percentage",
    color="#2878B5",
)
plt.axhline(100, color="black", linewidth=0.8, linestyle="--")
plt.ylim(0, 105)
plt.ylabel("Percentage of unseen rows")
plt.xlabel("Predicted family")
plt.title(
    "Unseen real DDoS capture — CatBoost prediction distribution"
)
plt.tight_layout()
plt.show()

external_predictions = external_attack_df[selected_features].copy()
external_predictions["true_family"] = external_true_family
external_predictions["predicted_family"] = external_prediction_family
external_predictions["confidence"] = external_confidence
external_predictions["true_family_probability"] = true_family_probability
external_predictions["correct_family"] = (
    external_prediction_family == external_true_family
)

external_predictions_path = (
    "/kaggle/working/"
    "unseen_external_ddos_predictions_5_classes.csv"
)
external_metrics_path = (
    "/kaggle/working/"
    "unseen_external_ddos_metrics_5_classes.csv"
)
external_predictions.to_csv(external_predictions_path, index=False)
pd.DataFrame([external_metrics]).to_csv(
    external_metrics_path,
    index=False,
)

print("\nSaved external predictions:", external_predictions_path)
print("Saved external metrics:", external_metrics_path)

