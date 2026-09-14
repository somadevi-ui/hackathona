"""
Trains a Random Forest intrusion-detection classifier on NSL-KDD
and saves the model + preprocessing artifacts + metrics report.
"""

import json
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    precision_score, recall_score, f1_score, accuracy_score,
    confusion_matrix, classification_report
)

from preprocess import load_raw, fit_transform

ARTIFACT_DIR = "artifacts"


def main():
    import os
    os.makedirs(ARTIFACT_DIR, exist_ok=True)

    print("Loading data...")
    train_df = load_raw("data/KDDTrain.txt")
    test_df = load_raw("data/KDDTest.txt")

    print("Preprocessing...")
    bundle = fit_transform(train_df, test_df)

    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=150, max_depth=20, n_jobs=-1, random_state=42, class_weight="balanced"
    )
    clf.fit(bundle["X_train"], bundle["y_train"])

    print("Evaluating on held-out test set...")
    y_pred = clf.predict(bundle["X_test"])
    y_proba = clf.predict_proba(bundle["X_test"])[:, 1]

    metrics = {
        "accuracy": round(accuracy_score(bundle["y_test"], y_pred), 4),
        "precision": round(precision_score(bundle["y_test"], y_pred), 4),
        "recall": round(recall_score(bundle["y_test"], y_pred), 4),
        "f1_score": round(f1_score(bundle["y_test"], y_pred), 4),
    }
    print(json.dumps(metrics, indent=2))
    print(classification_report(bundle["y_test"], y_pred, target_names=["normal", "attack"]))

    # Confusion matrix chart
    cm = confusion_matrix(bundle["y_test"], y_pred)
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_xticklabels(["normal", "attack"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["normal", "attack"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    ax.set_title("Confusion Matrix - Intrusion Detection")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                     color="white" if cm[i, j] > cm.max() / 2 else "black")
    fig.colorbar(im)
    fig.tight_layout()
    fig.savefig(f"{ARTIFACT_DIR}/confusion_matrix.png", dpi=150)
    plt.close(fig)

    # Feature importance chart (top 12)
    importances = clf.feature_importances_
    idx = importances.argsort()[::-1][:12]
    top_feats = [bundle["feature_cols"][i] for i in idx]
    top_vals = importances[idx]
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.barh(top_feats[::-1], top_vals[::-1], color="#2563eb")
    ax.set_title("Top 12 Feature Importances (Random Forest)")
    ax.set_xlabel("Importance")
    fig.tight_layout()
    fig.savefig(f"{ARTIFACT_DIR}/feature_importance.png", dpi=150)
    plt.close(fig)

    # Save model + preprocessing artifacts
    joblib.dump(clf, f"{ARTIFACT_DIR}/model.joblib")
    joblib.dump(bundle["scaler"], f"{ARTIFACT_DIR}/scaler.joblib")
    joblib.dump(bundle["encoders"], f"{ARTIFACT_DIR}/encoders.joblib")
    joblib.dump(bundle["feature_cols"], f"{ARTIFACT_DIR}/feature_cols.joblib")
    with open(f"{ARTIFACT_DIR}/metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    # Save the readable test set + predictions for the live-feed simulation
    test_readable = bundle["test_df_readable"].copy()
    test_readable["predicted_label"] = y_pred
    test_readable["attack_confidence"] = y_proba
    test_readable.to_csv(f"{ARTIFACT_DIR}/test_with_predictions.csv", index=False)

    print(f"\nArtifacts saved to ./{ARTIFACT_DIR}/")


if __name__ == "__main__":
    main()
