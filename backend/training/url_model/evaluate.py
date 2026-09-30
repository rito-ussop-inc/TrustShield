"""Standalone evaluation script for URL classification model artifact.
TRD §8, PRD §7 FR-8.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path
import joblib
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from training.url_model.features import extract_url_feature_vector


def evaluate_artifact(artifact_path: Path, test_csv_path: Path) -> dict:
    if not artifact_path.exists():
        raise FileNotFoundError(f"Model artifact not found at {artifact_path}")
    if not test_csv_path.exists():
        raise FileNotFoundError(f"Test dataset not found at {test_csv_path}")

    artifact = joblib.load(artifact_path)
    model = artifact["model"]
    version = artifact.get("model_version", "unknown")

    # Load test CSV
    import csv
    urls, labels = [], []
    with test_csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row["url"])
            labels.append(int(row["binary_label"]))

    X = np.array([extract_url_feature_vector(u) for u in urls])
    y = np.array(labels)

    probs = model.predict_proba(X)[:, 1]
    preds = (probs >= 0.5).astype(int)

    report_str = classification_report(y, preds, target_names=["benign", "malicious"], zero_division=0)
    cm = confusion_matrix(y, preds).tolist()
    roc_auc = float(roc_auc_score(y, probs))
    pr_auc = float(average_precision_score(y, probs))

    print(f"=== URL Model Evaluation: {version} ===")
    print(report_str)
    print(f"Confusion Matrix:\n{cm}")
    print(f"ROC-AUC: {roc_auc:.4f} | PR-AUC: {pr_auc:.4f}")

    return {
        "model_version": version,
        "sample_count": len(urls),
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": cm,
    }


if __name__ == "__main__":
    repo_root = Path.cwd()
    evaluate_artifact(
        repo_root / "ml" / "artifacts" / "url_classifier.joblib",
        repo_root / "data" / "url_dataset_v1.csv",
    )
