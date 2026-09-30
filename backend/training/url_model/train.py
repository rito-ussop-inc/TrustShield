"""Model training pipeline for URL classification.
TRD §8, PRD §7 FR-6, FR-7, FR-8.

Trains tabular baselines (LogisticRegression, RandomForest, GradientBoosting),
compares on validation data, calibrates probabilities, evaluates on held-out test set,
and exports versioned artifact and evaluation report.
"""
from __future__ import annotations
import json
import os
import sys
import time
from pathlib import Path
import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Ensure backend modules can be imported
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from training.url_model.dataset import (
    DATASET_VERSION,
    build_curated_records,
    save_dataset_csv,
    split_dataset_by_domain,
)
from training.url_model.features import FEATURE_NAMES, extract_url_feature_vector

MODEL_VERSION = "url-classifier-tabular-v1.0.0"


def train_and_evaluate(
    dataset_csv_path: Path | None = None,
    artifact_path: Path | None = None,
    report_path: Path | None = None,
) -> dict:
    repo_root = Path.cwd()
    data_path = dataset_csv_path or (repo_root / "data" / "url_dataset_v1.csv")
    art_path = artifact_path or (repo_root / "ml" / "artifacts" / "url_classifier.joblib")
    rep_path = report_path or (repo_root / "ml" / "evaluation" / "url_model_evaluation_report.json")

    # Step 1: Ingest and save dataset
    records = build_curated_records()
    save_dataset_csv(records, data_path)
    print(f"[1/7] Ingested and deduplicated {len(records)} records -> saved to {data_path}")

    # Step 2: Domain-grouped split
    train_recs, val_recs, test_recs = split_dataset_by_domain(records, train_ratio=0.70, val_ratio=0.15, random_seed=42)
    print(f"[2/7] Split: Train={len(train_recs)}, Val={len(val_recs)}, Test={len(test_recs)} (zero domain leakage)")

    # Step 3: Feature extraction
    X_train = np.array([extract_url_feature_vector(r.url) for r in train_recs])
    y_train = np.array([r.binary_label for r in train_recs])

    X_val = np.array([extract_url_feature_vector(r.url) for r in val_recs])
    y_val = np.array([r.binary_label for r in val_recs])

    X_test = np.array([extract_url_feature_vector(r.url) for r in test_recs])
    y_test = np.array([r.binary_label for r in test_recs])

    # Step 4: Candidate models training on Train split
    candidates = {
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(C=1.0, max_iter=1000, random_state=42)),
        ]),
        "RandomForest": RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42),
        "GradientBoosting": GradientBoostingClassifier(n_estimators=100, learning_rate=0.08, max_depth=3, random_state=42),
    }

    val_metrics = {}
    fitted_models = {}

    print("[3/7] Training candidate models on Train split and evaluating on Validation split...")
    for name, model in candidates.items():
        model.fit(X_train, y_train)
        fitted_models[name] = model

        val_probs = model.predict_proba(X_val)[:, 1]
        val_preds = (val_probs >= 0.5).astype(int)

        pr_auc = float(average_precision_score(y_val, val_probs))
        roc_auc = float(roc_auc_score(y_val, val_probs))
        f1 = float(f1_score(y_val, val_preds, zero_division=0))
        loss = float(log_loss(y_val, val_probs))

        val_metrics[name] = {
            "pr_auc": pr_auc,
            "roc_auc": roc_auc,
            "f1": f1,
            "log_loss": loss,
        }
        print(f"      - {name}: Val PR-AUC={pr_auc:.4f}, ROC-AUC={roc_auc:.4f}, F1={f1:.4f}, LogLoss={loss:.4f}")

    # Select best model based on Validation PR-AUC and F1
    best_name = max(val_metrics, key=lambda k: (val_metrics[k]["pr_auc"], val_metrics[k]["f1"]))
    best_base_model = fitted_models[best_name]
    print(f"[4/7] Selected best baseline: '{best_name}'")

    # Step 5: Probability calibration using cross-validation
    print("[5/7] Fitting probability calibration on Train split (3-fold CV)...")
    calibrated_model = CalibratedClassifierCV(best_base_model, method="sigmoid", cv=3)
    calibrated_model.fit(X_train, y_train)

    # Step 6: Final evaluation on the frozen Held-Out Test set
    print("[6/7] Evaluating calibrated model on frozen Held-Out Test set...")
    t0 = time.perf_counter()
    test_probs = calibrated_model.predict_proba(X_test)[:, 1]
    latency_total_s = time.perf_counter() - t0
    latency_per_item_ms = (latency_total_s / len(X_test)) * 1000

    test_roc_auc = float(roc_auc_score(y_test, test_probs))
    test_pr_auc = float(average_precision_score(y_test, test_probs))

    # Evaluate at multiple operating thresholds
    thresholds = [0.3, 0.5, 0.7]
    threshold_metrics = {}
    for th in thresholds:
        preds = (test_probs >= th).astype(int)
        cm = confusion_matrix(y_test, preds).tolist()
        tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
        prec = float(precision_score(y_test, preds, zero_division=0))
        rec = float(recall_score(y_test, preds, zero_division=0))
        f1 = float(f1_score(y_test, preds, zero_division=0))
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        threshold_metrics[f"threshold_{th}"] = {
            "threshold": th,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        }

    # Step 7: Export versioned artifact and metadata
    art_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_payload = {
        "model": calibrated_model,
        "selected_architecture": best_name,
        "feature_names": FEATURE_NAMES,
        "model_version": MODEL_VERSION,
        "dataset_version": DATASET_VERSION,
        "trained_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    joblib.dump(artifact_payload, art_path)
    artifact_size_bytes = os.path.getsize(art_path)
    print(f"[7/7] Saved model artifact -> {art_path} ({artifact_size_bytes / 1024:.1f} KB)")

    # Build evaluation report
    report = {
        "model_version": MODEL_VERSION,
        "dataset_version": DATASET_VERSION,
        "evaluation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "selected_architecture": best_name,
        "splits": {
            "train_samples": len(train_recs),
            "val_samples": len(val_recs),
            "test_samples": len(test_recs),
            "domain_grouping": True,
            "domain_leakage_check": "Zero domain overlap between train/val/test",
        },
        "validation_model_comparison": val_metrics,
        "held_out_test_metrics": {
            "roc_auc": test_roc_auc,
            "pr_auc": test_pr_auc,
            "operating_thresholds": threshold_metrics,
            "inference_latency_ms_per_url": round(latency_per_item_ms, 3),
            "artifact_size_bytes": artifact_size_bytes,
        },
        "feature_schema": {
            "feature_count": len(FEATURE_NAMES),
            "feature_names": FEATURE_NAMES,
        },
    }

    rep_path.parent.mkdir(parents=True, exist_ok=True)
    with rep_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"      Saved evaluation report -> {rep_path}")

    # Also mirror artifact to backend/app/ml/artifacts/ for robust loading
    backend_art = repo_root / "backend" / "app" / "ml" / "artifacts" / "url_classifier.joblib"
    backend_art.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact_payload, backend_art)

    return report


if __name__ == "__main__":
    train_and_evaluate()
