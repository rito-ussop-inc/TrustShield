"""URL ML integration module (TRD §8, PRD §7 FR-6).

Replaces previous heuristic-only scoring with a genuinely trained tabular model
backed by URLClassifier. Transparently falls back to heuristic baseline if
model artifact is unavailable, clearly documenting the signal origin.
"""
from __future__ import annotations
from app.ml.url_classifier import get_classifier, DEFAULT_MODEL_VERSION

URL_ML_VERSION = DEFAULT_MODEL_VERSION


def url_heuristic_baseline_score(features: dict) -> float:
    """Explicit deterministic heuristic baseline (not a learned model).
    Retained for explainable local fallbacks.
    """
    score = 0.0
    if features.get("is_ip_host"):
        score += 0.30
    if features.get("punycode"):
        score += 0.25
    if features.get("suspicious_keywords_host"):
        score += min(0.30, 0.15 * len(features["suspicious_keywords_host"]))
    elif features.get("suspicious_keywords"):
        score += min(0.20, 0.05 * len(features["suspicious_keywords"]))
    if features.get("suspicious_structure"):
        score += 0.20
    if features.get("shortener"):
        score += 0.15
    if features.get("subdomain_count", 0) >= 3:
        score += 0.15
    if features.get("double_encoded"):
        score += 0.15
    elif features.get("encoded"):
        score += 0.05
    if features.get("login_path") or features.get("payment_path"):
        score += 0.10
    if not features.get("is_https"):
        score += 0.05
    return round(min(0.95, score), 3)


def url_ml_probability(features_or_url: dict | str) -> float:
    """Returns estimated malicious probability.
    Uses trained tabular model if available; falls back to transparent heuristic baseline.
    """
    clf = get_classifier()

    # If full URL string was passed
    if isinstance(features_or_url, str):
        prob = clf.predict_probability(features_or_url)
        if prob is not None:
            return prob
        # Fallback to heuristic
        from app.analyzers.url.features import extract_url_features
        feats = extract_url_features(features_or_url)
        return url_heuristic_baseline_score(feats)

    # If features dict was passed
    if isinstance(features_or_url, dict):
        url = features_or_url.get("normalized_url") or features_or_url.get("url")
        if url:
            prob = clf.predict_probability(url)
            if prob is not None:
                return prob
        return url_heuristic_baseline_score(features_or_url)

    return 0.0


def get_url_ml_info() -> dict:
    """Returns status and version of URL ML subsystem."""
    clf = get_classifier()
    status = clf.get_status()
    return {
        "status": status["status"],
        "version": status["version"],
        "is_trained_model": status["status"] == "available",
        "error": status.get("error"),
    }
