"""URL ML signal — transparent heuristic probability (v1).

Kept deliberately simple/deterministic for MVP; versioned. A learned
URL model can replace this behind the same function signature once
validation data supports it (TRD §8, §15-16).
"""
from __future__ import annotations

URL_ML_VERSION = "url-heuristic-v1.0.0"


def url_ml_probability(features: dict) -> float:
    score = 0.0
    if features.get("is_ip_host"):
        score += 0.3
    if features.get("punycode"):
        score += 0.3
    if features.get("suspicious_keywords"):
        score += min(0.3, 0.1 * len(features["suspicious_keywords"]))
    if features.get("suspicious_structure"):
        score += 0.2
    if features.get("shortener"):
        score += 0.15
    if features.get("subdomain_count", 0) >= 3:
        score += 0.15
    if features.get("encoded"):
        score += 0.1
    if features.get("login_path") or features.get("payment_path"):
        score += 0.1
    if not features.get("is_https"):
        score += 0.05
    return round(min(0.95, score), 3)
