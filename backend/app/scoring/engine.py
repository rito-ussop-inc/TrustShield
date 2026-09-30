"""Weighted evidence scoring (TRD §12). Versioned, calibrated later.

Weights are initial engineering values only — NOT scientific thresholds.
Keep scoring separate from feature extraction (rule 6).
"""
from __future__ import annotations

SCORING_VERSION = "scoring-v1.0.0"

# Base weights per signal key
WEIGHTS: dict[str, int] = {
    "threat_intelligence_match": 35,
    "credential_request": 15,
    "suspicious_url": 15,
    "urgency": 10,
    "domain_mismatch": 15,
    "ml_signal": 10,
    # URL-rule fine-grained weights (sum capped at 100 overall)
    "URL_IP_HOST": 15,
    "URL_PUNYCODE": 15,
    "URL_LONG": 5,
    "URL_MANY_SUBDOMAINS": 8,
    "URL_SUSPICIOUS_KEYWORD": 10,
    "URL_ENCODED": 8,
    "URL_LOGIN_PATH": 10,
    "URL_PAYMENT_PATH": 10,
    "URL_SHORTENER": 8,
    "URL_SUSPICIOUS_STRUCTURE": 8,
    "URL_NO_HTTPS": 4,
    # Message-rule weights
    "MSG_URGENCY": 10,
    "MSG_THREAT": 10,
    "MSG_AUTHORITY": 8,
    "MSG_CREDENTIAL_REQUEST": 15,
    "MSG_PAYMENT_REQUEST": 12,
    "MSG_REWARD": 8,
    "MSG_CTA": 5,
    "MSG_URL_PRESENT": 5,
    # Integrity
    "DOC_INTEGRITY_MISMATCH": 30,
    "DOC_NO_REFERENCE": 5,
}

# Risk thresholds (calibrate against validation data per TRD §7)
THRESHOLDS = {
    "CRITICAL": 75,
    "HIGH": 50,
    "MEDIUM": 25,
}


def score_from_signals(signals: dict[str, float | bool | int], ml_phishing_prob: float = 0.0) -> int:
    """Compute 0-100 score from weighted signals.

    signals: mapping signal_key -> truthy/weight factor (0/1 or 0..1).
    ml_phishing_prob: 0..1 model probability for phishing/spam.
    """
    total = 0.0
    for key, val in signals.items():
        w = WEIGHTS.get(key, 0)
        try:
            f = float(val)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            f = 1.0 if val else 0.0
        f = max(0.0, min(1.0, f))
        total += w * f
    # ML contribution scaled by its weight
    if ml_phishing_prob > 0:
        total += WEIGHTS.get("ml_signal", 10) * max(0.0, min(1.0, ml_phishing_prob))
    return int(max(0, min(100, round(total))))


def level_from_score(score: int, has_signals: bool = True) -> str:
    if not has_signals:
        return "UNKNOWN"
    if score >= THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    if score >= THRESHOLDS["HIGH"]:
        return "HIGH"
    if score >= THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"
