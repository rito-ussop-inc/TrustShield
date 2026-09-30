"""Weighted non-duplicative evidence scoring (TRD §12, PRD §7 FR-9).
Versioned fusion strategy preventing double counting across rules, aggregate signals, and model predictions.
"""
from __future__ import annotations

SCORING_VERSION = "scoring-v2.0.0"

# Category caps for local URL rules to prevent correlated signal stacking
URL_HOST_ANOMALY_CAP = 25
URL_LURE_CATEGORY_CAP = 20
URL_OBFUSCATION_CAP = 15

# ML channel max contribution
ML_CHANNEL_MAX = 25

# Base weights per signal key
WEIGHTS: dict[str, int] = {
    # Threat Intelligence (dominant external signal)
    "threat_intelligence_match": 35,
    # Host / Authority Anomalies
    "URL_IP_HOST": 15,
    "URL_PUNYCODE": 15,
    "URL_USERINFO": 15,
    "URL_UNUSUAL_PORT": 10,
    "URL_SUSPICIOUS_STRUCTURE": 10,
    # Host & Path Lures
    "URL_SUSPICIOUS_KEYWORD": 15,
    "URL_MANY_SUBDOMAINS": 10,
    "URL_LOGIN_PATH": 8,
    "URL_PAYMENT_PATH": 8,
    "URL_PATH_KEYWORD": 5,
    # Obfuscation & Context
    "URL_DOUBLE_ENCODED": 10,
    "URL_ENCODED": 4,
    "URL_NESTED_REDIRECT": 8,
    "URL_SHORTENER": 6,
    "URL_LONG": 4,
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
    # Legacy / shared keys
    "credential_request": 15,
    "urgency": 10,
    "domain_mismatch": 15,
}

# Calibrated Risk Thresholds (FR-9)
THRESHOLDS = {
    "CRITICAL": 75,
    "HIGH": 50,
    "MEDIUM": 25,
}


def score_from_signals(
    signals: dict[str, float | bool | int],
    ml_phishing_prob: float = 0.0,
) -> int:
    """Computes non-duplicative fused 0-100 score.
    Separates Threat Intel, Local Heuristics (with category caps), and Calibrated ML.
    """
    total = 0.0

    # 1. Threat Intelligence channel
    ti_signal = float(signals.get("threat_intelligence_match", 0.0) or 0.0)
    if ti_signal > 0:
        total += WEIGHTS["threat_intelligence_match"] * min(1.0, ti_signal)

    # 2. Local URL Heuristic channel (partitioned with category caps to prevent double-counting)
    host_subtotal = 0.0
    for k in ("URL_IP_HOST", "URL_PUNYCODE", "URL_USERINFO", "URL_UNUSUAL_PORT", "URL_SUSPICIOUS_STRUCTURE"):
        if signals.get(k):
            host_subtotal += WEIGHTS[k]
    total += min(URL_HOST_ANOMALY_CAP, host_subtotal)

    lure_subtotal = 0.0
    for k in ("URL_SUSPICIOUS_KEYWORD", "URL_MANY_SUBDOMAINS", "URL_LOGIN_PATH", "URL_PAYMENT_PATH", "URL_PATH_KEYWORD"):
        if signals.get(k):
            lure_subtotal += WEIGHTS[k]
    total += min(URL_LURE_CATEGORY_CAP, lure_subtotal)

    obf_subtotal = 0.0
    for k in ("URL_DOUBLE_ENCODED", "URL_ENCODED", "URL_NESTED_REDIRECT", "URL_SHORTENER", "URL_LONG", "URL_NO_HTTPS"):
        if signals.get(k):
            obf_subtotal += WEIGHTS[k]
    total += min(URL_OBFUSCATION_CAP, obf_subtotal)

    # If only aggregate suspicious_url was provided without fine-grained rules
    has_fine_url_rules = (host_subtotal + lure_subtotal + obf_subtotal) > 0
    if not has_fine_url_rules and signals.get("suspicious_url"):
        total += 15.0

    # 3. Message, Document, and other domain signals
    for key, val in signals.items():
        if key in ("threat_intelligence_match", "suspicious_url") or key.startswith("URL_"):
            continue
        w = WEIGHTS.get(key, 0)
        try:
            f = float(val)
        except (TypeError, ValueError):
            f = 1.0 if val else 0.0
        total += w * max(0.0, min(1.0, f))

    # 4. Calibrated ML Channel (independent, non-duplicated supporting signal)
    if ml_phishing_prob > 0.15:
        # Scale to max ML_CHANNEL_MAX points
        ml_contrib = ML_CHANNEL_MAX * max(0.0, min(1.0, ml_phishing_prob))
        total += ml_contrib

    return int(max(0, min(100, round(total))))


def level_from_score(score: int, has_signals: bool = True, force_unknown: bool = False) -> str:
    if force_unknown or not has_signals:
        return "UNKNOWN"
    if score >= THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    if score >= THRESHOLDS["HIGH"]:
        return "HIGH"
    if score >= THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"
