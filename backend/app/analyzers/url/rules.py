"""URL heuristic rules -> Evidence (never decide final result directly)."""
from __future__ import annotations
from app.evidence.models import make_evidence


def apply_url_rules(features: dict) -> tuple[list, dict]:
    evidence = []
    signals: dict[str, float] = {}

    def add(rule_id, category, title, desc, severity, signal_key=None, confidence=None, source="url-heuristics"):
        evidence.append(make_evidence(id=rule_id, category=category, title=title, description=desc, severity=severity, source=source, confidence=confidence))
        if signal_key:
            signals[signal_key] = 1.0

    if features.get("is_ip_host"):
        add("URL_IP_HOST", "url-heuristic", "URL uses an IP address as host",
            "Legitimate public sites rarely use raw IP hosts; phishing often does to evade domain reputation.",
            "MEDIUM", "URL_IP_HOST", 0.7)
    if features.get("url_length", 0) > 150:
        add("URL_LONG", "url-heuristic", f"Unusually long URL ({features['url_length']} chars)",
            "Very long URLs can hide the true destination or carry obfuscated payloads.", "LOW", "URL_LONG", 0.5)
    if features.get("subdomain_count", 0) >= 3:
        add("URL_MANY_SUBDOMAINS", "url-heuristic", f"Excessive subdomains ({features['subdomain_count']})",
            "Multiple nested subdomains are used to mimic trusted brands (e.g. paypal.secure.login.example.com).", "MEDIUM", "URL_MANY_SUBDOMAINS", 0.6)
    if features.get("suspicious_keywords"):
        kws = ", ".join(features["suspicious_keywords"][:6])
        add("URL_SUSPICIOUS_KEYWORD", "url-heuristic", f"Suspicious keywords in URL: {kws}",
            "Words like login/verify/account/urgent are common in phishing lures.", "MEDIUM", "URL_SUSPICIOUS_KEYWORD", 0.6)
    if features.get("encoded") or features.get("double_encoded"):
        add("URL_ENCODED", "url-heuristic", "URL contains encoded/obfuscated sequences",
            "Percent-encoding or double-encoding can hide keywords and destination.", "MEDIUM", "URL_ENCODED", 0.6)
    if features.get("punycode"):
        add("URL_PUNYCODE", "url-heuristic", "URL uses punycode (xn--) internationalized domain",
            "Punycode enables homograph attacks that visually mimic trusted brands.", "HIGH", "URL_PUNYCODE", 0.75)
    if features.get("login_path"):
        add("URL_LOGIN_PATH", "url-heuristic", "URL path suggests a login page",
            "Combined with an unfamiliar domain, login paths indicate possible credential harvesting.", "MEDIUM", "URL_LOGIN_PATH", 0.6)
    if features.get("payment_path"):
        add("URL_PAYMENT_PATH", "url-heuristic", "URL path suggests payment/checkout",
            "Payment paths on unfamiliar domains warrant independent verification.", "MEDIUM", "URL_PAYMENT_PATH", 0.6)
    if features.get("shortener"):
        add("URL_SHORTENER", "url-heuristic", "URL uses a link shortener",
            "Shorteners hide the final destination; expand via a trusted expander before trusting.", "LOW", "URL_SHORTENER", 0.5)
    if features.get("suspicious_structure"):
        add("URL_SUSPICIOUS_STRUCTURE", "url-heuristic", "Suspicious URL structure (userinfo/@/nested scheme)",
            "Patterns like user@host or pasted http inside URL are used to mislead about the real host.", "MEDIUM", "URL_SUSPICIOUS_STRUCTURE", 0.65)
    if not features.get("is_https"):
        add("URL_NO_HTTPS", "url-heuristic", "URL does not use HTTPS",
            "Plain HTTP exposes data in transit; login/payment over HTTP is high risk.", "LOW", "URL_NO_HTTPS", 0.5)

    # Combined suspicious_url aggregate for scoring
    if any(k in signals for k in ("URL_IP_HOST", "URL_PUNYCODE", "URL_SUSPICIOUS_KEYWORD", "URL_SUSPICIOUS_STRUCTURE", "URL_SHORTENER")):
        signals["suspicious_url"] = 1.0

    return evidence, signals
