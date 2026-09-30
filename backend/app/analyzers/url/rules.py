"""URL heuristic rules -> Evidence (never decide final result directly). TRD §5, PRD §7 FR-4."""
from __future__ import annotations
from app.evidence.models import make_evidence


def apply_url_rules(features: dict) -> tuple[list, dict]:
    evidence = []
    signals: dict[str, float] = {}

    def add(rule_id: str, category: str, title: str, desc: str, severity: str, signal_key: str | None = None, confidence: float | None = None, source: str = "url-heuristics"):
        evidence.append(make_evidence(id=rule_id, category=category, title=title, description=desc, severity=severity, source=source, confidence=confidence))
        if signal_key:
            signals[signal_key] = 1.0

    host = features.get("hostname", "")
    reg_domain = features.get("registrable_domain", "")

    # Rule 1: IP address as host
    if features.get("is_ip_host"):
        add(
            "URL_IP_HOST", "url-heuristic",
            f"URL uses a raw IP address as host ({host})",
            "Observed raw IP address instead of a domain name. Legitimate public services generally use registered domain names.",
            "MEDIUM", "URL_IP_HOST", 0.70
        )

    # Rule 2: Unusually long URL
    url_len = features.get("url_length", 0)
    if url_len > 150:
        add(
            "URL_LONG", "url-heuristic",
            f"Unusually long URL ({url_len} characters)",
            "Observed URL length exceeds typical navigation links; long URLs may be used to obscure destinations or embed payloads.",
            "LOW", "URL_LONG", 0.45
        )

    # Rule 3: Many subdomains (PSL-based)
    sub_count = features.get("subdomain_count", 0)
    if sub_count >= 3:
        add(
            "URL_MANY_SUBDOMAINS", "url-heuristic",
            f"Deep subdomain nesting ({sub_count} levels under '{reg_domain}')",
            "Observed multiple nested subdomain labels. Often used in brand-impersonation lures (e.g. brand.verify.account.attacker.com).",
            "MEDIUM", "URL_MANY_SUBDOMAINS", 0.60
        )

    # Rule 4: Suspicious keywords in hostname vs path
    host_kws = features.get("suspicious_keywords_host", [])
    if host_kws:
        kws_str = ", ".join(host_kws[:5])
        add(
            "URL_SUSPICIOUS_KEYWORD", "url-heuristic",
            f"Security/account keywords in hostname: {kws_str}",
            "Observed authentication or financial keywords embedded in the hostname or domain.",
            "MEDIUM", "URL_SUSPICIOUS_KEYWORD", 0.65
        )
    elif features.get("suspicious_keywords_path"):
        path_kws = features.get("suspicious_keywords_path", [])
        kws_str = ", ".join(path_kws[:4])
        add(
            "URL_PATH_KEYWORD", "url-heuristic",
            f"Action/account terms in URL path: {kws_str}",
            "Observed account, login, or billing terms in the URL path. Contextual indicator; common on both legitimate and phishing pages.",
            "LOW", "URL_PATH_KEYWORD", 0.40
        )

    # Rule 5: Obfuscation and Encoding
    if features.get("double_encoded"):
        add(
            "URL_DOUBLE_ENCODED", "url-heuristic",
            "URL contains double-percent-encoded characters (%25)",
            "Observed double percent-encoding sequence. May indicate evasion of basic string filters or WAF inspection.",
            "MEDIUM", "URL_ENCODED", 0.65
        )
    elif features.get("encoded"):
        add(
            "URL_ENCODED", "url-heuristic",
            "URL contains percent-encoded characters",
            "Observed standard percent-encoded characters. Normal for special characters; verified in context.",
            "LOW", "URL_ENCODED", 0.35
        )

    # Rule 6: Punycode / IDNA
    if features.get("punycode"):
        add(
            "URL_PUNYCODE", "url-heuristic",
            f"URL hostname uses Punycode/IDNA (xn--) encoding: {host}",
            "Observed internationalized domain encoding. Legitimate for non-Latin scripts, but also utilized in homograph visual spoofing.",
            "MEDIUM", "URL_PUNYCODE", 0.60
        )

    # Rule 7: Login path
    if features.get("login_path"):
        add(
            "URL_LOGIN_PATH", "url-heuristic",
            "URL path targets an authentication or login endpoint",
            "Observed login/sign-in endpoint in path. Legitimate on recognized platforms; independently verify domain before entering credentials.",
            "LOW", "URL_LOGIN_PATH", 0.50
        )

    # Rule 8: Payment path
    if features.get("payment_path"):
        add(
            "URL_PAYMENT_PATH", "url-heuristic",
            "URL path targets a payment or checkout interface",
            "Observed billing or checkout path. Legitimate for e-commerce and billing; independently verify domain before transacting.",
            "LOW", "URL_PAYMENT_PATH", 0.50
        )

    # Rule 9: Shortener
    if features.get("shortener"):
        add(
            "URL_SHORTENER", "url-heuristic",
            f"URL uses a known link-shortening service ({host})",
            "Observed link shortener domain. Shortened links conceal the ultimate destination domain and query parameters.",
            "LOW", "URL_SHORTENER", 0.50
        )

    # Rule 10: Unusual non-standard port
    if features.get("is_unusual_port"):
        port = features.get("port")
        add(
            "URL_UNUSUAL_PORT", "url-heuristic",
            f"URL specifies non-standard service port {port}",
            "Observed non-standard port for web traffic (expected 80/443). May indicate alternative hosting or evasion.",
            "MEDIUM", "URL_UNUSUAL_PORT", 0.60
        )

    # Rule 11: Suspicious userinfo / structure
    if features.get("has_userinfo"):
        add(
            "URL_USERINFO", "url-heuristic",
            "URL includes userinfo in authority ('user@host')",
            "Observed user credentials or username prefix in the URL authority before '@'. Frequently used to mislead about true host.",
            "HIGH", "URL_SUSPICIOUS_STRUCTURE", 0.75
        )
    elif features.get("has_nested_redirect_url"):
        add(
            "URL_NESTED_REDIRECT", "url-heuristic",
            "URL query parameter contains a nested destination URL",
            "Observed destination URL embedded in query parameter. May act as an open redirect or forwarding bounce.",
            "MEDIUM", "URL_SUSPICIOUS_STRUCTURE", 0.60
        )
    elif features.get("suspicious_structure"):
        add(
            "URL_SUSPICIOUS_STRUCTURE", "url-heuristic",
            "Suspicious URL syntax structure",
            "Observed structural anomalies such as embedded schemes or redundant separators.",
            "MEDIUM", "URL_SUSPICIOUS_STRUCTURE", 0.55
        )

    # Rule 12: Cleartext HTTP
    if not features.get("is_https"):
        add(
            "URL_NO_HTTPS", "url-heuristic",
            "URL uses unencrypted HTTP protocol",
            "Observed plain HTTP connection. Data in transit is vulnerable to interception and tampering on local networks.",
            "LOW", "URL_NO_HTTPS", 0.50
        )

    # Backward compatibility: aggregate suspicious_url signal
    if any(k in signals for k in ("URL_IP_HOST", "URL_PUNYCODE", "URL_SUSPICIOUS_KEYWORD", "URL_SUSPICIOUS_STRUCTURE", "URL_SHORTENER", "URL_UNUSUAL_PORT")):
        signals["suspicious_url"] = 1.0

    return evidence, signals
