"""URL feature extraction (TRD §5). Pure functions, no scoring."""
from __future__ import annotations
import re
from urllib.parse import urlsplit, unquote

SUSPICIOUS_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "security", "bank", "paypal",
    "free", "prize", "winner", "urgent", "suspend", "blocked",
    "password", "credential", "otp", "payment", "invoice", "refund",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "short.link", "tiny.cc", "rebrand.ly", "cutt.ly",
}

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _registrable_domain(host: str) -> str:
    parts = host.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


def extract_url_features(normalized_url: str) -> dict:
    parts = urlsplit(normalized_url)
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    query = parts.query or ""
    full = normalized_url or ""
    lowered = full.lower()

    hostname_labels = [p for p in host.split(".") if p]
    subdomain_count = max(0, len(hostname_labels) - 2) if len(hostname_labels) >= 2 else 0
    digit_count = sum(c.isdigit() for c in full)
    special_count = sum(c in "-_@%?&=+~!$*(),;:" for c in full)

    # encoded/obfuscation indicators
    encoded = "%" in full and bool(re.search(r"%[0-9A-Fa-f]{2}", full))
    try:
        decoded = unquote(full)
        double_encoded = "%25" in full.lower()
    except Exception:
        decoded = full
        double_encoded = False

    is_ip = bool(IPV4_RE.match(host)) or (host.startswith("[") and host.endswith("]"))
    punycode = "xn--" in host
    https = parts.scheme.lower() == "https"
    has_userinfo = bool(parts.username)
    at_in_rest = "@" in path or "@" in query

    susp_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in lowered]
    login_path = any(s in (path + query).lower() for s in ["login", "signin", "sign-in", "log-in"])
    payment_path = any(s in (path + query).lower() for s in ["payment", "pay", "checkout", "invoice", "refund", "billing"])
    shortener = host in SHORTENERS
    suspicious_structure = has_userinfo or at_in_rest or double_encoded or full.count("//") > 1 or full.count("http") > 1

    return {
        "scheme": parts.scheme.lower(),
        "hostname": host,
        "registrable_domain": _registrable_domain(host),
        "path": path,
        "query": query,
        "query_length": len(query),
        "url_length": len(full),
        "hostname_length": len(host),
        "subdomain_count": subdomain_count,
        "digit_count": digit_count,
        "special_count": special_count,
        "suspicious_keywords": susp_keywords,
        "encoded": encoded,
        "double_encoded": double_encoded,
        "is_ip_host": is_ip,
        "punycode": punycode,
        "is_https": https,
        "login_path": login_path,
        "payment_path": payment_path,
        "shortener": shortener,
        "suspicious_structure": suspicious_structure,
        "has_userinfo": has_userinfo,
    }
