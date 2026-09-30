"""URL feature extraction (TRD §5, PRD §7 FR-3). Pure functions, no scoring."""
from __future__ import annotations
import re
from urllib.parse import urlsplit, parse_qsl, unquote
import tldextract
from app.analyzers.url.validation import is_valid_ipv4, is_valid_ipv6

SUSPICIOUS_HOST_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "security", "bank", "paypal",
    "password", "credential", "suspend", "blocked",
]

SUSPICIOUS_PATH_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "security", "bank", "paypal",
    "free", "prize", "winner", "urgent", "suspend", "blocked",
    "password", "credential", "otp", "payment", "invoice", "refund",
    "checkout", "billing", "wallet",
]

SUSPICIOUS_QUERY_KEYWORDS = [
    "login", "signin", "verify", "account", "token", "password", "otp",
    "redirect", "dest", "url", "return", "session", "credential",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "short.link", "tiny.cc", "rebrand.ly", "cutt.ly",
    "is.gd", "v.gd", "rb.gy",
}

# Offline PSL extractor using bundled data only (no DNS or web requests)
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)


def extract_domain_info(host: str) -> tuple[str, str, str, int]:
    """Returns (registrable_domain, suffix, subdomain, subdomain_count) using PSL."""
    if not host:
        return "", "", "", 0
    clean_host = host.strip("[]")
    if is_valid_ipv4(clean_host) or is_valid_ipv6(clean_host):
        return host, "", "", 0

    res = _TLD_EXTRACTOR(clean_host)
    if res.domain and res.suffix:
        reg_domain = f"{res.domain}.{res.suffix}"
    else:
        reg_domain = clean_host

    subdomain = res.subdomain or ""
    subdomain_count = len([p for p in subdomain.split(".") if p]) if subdomain else 0
    return reg_domain, res.suffix or "", subdomain, subdomain_count


def _registrable_domain(host: str) -> str:
    """Maintained backward-compatible function now using PSL."""
    reg, _, _, _ = extract_domain_info(host)
    return reg


def extract_url_features(normalized_url: str) -> dict:
    parts = urlsplit(normalized_url or "")
    raw_host = parts.hostname or ""
    host = raw_host.lower()
    path = parts.path or ""
    query = parts.query or ""
    full = normalized_url or ""
    lowered = full.lower()

    # PSL domain extraction
    registrable_domain, suffix, subdomain, subdomain_count = extract_domain_info(host)

    # Host type determination
    clean_host = host.strip("[]")
    if is_valid_ipv4(clean_host):
        host_type = "ipv4"
        is_ip = True
    elif is_valid_ipv6(clean_host) or (host.startswith("[") and host.endswith("]")):
        host_type = "ipv6"
        is_ip = True
    elif host in ("localhost", "127.0.0.1", "::1"):
        host_type = "localhost"
        is_ip = host != "localhost"
    else:
        host_type = "domain"
        is_ip = False

    hostname_labels = [p for p in host.split(".") if p]
    label_count = len(hostname_labels)
    digit_count = sum(c.isdigit() for c in full)
    special_count = sum(c in "-_@%?&=+~!$*(),;:" for c in full)

    # Encoding / obfuscation indicators
    encoded = "%" in full and bool(re.search(r"%[0-9A-Fa-f]{2}", full))
    double_encoded = "%25" in lowered

    punycode = "xn--" in host
    https = parts.scheme.lower() == "https"
    has_userinfo = bool(parts.username) or ("@" in (parts.netloc or ""))
    at_in_rest = "@" in path or "@" in query

    # Port analysis
    port: int | None = None
    try:
        port = parts.port
    except ValueError:
        pass
    is_unusual_port = port is not None and port not in (80, 443, 8080, 8443)

    # Component-aware keyword extraction
    host_terms = [k for k in SUSPICIOUS_HOST_KEYWORDS if k in host]
    path_terms = [k for k in SUSPICIOUS_PATH_KEYWORDS if k in path.lower()]
    query_terms = [k for k in SUSPICIOUS_QUERY_KEYWORDS if k in query.lower()]

    # Deduplicated list for backward compatibility
    all_susp_keywords = list(dict.fromkeys(host_terms + path_terms + query_terms))

    # Path context
    login_path = any(s in path.lower() for s in ["login", "signin", "sign-in", "log-in"])
    payment_path = any(s in path.lower() for s in ["payment", "pay", "checkout", "invoice", "refund", "billing"])
    has_credential_terms = any(s in (path + " " + query).lower() for s in ["password", "credential", "otp", "token", "auth"])
    has_payment_terms = payment_path or any(s in query.lower() for s in ["payment", "invoice", "refund", "card", "bank"])

    # Query params analysis & nested redirect URLs
    query_params = []
    has_nested_redirect_url = False
    try:
        query_params = parse_qsl(query, keep_blank_values=True)
        for k, v in query_params:
            lk, lv = k.lower(), v.lower()
            if lk in ("redirect", "url", "next", "dest", "target", "return", "goto", "out"):
                if lv.startswith(("http://", "https://", "//")) or "%3a%2f%2f" in lv:
                    has_nested_redirect_url = True
                    break
    except Exception:
        pass

    shortener = host in SHORTENERS or registrable_domain in SHORTENERS
    has_trailing_dot = host.endswith(".") or (parts.netloc and parts.netloc.split(":")[0].endswith("."))

    # Structural suspicion
    suspicious_structure = (
        has_userinfo
        or at_in_rest
        or double_encoded
        or full.count("//") > 1
        or full.count("http") > 1
        or has_nested_redirect_url
    )

    return {
        "scheme": parts.scheme.lower(),
        "hostname": host,
        "registrable_domain": registrable_domain,
        "public_suffix": suffix,
        "subdomain": subdomain,
        "host_type": host_type,
        "path": path,
        "query": query,
        "path_length": len(path),
        "query_length": len(query),
        "query_param_count": len(query_params),
        "url_length": len(full),
        "hostname_length": len(host),
        "label_count": label_count,
        "subdomain_count": subdomain_count,
        "digit_count": digit_count,
        "special_count": special_count,
        "suspicious_keywords": all_susp_keywords,
        "suspicious_keywords_host": host_terms,
        "suspicious_keywords_path": path_terms,
        "suspicious_keywords_query": query_terms,
        "encoded": encoded,
        "double_encoded": double_encoded,
        "is_ip_host": is_ip,
        "punycode": punycode,
        "is_https": https,
        "port": port,
        "is_unusual_port": is_unusual_port,
        "login_path": login_path,
        "payment_path": payment_path,
        "has_credential_terms": has_credential_terms,
        "has_payment_terms": has_payment_terms,
        "has_nested_redirect_url": has_nested_redirect_url,
        "shortener": shortener,
        "has_trailing_dot": has_trailing_dot,
        "suspicious_structure": suspicious_structure,
        "has_userinfo": has_userinfo,
    }
