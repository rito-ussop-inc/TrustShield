"""URL normalization — safe, deterministic."""
from __future__ import annotations
from urllib.parse import urlsplit, urlunsplit, unquote


def normalize_url(raw: str) -> str:
    url = (raw or "").strip()
    if not url:
        return url
    # Add scheme if missing for parsing, but keep track — validation handles it
    if "://" not in url:
        url = "https://" + url
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower() or "https"
        host = (parts.hostname or "").lower().strip().strip(".")
        # IDNA encode/decode to normalize punycode display safely
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            pass
        netloc = host
        if parts.port and parts.port not in (80, 443):
            netloc = f"{host}:{parts.port}"
        elif parts.username:
            # strip userinfo for canonical form but keep indicator in features
            netloc = host
        path = parts.path or ""
        query = parts.query or ""
        fragment = ""  # drop fragment for canonical analysis
        normalized = urlunsplit((scheme, netloc, path, query, fragment))
        return normalized
    except Exception:
        return url.strip()
