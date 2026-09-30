"""Strict URL validation (TRD §17)."""
from __future__ import annotations
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}


def validate_url(url: str) -> tuple[bool, str]:
    """Returns (ok, reason)."""
    if not url or len(url) > 2048:
        return False, "URL is empty or exceeds 2048 characters"
    try:
        parts = urlsplit(url)
    except Exception:
        return False, "URL could not be parsed"
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"Only http/https URLs are supported (got '{parts.scheme}')"
    host = parts.hostname or ""
    if not host:
        return False, "URL must include a hostname"
    if len(host) > 253:
        return False, "Hostname too long"
    if " " in url or "\n" in url or "\r" in url:
        return False, "URL contains whitespace"
    if "@" in (parts.netloc or "") and parts.username:
        # userinfo in URL is suspicious but still parseable — allow with warning
        pass
    return True, "ok"
