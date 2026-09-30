"""Strict URL validation (TRD §17, PRD §7 FR-1)."""
from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}

IPV4_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
IPV4_REGEX = re.compile(r"^" + r"\.".join([IPV4_OCTET] * 4) + r"$")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class URLValidationResult:
    is_valid: bool
    reason: str
    scheme_inferred: bool = False
    candidate_url: str = ""
    warnings: list[str] = field(default_factory=list)


def is_valid_ipv4(host: str) -> bool:
    if IPV4_REGEX.match(host):
        try:
            ipaddress.IPv4Address(host)
            return True
        except ValueError:
            return False
    return False


def is_valid_ipv6(host: str) -> bool:
    clean = host.strip("[]")
    try:
        ipaddress.IPv6Address(clean)
        return True
    except ValueError:
        return False


def validate_url_detailed(url: str, allow_schemeless: bool = True) -> URLValidationResult:
    """Validates URL according to FR-1 and returns rich validation result."""
    if not url or not url.strip() or len(url) > 2048:
        return URLValidationResult(False, "URL is empty or exceeds 2048 characters")

    raw = url.strip()
    if any(c.isspace() for c in raw):
        return URLValidationResult(False, "URL contains whitespace")
    if CONTROL_CHAR_RE.search(raw):
        return URLValidationResult(False, "URL contains control characters")

    scheme_inferred = False
    if "://" in raw:
        scheme_part, _ = raw.split("://", 1)
        scheme = scheme_part.lower()
        if scheme not in ALLOWED_SCHEMES:
            return URLValidationResult(False, f"Only http/https URLs are supported (got '{scheme}')")
        candidate = raw
    else:
        # Check for non-HTTP colon schemes like javascript:, data:, file:, etc.
        colon_idx = raw.find(":")
        slash_idx = raw.find("/")
        q_idx = raw.find("?")
        delims = [i for i in (slash_idx, q_idx) if i != -1]
        first_delim = min(delims) if delims else len(raw)

        if colon_idx != -1 and colon_idx < first_delim:
            prefix = raw[:colon_idx].lower()
            suffix = raw[colon_idx + 1:first_delim]
            # If suffix is not numeric port, it's an unsupported scheme
            if not suffix.isdigit():
                return URLValidationResult(False, f"Only http/https URLs are supported (got '{prefix}')")

        if not allow_schemeless:
            return URLValidationResult(False, "Missing URL scheme (http/https required)")

        candidate = "https://" + raw
        scheme_inferred = True

    try:
        parts = urlsplit(candidate)
    except Exception as e:
        return URLValidationResult(False, f"URL could not be parsed: {e}")

    # Port validation
    try:
        port = parts.port
        if port is not None and not (1 <= port <= 65535):
            return URLValidationResult(False, f"Port out of range (1-65535, got {port})")
    except ValueError:
        return URLValidationResult(False, "Invalid port number in URL")

    # Host validation
    host = parts.hostname or ""
    if not host:
        return URLValidationResult(False, "URL must include a hostname")
    if len(host) > 253:
        return URLValidationResult(False, "Hostname exceeds 253 characters")

    # IPv6 check
    netloc = parts.netloc or ""
    is_ipv6 = "[" in netloc or "]" in netloc
    if is_ipv6:
        if not (netloc.count("[") == 1 and netloc.count("]") == 1 and netloc.find("[") < netloc.find("]")):
            return URLValidationResult(False, "Malformed bracketed IPv6 in authority")
        if not is_valid_ipv6(host):
            return URLValidationResult(False, f"Invalid IPv6 address ('{host}')")

    # IPv4 numeric check: if not IPv6 and contains only digits and dots (or starts like IPv4)
    if not is_ipv6 and host and (all(c.isdigit() or c == "." for c in host) and "." in host):
        if not is_valid_ipv4(host):
            return URLValidationResult(False, f"Invalid IPv4 address ('{host}')")

    # Check DNS labels
    for lbl in host.split("."):
        if len(lbl) > 63:
            return URLValidationResult(False, "Hostname label exceeds 63 characters")

    warnings: list[str] = []
    if scheme_inferred:
        warnings.append("Scheme was missing from input; inferred https://")
    if parts.username or ("@" in netloc):
        warnings.append("URL contains userinfo in authority component")

    return URLValidationResult(
        is_valid=True,
        reason="ok",
        scheme_inferred=scheme_inferred,
        candidate_url=candidate,
        warnings=warnings,
    )


def validate_url(url: str, allow_schemeless: bool = True) -> tuple[bool, str]:
    """Returns (ok, reason) for compatibility with existing callers."""
    res = validate_url_detailed(url, allow_schemeless=allow_schemeless)
    return res.is_valid, res.reason
