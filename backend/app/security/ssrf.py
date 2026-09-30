"""SSRF protection (TRD §17). Backend NEVER fetches arbitrary user URLs for content.

If fetching is ever needed, use safe_fetch() which blocks private/loopback/
link-local ranges, restricts schemes, validates DNS, applies timeouts and
redirect limits.
"""
from __future__ import annotations
import ipaddress
import socket
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False


def validate_fetch_target(url: str) -> tuple[bool, str]:
    try:
        parts = urlsplit(url)
    except Exception:
        return False, "unparseable URL"
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        return False, "protocol not allowed"
    host = parts.hostname or ""
    if not host:
        return False, "missing host"
    # block obvious internal names
    if host.lower() in ("localhost", "metadata.google.internal") or host.lower().endswith(".internal"):
        return False, "internal host blocked"
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except Exception:
        return False, "DNS resolution failed"
    for fam, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if not _is_public_ip(ip):
            return False, f"resolved IP {ip} is not public (SSRF blocked)"
    return True, "ok"


async def safe_fetch(url: str, timeout: int = 5, max_redirects: int = 2) -> bytes:
    ok, reason = validate_fetch_target(url)
    if not ok:
        raise ValueError(f"SSRF blocked: {reason}")
    import httpx
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, max_redirects=max_redirects) as client:
        r = await client.get(url, headers={"User-Agent": "TrustShield/1.0"})
        r.raise_for_status()
        return r.content[:2_000_000]
