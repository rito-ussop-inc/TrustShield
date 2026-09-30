"""Threat intelligence orchestration — bounded concurrency, timeouts, caching, and failure resilience.
TRD §6, PRD §7 FR-5, FR-11.
"""
from __future__ import annotations
import asyncio
import time
from urllib.parse import urlsplit, urlunsplit
from app.threat_intel.base import ThreatIntelResult

# In-memory TTL cache: (provider, clean_url) -> (ThreatIntelResult, expire_time)
_CACHE: dict[tuple[str, str], tuple[ThreatIntelResult, float]] = {}
DEFAULT_CACHE_TTL_SECONDS = 300  # 5 minutes
DEFAULT_PROVIDER_TIMEOUT = 3  # seconds (strict per-provider cap per Before/After spec)
CONCURRENCY_LIMIT = 5


def _sanitize_url_for_provider(url: str) -> str:
    """Strips userinfo from URL before sending to third-party threat intel providers."""
    try:
        parts = urlsplit(url)
        if "@" in parts.netloc:
            # strip userinfo
            host_and_port = parts.netloc.split("@")[-1]
            return urlunsplit((parts.scheme, host_and_port, parts.path, parts.query, ""))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
    except Exception:
        return url


def clear_cache():
    """Clear threat intel cache (useful in tests)."""
    _CACHE.clear()


async def _check_single_provider(
    provider,
    clean_url: str,
    semaphore: asyncio.Semaphore,
    timeout: int = DEFAULT_PROVIDER_TIMEOUT,
) -> ThreatIntelResult:
    provider_name = getattr(provider, "name", "unknown")
    now = time.time()
    cache_key = (provider_name, clean_url)

    # Check cache
    if cache_key in _CACHE:
        cached_result, expire_time = _CACHE[cache_key]
        if now < expire_time:
            return cached_result

    async with semaphore:
        try:
            # Wrap check_url with hard timeout
            result: ThreatIntelResult = await asyncio.wait_for(
                provider.check_url(clean_url),
                timeout=float(getattr(provider, "timeout", timeout) or timeout),
            )
            # Normalize status
            status = result.status.lower()
            if status not in ("match", "no_match", "unavailable", "not_configured"):
                status = "unavailable"
            result.status = status

            # Cache successful checks (match or no_match)
            if status in ("match", "no_match"):
                _CACHE[cache_key] = (result, now + DEFAULT_CACHE_TTL_SECONDS)

            return result

        except asyncio.TimeoutError:
            return ThreatIntelResult(
                provider=provider_name,
                status="unavailable",
                matched=False,
                detail=f"Provider request timed out after {timeout}s",
            )
        except Exception as e:
            # Sanitize error detail to prevent secret leaks
            err_msg = type(e).__name__
            return ThreatIntelResult(
                provider=provider_name,
                status="unavailable",
                matched=False,
                detail=f"{err_msg}: provider communication failure",
            )


async def check_all(
    providers,
    url: str,
    timeout: int = DEFAULT_PROVIDER_TIMEOUT,
) -> list[ThreatIntelResult]:
    """Fan out to all configured providers with bounded concurrency and timeouts."""
    if not providers:
        return []

    clean_url = _sanitize_url_for_provider(url)
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    tasks = [
        _check_single_provider(p, clean_url, semaphore, timeout=timeout)
        for p in providers
    ]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return list(results)
