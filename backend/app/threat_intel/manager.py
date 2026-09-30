"""Fan-out to all configured providers; failures -> unavailable, continue local analysis."""
from __future__ import annotations
import asyncio
from app.threat_intel.base import ThreatIntelResult


async def check_all(providers, url: str) -> list[ThreatIntelResult]:
    results: list[ThreatIntelResult] = []
    for p in providers:
        try:
            r = await p.check_url(url)
        except Exception as e:
            r = ThreatIntelResult(provider=getattr(p, "name", "unknown"), status="unavailable", matched=False, detail=str(e)[:200])
        results.append(r)
    return results
