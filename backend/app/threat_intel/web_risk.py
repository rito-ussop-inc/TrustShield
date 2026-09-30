"""Google Web Risk provider — GET threats:search (requires API key).

Docs: https://cloud.google.com/web-risk/docs — if key missing -> not_configured.
"""
from __future__ import annotations
import httpx
from urllib.parse import quote
from app.threat_intel.base import ThreatIntelResult


class WebRiskProvider:
    name = "webrisk"

    def __init__(self, api_key: str = "", timeout: int = 3):
        self.api_key = api_key
        self.timeout = timeout

    async def check_url(self, url: str) -> ThreatIntelResult:
        if not self.api_key:
            return ThreatIntelResult(provider=self.name, status="not_configured", matched=False, detail="WEBRISK_API_KEY not set")
        try:
            endpoint = (
                "https://webrisk.googleapis.com/v1/uris:search"
                f"?key={self.api_key}&uri={quote(url, safe='')}"
                "&threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE"
            )
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(endpoint, headers={"User-Agent": "TrustShield/1.0"})
                if resp.status_code != 200:
                    return ThreatIntelResult(provider=self.name, status="unavailable", matched=False, detail=f"HTTP {resp.status_code}")
                data = resp.json()
                threat = data.get("threat")
                if threat:
                    types = threat.get("threatTypes") or threat.get("threat_types") or ["SOCIAL_ENGINEERING"]
                    return ThreatIntelResult(provider=self.name, status="match", matched=True, category=",".join(types), detail="Flagged by Google Web Risk")
                return ThreatIntelResult(provider=self.name, status="no_match", matched=False, detail="Not flagged by Web Risk")
        except Exception as e:
            return ThreatIntelResult(provider=self.name, status="unavailable", matched=False, detail=f"{type(e).__name__}: provider failure")
