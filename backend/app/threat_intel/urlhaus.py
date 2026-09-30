"""URLhaus provider — POST https://urlhaus-api.abuse.ch/v1/url/"""
from __future__ import annotations
import httpx
from app.threat_intel.base import ThreatIntelResult


class URLhausProvider:
    name = "urlhaus"

    def __init__(self, api_key: str = "", timeout: int = 3):
        self.api_key = api_key
        self.timeout = timeout

    async def check_url(self, url: str) -> ThreatIntelResult:
        try:
            headers = {"User-Agent": "TrustShield/1.0"}
            if self.api_key:
                headers["Auth-Key"] = self.api_key
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers=headers)
                if resp.status_code != 200:
                    return ThreatIntelResult(provider=self.name, status="unavailable", matched=False, detail=f"HTTP {resp.status_code}")
                data = resp.json()
                qs = (data.get("query_status") or "").lower()
                if qs in ("ok", "found"):
                    threat = data.get("threat") or data.get("url_status") or "malware"
                    return ThreatIntelResult(provider=self.name, status="match", matched=True, category=str(threat), detail="Listed in URLhaus")
                if qs in ("no_results", "not_found"):
                    return ThreatIntelResult(provider=self.name, status="no_match", matched=False, detail="Not listed in URLhaus")
                return ThreatIntelResult(provider=self.name, status="unavailable", matched=False, detail=f"query_status={qs}")
        except Exception as e:
            return ThreatIntelResult(provider=self.name, status="unavailable", matched=False, detail=f"{type(e).__name__}: provider failure")
