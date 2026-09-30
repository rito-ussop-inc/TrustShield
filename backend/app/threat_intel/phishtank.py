"""PhishTank provider — POST https://checkurl.phishtank.com/checkurl/"""
from __future__ import annotations
import httpx
from urllib.parse import quote
from app.threat_intel.base import ThreatIntelResult


class PhishTankProvider:
    name = "phishtank"

    def __init__(self, api_key: str = "", timeout: int = 3):
        self.api_key = api_key
        self.timeout = timeout

    async def check_url(self, url: str) -> ThreatIntelResult:
        if not self.api_key:
            return ThreatIntelResult(provider=self.name, status="not_configured", matched=False, detail="PHISHTANK_API_KEY not set")
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    "https://checkurl.phishtank.com/checkurl/",
                    data={"url": url, "format": "json", "app_key": self.api_key},
                    headers={"User-Agent": "TrustShield/1.0"},
                )
                if resp.status_code != 200:
                    return ThreatIntelResult(provider=self.name, status="unavailable", matched=False, detail=f"HTTP {resp.status_code}")
                data = resp.json()
                results = data.get("results", {})
                in_db = bool(results.get("in_database"))
                verified = bool(results.get("verified"))
                valid = bool(results.get("valid"))
                matched = bool(in_db and valid)
                if matched:
                    return ThreatIntelResult(provider=self.name, status="match", matched=True, category="phishing", detail="Listed in PhishTank")
                return ThreatIntelResult(provider=self.name, status="no_match", matched=False, detail="Not listed in PhishTank")
        except Exception as e:
            return ThreatIntelResult(provider=self.name, status="unavailable", matched=False, detail=f"{type(e).__name__}: provider failure")
