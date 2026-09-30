"""Threat-intel provider interface (TRD §6)."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol


@dataclass
class ThreatIntelResult:
    provider: str
    status: str  # match | no_match | unavailable | not_configured | error
    matched: bool = False
    category: str | None = None
    detail: str | None = None


class ThreatIntelProvider(Protocol):
    name: str

    async def check_url(self, url: str) -> ThreatIntelResult:
        ...
