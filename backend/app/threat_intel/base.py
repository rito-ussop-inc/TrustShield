"""Threat-intel provider interface (TRD §6, PRD §7 FR-5)."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol, Literal

ProviderStatusType = Literal["match", "no_match", "unavailable", "not_configured"]


@dataclass
class ThreatIntelResult:
    provider: str
    status: str  # match | no_match | unavailable | not_configured
    matched: bool = False
    category: str | None = None
    detail: str | None = None
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ThreatIntelProvider(Protocol):
    name: str

    async def check_url(self, url: str) -> ThreatIntelResult:
        ...
