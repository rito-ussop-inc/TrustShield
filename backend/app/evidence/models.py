"""Evidence helpers — keep evidence separate from scoring (TRD rule 7)."""
from __future__ import annotations
import uuid
from app.schemas.models import Evidence


def make_evidence(
    *,
    id: str,
    category: str,
    title: str,
    description: str,
    severity: str = "INFO",
    source: str | None = None,
    confidence: float | None = None,
) -> Evidence:
    sev = severity if severity in ("INFO", "LOW", "MEDIUM", "HIGH") else "INFO"
    return Evidence(
        id=id,
        category=category,
        title=title,
        description=description,
        severity=sev,  # type: ignore[arg-type]
        source=source,
        confidence=confidence,
    )


def unique_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"
