"""Pydantic schemas — API contracts (TRD §4, §13, §14)."""
from __future__ import annotations
from typing import Literal
from pydantic import BaseModel, Field

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
InputType = Literal["URL", "QR", "MESSAGE", "DOCUMENT"]
Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH"]


class Evidence(BaseModel):
    id: str
    category: str
    title: str
    description: str
    severity: Severity
    source: str | None = None
    confidence: float | None = None


class AnalysisResult(BaseModel):
    analysisId: str
    inputType: InputType
    riskScore: int | None = None
    riskLevel: RiskLevel
    confidence: float | None = None
    findings: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    recommendation: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    providerStatus: dict[str, str] = Field(default_factory=dict)
    decodedPayload: str | None = None
    payloadType: str | None = None
    fileSha256: str | None = None


class UrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class MessageRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10000)


class DocumentResponseExtra(BaseModel):
    fileSha256: str | None = None
    integrityMatch: bool | None = None


class HistoryItem(BaseModel):
    analysisId: str
    inputType: InputType
    riskLevel: RiskLevel
    riskScore: int | None
    createdAt: str
