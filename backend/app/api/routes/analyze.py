"""API routes (TRD §4)."""
from __future__ import annotations
import hashlib
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Request
from app.schemas.models import UrlRequest, MessageRequest, AnalysisResult
from app.services.analysis import analyze_url, analyze_message, analyze_qr, analyze_document
from app.threat_intel.phishtank import PhishTankProvider
from app.threat_intel.urlhaus import URLhausProvider
from app.threat_intel.web_risk import WebRiskProvider
from app.config import get_settings

router = APIRouter(prefix="/api/v1")


def _providers():
    s = get_settings()
    return [
        PhishTankProvider(api_key=s.PHISHTANK_API_KEY, timeout=s.REQUEST_TIMEOUT_SECONDS),
        URLhausProvider(api_key=s.URLHAUS_API_KEY, timeout=s.REQUEST_TIMEOUT_SECONDS),
        WebRiskProvider(api_key=s.WEBRISK_API_KEY, timeout=s.REQUEST_TIMEOUT_SECONDS),
    ]


@router.post("/analyze/url", response_model=AnalysisResult)
async def post_analyze_url(body: UrlRequest):
    if not body.url or not body.url.strip():
        raise HTTPException(status_code=422, detail="URL must not be empty")
    return await analyze_url(body.url.strip(), _providers())


@router.post("/analyze/message", response_model=AnalysisResult)
async def post_analyze_message(body: MessageRequest):
    if not body.text or not body.text.strip():
        raise HTTPException(status_code=422, detail="Message text must not be empty")
    return await analyze_message(body.text, _providers())


@router.post("/analyze/qr", response_model=AnalysisResult)
async def post_analyze_qr(file: UploadFile = File(...)):
    s = get_settings()
    data = await file.read()
    if len(data) > s.MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File exceeds {s.MAX_UPLOAD_MB} MB")
    if len(data) == 0:
        raise HTTPException(status_code=422, detail="Empty file")
    ct = (file.content_type or "").lower()
    if not (ct.startswith("image/") or ct == "application/octet-stream"):
        # allow by extension fallback
        name = (file.filename or "").lower()
        if not name.endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp")):
            raise HTTPException(status_code=415, detail="Only QR image files (png/jpg/webp) are supported")
    return await analyze_qr(data, file.filename or "qr.png", _providers())


@router.post("/analyze/document", response_model=AnalysisResult)
async def post_analyze_document(file: UploadFile = File(...), reference_sha256: str | None = Form(default=None)):
    s = get_settings()
    data = await file.read()
    if len(data) > s.MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File exceeds {s.MAX_UPLOAD_MB} MB")
    if len(data) == 0:
        raise HTTPException(status_code=422, detail="Empty file")
    return await analyze_document(data, file.filename or "document", file.content_type, reference_sha256, s.MAX_UPLOAD_MB)


@router.get("/analyses")
def list_analyses(limit: int = 20):
    limit = max(1, min(100, limit))
    try:
        from app.database.db import get_session, Analysis
        s = get_session()
        try:
            rows = s.query(Analysis).order_by(Analysis.created_at.desc()).limit(limit).all()
            return [
                {
                    "analysisId": r.id,
                    "inputType": r.input_type,
                    "riskLevel": r.risk_level,
                    "riskScore": r.risk_score,
                    "inputSummary": r.input_summary or (r.input_hash[:16] if r.input_hash else "—"),
                    "createdAt": r.created_at.isoformat() if r.created_at else "",
                }
                for r in rows
            ]
        finally:
            s.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail="history unavailable")


@router.get("/analyses/{analysis_id}", response_model=AnalysisResult)
def get_analysis(analysis_id: str):
    try:
        from app.database.db import get_session, Analysis, EvidenceRow, FindingRow, ProviderCheckRow
        from app.schemas.models import Evidence
        s = get_session()
        try:
            a = s.query(Analysis).filter(Analysis.id == analysis_id).first()
            if not a:
                raise HTTPException(status_code=404, detail="analysis not found")
            evs = s.query(EvidenceRow).filter(EvidenceRow.analysis_id == analysis_id).all()
            fins = s.query(FindingRow).filter(FindingRow.analysis_id == analysis_id).all()
            provs = s.query(ProviderCheckRow).filter(ProviderCheckRow.analysis_id == analysis_id).all()
            return AnalysisResult(analysisId=a.id, inputType=a.input_type, riskScore=a.risk_score,  # type: ignore[arg-type]
                                  riskLevel=a.risk_level, confidence=a.confidence,  # type: ignore[arg-type]
                                  findings=[f.description for f in fins] or ["Stored analysis"],
                                  evidence=[Evidence(id=e.id, category=e.category, title=e.title, description=e.description,
                                                     severity=e.severity, source=e.source, confidence=e.confidence) for e in evs],  # type: ignore[arg-type]
                                  recommendation=[], limitations=[], providerStatus={p.provider: p.status for p in provs})
        finally:
            s.close()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="lookup failed")
