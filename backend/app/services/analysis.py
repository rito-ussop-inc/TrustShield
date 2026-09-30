"""Orchestration: analyzers -> threat intel -> Trust Engine -> persistence.
Keeps analyzers independent; scoring separate; evidence separate.
TRD §4, §5, §6, PRD §6, §7.
"""
from __future__ import annotations
import hashlib
import uuid
from datetime import datetime, timezone

from app.analyzers.url.normalization import normalize_url, normalize_url_details
from app.analyzers.url.validation import validate_url, validate_url_detailed
from app.analyzers.url.features import extract_url_features
from app.analyzers.url.rules import apply_url_rules
from app.analyzers.message.normalize import normalize_message, extract_urls
from app.analyzers.message.features import extract_message_features
from app.analyzers.message.rules import apply_message_rules
from app.analyzers.qr.decoder import decode_qr_bytes, classify_payload
from app.analyzers.document.validator import validate_document, sha256_bytes, build_metadata
from app.ml.message_classifier import classify_message
from app.ml.url_ml import url_ml_probability, get_url_ml_info, URL_ML_VERSION
from app.threat_intel.manager import check_all
from app.trust_engine.engine import TrustEngine
from app.evidence.models import make_evidence
from app.schemas.models import AnalysisResult, ProviderCheckDetail

trust_engine = TrustEngine()


def _persist(analysis_id: str, input_type: str, assessment, evidence, provider_results, model_version: str, input_hash: str, input_summary: str | None = None):
    try:
        from app.database.db import get_session, Analysis, EvidenceRow, FindingRow, ProviderCheckRow
        s = get_session()
        try:
            s.add(Analysis(id=analysis_id, input_type=input_type, risk_score=assessment.risk_score,
                           risk_level=assessment.risk_level, confidence=assessment.confidence,
                           model_version=model_version, input_hash=input_hash,
                           input_summary=input_summary[:250] if input_summary else None))
            for ev in evidence:
                s.add(EvidenceRow(analysis_id=analysis_id, category=ev.category if hasattr(ev, "category") else ev["category"],
                                  title=ev.title if hasattr(ev, "title") else ev["title"],
                                  description=ev.description if hasattr(ev, "description") else ev["description"],
                                  severity=ev.severity if hasattr(ev, "severity") else ev["severity"],
                                  source=ev.source if hasattr(ev, "source") else ev.get("source"),
                                  confidence=ev.confidence if hasattr(ev, "confidence") else ev.get("confidence")))
            for i, f in enumerate(assessment.findings):
                s.add(FindingRow(analysis_id=analysis_id, code=f"F{i+1}", description=f, severity="INFO"))
            for r in provider_results or []:
                s.add(ProviderCheckRow(analysis_id=analysis_id, provider=r.provider, status=r.status, matched=r.matched, category=r.category))
            s.commit()
        finally:
            s.close()
    except Exception:
        # DB failure must never break analysis
        pass


def _input_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


async def analyze_url(raw_url: str, providers) -> AnalysisResult:
    analysis_id = str(uuid.uuid4())
    norm_details = normalize_url_details(raw_url)
    val_res = validate_url_detailed(raw_url, allow_schemeless=True)

    evidence: list = []
    signals: dict = {}
    provider_status: dict[str, str] = {}
    provider_results = []
    provider_details: list[ProviderCheckDetail] = []
    ml_info = get_url_ml_info()

    # Retain normalization warnings
    all_warnings = list(dict.fromkeys(norm_details.warnings + val_res.warnings))

    if not val_res.is_valid:
        evidence.append(make_evidence(
            id="URL_INVALID", category="url-heuristic", title="Invalid URL",
            description=f"URL validation failed: {val_res.reason}", severity="INFO", source="url-validation"
        ))
        assessment = trust_engine.assess({}, evidence, provider_status={}, context="url")
        return AnalysisResult(
            analysisId=analysis_id, inputType="URL", riskScore=assessment.risk_score,
            riskLevel="UNKNOWN", confidence=assessment.confidence, findings=assessment.findings,
            evidence=evidence, recommendation=assessment.recommendations,
            limitations=["Could not validate URL — input format invalid; no safety determination possible"] + assessment.limitations,
            providerStatus={},
            rawUrl=raw_url,
            normalizedUrl=norm_details.normalized_url or raw_url,
            normalizationWarnings=all_warnings,
            modelStatus="unavailable",
            modelVersion=ml_info["version"],
            scoringVersion=assessment.scoring_version,
            providerResults=[],
        )

    # Add evidence for normalization transformations if present
    if norm_details.scheme_inferred:
        evidence.append(make_evidence(
            id="URL_SCHEME_INFERRED", category="url-normalization",
            title="URL scheme inferred as https://",
            description="Input lacked a scheme prefix; default https:// scheme was applied for analysis.",
            severity="INFO", source="url-normalization"
        ))
    if norm_details.original_userinfo:
        evidence.append(make_evidence(
            id="URL_USERINFO_EXTRACTED", category="url-normalization",
            title="Userinfo credentials extracted from authority",
            description="URL contained userinfo before '@' in the authority component. Sanitized for external lookups.",
            severity="INFO", source="url-normalization"
        ))

    # Feature extraction & deterministic rules
    features = extract_url_features(norm_details.normalized_url)
    features["raw_url"] = raw_url
    features["normalized_url"] = norm_details.normalized_url

    ev, sig = apply_url_rules(features)
    evidence.extend(ev)
    signals.update(sig)

    # Trained model inference
    ml_prob = url_ml_probability(norm_details.normalized_url)
    if ml_info["is_trained_model"]:
        if ml_prob >= 0.35:
            severity = "HIGH" if ml_prob >= 0.70 else "MEDIUM" if ml_prob >= 0.50 else "LOW"
            evidence.append(make_evidence(
                id="URL_TRAINED_MODEL",
                category="ml-prediction",
                title=f"URL trained model: suspicious likelihood {ml_prob:.2f}",
                description=f"Trained tabular model ({ml_info['version']}) estimates {ml_prob:.1%} probability of malicious structure. Independent supporting signal.",
                severity=severity,
                source="url-classifier",
                confidence=ml_prob,
            ))
    else:
        evidence.append(make_evidence(
            id="URL_MODEL_UNAVAILABLE",
            category="missing-unknown",
            title="URL trained model unavailable",
            description=f"Model artifact not loaded ({ml_info.get('error') or 'missing'}). Proceeding with deterministic rules and threat intel.",
            severity="INFO",
            source="url-classifier",
        ))

    # Threat Intelligence querying
    provider_results = await check_all(providers, norm_details.normalized_url)
    provider_status = {r.provider: r.status for r in provider_results}
    for r in provider_results:
        provider_details.append(ProviderCheckDetail(
            provider=r.provider,
            status=r.status,
            matched=r.matched,
            category=r.category,
            detail=r.detail,
            checkedAt=getattr(r, "checked_at", None),
        ))
        if r.status == "match":
            evidence.append(make_evidence(
                id=f"TI_{r.provider.upper()}_MATCH", category="threat-intelligence",
                title=f"Threat-intelligence match ({r.provider})",
                description=f"{r.provider} flags this URL ({r.category or 'malicious'}). {r.detail or ''}".strip(),
                severity="HIGH", source=r.provider, confidence=0.95
            ))
            signals["threat_intelligence_match"] = 1.0
        elif r.status == "unavailable":
            evidence.append(make_evidence(
                id=f"TI_{r.provider.upper()}_UNAVAIL", category="missing-unknown",
                title=f"Threat-intel unavailable ({r.provider})",
                description=f"Live check failed ({r.detail or 'provider failure'}). Local analysis continues.",
                severity="INFO", source=r.provider
            ))
        elif r.status == "not_configured":
            evidence.append(make_evidence(
                id=f"TI_{r.provider.upper()}_NOCONFIG", category="missing-unknown",
                title=f"Provider not configured ({r.provider})",
                description="No API key configured; no live lookup available from this provider.",
                severity="INFO", source=r.provider
            ))
        else:
            evidence.append(make_evidence(
                id=f"TI_{r.provider.upper()}_NOMATCH", category="threat-intelligence",
                title=f"No match in {r.provider}",
                description="Provider did not list this URL. This is NOT proof of safety.",
                severity="INFO", source=r.provider
            ))

    target_info = {
        "raw_url": raw_url,
        "normalized_url": norm_details.normalized_url,
        "hostname": features.get("hostname", ""),
        "registrable_domain": features.get("registrable_domain", ""),
        "is_https": features.get("is_https", True),
        "suspicious_keywords_host": features.get("suspicious_keywords_host", []),
        "is_ip_host": features.get("is_ip_host", False),
    }
    assessment = trust_engine.assess(
        signals, evidence, ml_phishing_prob=ml_prob, provider_status=provider_status, context="url", target_info=target_info
    )
    _persist(analysis_id, "URL", assessment, evidence, provider_results, ml_info["version"], _input_hash(norm_details.normalized_url), input_summary=raw_url)

    return AnalysisResult(
        analysisId=analysis_id,
        inputType="URL",
        riskScore=assessment.risk_score,
        riskLevel=assessment.risk_level,  # type: ignore[arg-type]
        confidence=assessment.confidence,
        findings=assessment.findings,
        evidence=evidence,
        recommendation=assessment.recommendations,
        limitations=assessment.limitations,
        providerStatus=provider_status,
        rawUrl=raw_url,
        normalizedUrl=norm_details.normalized_url,
        normalizationWarnings=all_warnings,
        modelStatus=ml_info["status"],
        modelVersion=ml_info["version"],
        scoringVersion=assessment.scoring_version,
        providerResults=provider_details,
        plainSummary=assessment.plain_summary,
    )


async def analyze_message(text: str, providers) -> AnalysisResult:
    analysis_id = str(uuid.uuid4())
    norm = normalize_message(text)
    if not norm:
        ev = [make_evidence(id="MSG_EMPTY", category="message-language", title="Empty message", description="No text to analyze.", severity="INFO", source="message-rules")]
        a = trust_engine.assess({}, ev, context="message")
        return AnalysisResult(analysisId=analysis_id, inputType="MESSAGE", riskScore=a.risk_score, riskLevel="UNKNOWN",
                              confidence=a.confidence, findings=a.findings, evidence=ev, recommendation=a.recommendations,
                              limitations=a.limitations, providerStatus={})
    urls = extract_urls(norm)
    feats = extract_message_features(norm, urls)
    evidence, signals = apply_message_rules(feats)
    ml = classify_message(norm)
    ml_prob = float(ml.get("phishing_prob", 0.0))
    ml_label = ml.get("label", "UNKNOWN")
    ml_version = ml.get("version", "unknown")
    evidence.append(make_evidence(id="MSG_ML", category="ml-prediction",
                                  title=f"Message ML classifier: {ml_label} (suspicious {ml_prob:.2f})",
                                  description=f"TF-IDF + LogisticRegression baseline ({ml_version}). Supporting signal only, not proof.",
                                  severity="MEDIUM" if ml_prob >= 0.5 else "LOW", source="message-ml", confidence=ml_prob))

    # Analyze extracted URLs
    provider_status: dict[str, str] = {}
    provider_results = []
    provider_details: list[ProviderCheckDetail] = []
    for u in urls[:3]:
        norm_u = normalize_url(u)
        ok, _ = validate_url(norm_u)
        if not ok:
            continue
        f = extract_url_features(norm_u)
        uev, usig = apply_url_rules(f)
        for e in uev:
            e.description = f"[from link {f['hostname']}] " + e.description
            evidence.append(e)
        for k, v in usig.items():
            signals[k] = max(float(signals.get(k, 0)), float(v))
        uprob = url_ml_probability(norm_u)
        ml_prob = max(ml_prob, uprob * 0.8)

        # threat intel per extracted URL
        pres = await check_all(providers, norm_u)
        provider_results.extend(pres)
        for r in pres:
            provider_status[r.provider] = r.status
            provider_details.append(ProviderCheckDetail(
                provider=r.provider,
                status=r.status,
                matched=r.matched,
                category=r.category,
                detail=r.detail,
                checkedAt=getattr(r, "checked_at", None),
            ))
            if r.status == "match":
                evidence.append(make_evidence(
                    id=f"TI_{r.provider.upper()}_MATCH_MSGURL", category="threat-intelligence",
                    title=f"Threat-intel match for link ({r.provider})",
                    description=f"Extracted link flagged by {r.provider}.", severity="HIGH", source=r.provider, confidence=0.95
                ))
                signals["threat_intelligence_match"] = 1.0

    assessment = trust_engine.assess(signals, evidence, ml_phishing_prob=ml_prob, provider_status=provider_status, context="message")
    _persist(analysis_id, "MESSAGE", assessment, evidence, provider_results, str(ml_version), _input_hash(norm), input_summary=norm[:120])
    return AnalysisResult(
        analysisId=analysis_id, inputType="MESSAGE", riskScore=assessment.risk_score,
        riskLevel=assessment.risk_level, confidence=assessment.confidence,  # type: ignore[arg-type]
        findings=assessment.findings, evidence=evidence, recommendation=assessment.recommendations,
        limitations=assessment.limitations, providerStatus=provider_status,
        modelStatus="available", modelVersion=str(ml_version), scoringVersion=assessment.scoring_version,
        providerResults=provider_details, plainSummary=assessment.plain_summary,
    )


async def analyze_qr(data: bytes, filename: str, providers) -> AnalysisResult:
    analysis_id = str(uuid.uuid4())
    payload, err = decode_qr_bytes(data)
    if err or not payload:
        ev = [make_evidence(id="QR_DECODE_FAIL", category="verification", title="QR decoding failed",
                            description=err or "No payload recovered.", severity="INFO", source="qr-decoder")]
        a = trust_engine.assess({}, ev, context="qr")
        return AnalysisResult(analysisId=analysis_id, inputType="QR", riskScore=a.risk_score, riskLevel="UNKNOWN",
                              confidence=a.confidence, findings=a.findings, evidence=ev, recommendation=a.recommendations,
                              limitations=["QR image could not be decoded — no safety claim possible"] + a.limitations,
                              providerStatus={}, plainSummary=a.plain_summary)
    ptype = classify_payload(payload)
    if ptype == "URL":
        sub = await analyze_url(payload, providers)
        return AnalysisResult(
            analysisId=analysis_id, inputType="QR", riskScore=sub.riskScore, riskLevel=sub.riskLevel,
            confidence=sub.confidence, findings=[f"QR payload is a URL: {payload[:120]}"] + sub.findings,
            evidence=sub.evidence, recommendation=sub.recommendation, limitations=sub.limitations,
            providerStatus=sub.providerStatus, decodedPayload=payload, payloadType=ptype,
            rawUrl=sub.rawUrl, normalizedUrl=sub.normalizedUrl, normalizationWarnings=sub.normalizationWarnings,
            modelStatus=sub.modelStatus, modelVersion=sub.modelVersion, scoringVersion=sub.scoringVersion,
            providerResults=sub.providerResults, plainSummary=sub.plainSummary,
        )
    elif ptype in ("TEXT", "EMAIL"):
        sub = await analyze_message(payload, providers)
        return AnalysisResult(
            analysisId=analysis_id, inputType="QR", riskScore=sub.riskScore, riskLevel=sub.riskLevel,
            confidence=sub.confidence, findings=[f"QR payload is {ptype}: {payload[:160]}"] + sub.findings,
            evidence=sub.evidence, recommendation=sub.recommendation, limitations=sub.limitations,
            providerStatus=sub.providerStatus, decodedPayload=payload, payloadType=ptype,
            modelStatus=sub.modelStatus, modelVersion=sub.modelVersion, scoringVersion=sub.scoringVersion,
            providerResults=sub.providerResults, plainSummary=sub.plainSummary,
        )
    else:
        ev = [make_evidence(id="QR_OTHER", category="verification", title=f"QR payload type: {ptype}",
                            description=f"Decoded payload: {payload[:300]}. No URL/text analyzer applies; treat as unknown.",
                            severity="INFO", source="qr-decoder")]
        a = trust_engine.assess({}, ev, context="qr")
        return AnalysisResult(
            analysisId=analysis_id, inputType="QR", riskScore=a.risk_score, riskLevel="UNKNOWN",
            confidence=a.confidence, findings=a.findings, evidence=ev, recommendation=a.recommendations,
            limitations=a.limitations, providerStatus={}, decodedPayload=payload, payloadType=ptype,
            scoringVersion=a.scoring_version, plainSummary=a.plain_summary,
        )


async def analyze_document(data: bytes, filename: str, content_type: str | None, reference_sha256: str | None, max_mb: int) -> AnalysisResult:
    analysis_id = str(uuid.uuid4())
    ok, reason = validate_document(filename, content_type, len(data), max_mb)
    if not ok:
        ev = [make_evidence(id="DOC_INVALID", category="cryptographic-integrity", title="File validation failed",
                            description=reason, severity="INFO", source="document-validator")]
        a = trust_engine.assess({}, ev, context="document")
        return AnalysisResult(analysisId=analysis_id, inputType="DOCUMENT", riskScore=a.risk_score, riskLevel="UNKNOWN",
                              confidence=a.confidence, findings=a.findings, evidence=ev, recommendation=a.recommendations,
                              limitations=a.limitations, providerStatus={}, plainSummary=a.plain_summary)
    digest = sha256_bytes(data)
    meta = build_metadata(filename, len(data), content_type, digest)
    evidence = [make_evidence(id="DOC_HASH", category="cryptographic-integrity",
                              title=f"SHA-256: {digest[:16]}…",
                              description=f"Computed SHA-256 {digest} for '{meta['filename']}' ({meta['size_bytes']} bytes, {meta['content_type']}).",
                              severity="INFO", source="document-hasher", confidence=1.0)]
    signals: dict = {}
    if reference_sha256:
        ref = reference_sha256.strip().lower()
        if ref == digest.lower():
            evidence.append(make_evidence(id="DOC_MATCH", category="cryptographic-integrity",
                                          title="Integrity match: file matches reference hash",
                                          description="Hash equals the supplied reference. This confirms integrity only — NOT issuer authenticity.",
                                          severity="INFO", source="document-comparison", confidence=1.0))
        else:
            evidence.append(make_evidence(id="DOC_MISMATCH", category="cryptographic-integrity",
                                          title="Integrity mismatch: file differs from reference",
                                          description="Hash does NOT match the supplied reference — file may be modified or a different file.",
                                          severity="HIGH", source="document-comparison", confidence=0.95))
            signals["DOC_INTEGRITY_MISMATCH"] = 1.0
    else:
        evidence.append(make_evidence(id="DOC_NOREF", category="missing-unknown",
                                      title="No reference hash supplied",
                                      description="Without a trusted reference hash, integrity cannot be confirmed — hash recorded for future comparison.",
                                      severity="INFO", source="document-comparison"))
        signals["DOC_NO_REFERENCE"] = 1.0
    a = trust_engine.assess(signals, evidence, context="document")
    _persist(analysis_id, "DOCUMENT", a, evidence, [], "sha256-v1", digest, input_summary=filename)
    return AnalysisResult(analysisId=analysis_id, inputType="DOCUMENT", riskScore=a.risk_score,
                          riskLevel=a.risk_level, confidence=a.confidence,  # type: ignore[arg-type]
                          findings=a.findings, evidence=evidence, recommendation=a.recommendations,
                          limitations=a.limitations, providerStatus={}, fileSha256=digest,
                          scoringVersion=a.scoring_version, plainSummary=a.plain_summary)
