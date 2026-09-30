"""Trust Engine — combines signals into explainable assessment (TRD §11, PRD §6).

Interface: TrustEngine.assess(signals, evidence) -> TrustAssessment
Retains individual signals; never reduces to unexplained number.
Uses observed-risk language; never claims 100% safety.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from app.scoring.engine import score_from_signals, level_from_score, SCORING_VERSION


@dataclass
class TrustAssessment:
    risk_score: int | None
    risk_level: str
    confidence: float | None
    findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    scoring_version: str = SCORING_VERSION


class TrustEngine:
    def assess(
        self,
        signals: dict,
        evidence,
        *,
        ml_phishing_prob: float = 0.0,
        provider_status: dict[str, str] | None = None,
        context: str = "",
    ) -> TrustAssessment:
        provider_status = provider_status or {}
        score = score_from_signals(signals, ml_phishing_prob=ml_phishing_prob)
        has_signals = bool(signals) or ml_phishing_prob > 0 or bool(evidence)

        # Unknown handling: no threat match != safe (TRD rule 9)
        any_unavailable = any(v == "unavailable" for v in provider_status.values())
        no_hits = all(
            not (isinstance(v, (int, float)) and v) and v is not True and v != 1
            for v in signals.values()
        ) if signals else True

        findings: list[str] = []
        for ev in evidence or []:
            # evidence may be pydantic or dict
            title = ev.title if hasattr(ev, "title") else ev.get("title", "")
            if title and title not in findings:
                findings.append(title)

        if not findings:
            if no_hits:
                findings.append("No high-confidence threat signals observed — treat as unknown/observed risk, not confirmed safe")
            else:
                findings.append("Assessment based on combined local signals")

        # Threat intel match escalates
        if signals.get("threat_intelligence_match"):
            findings.insert(0, "Threat-intelligence match for known malicious indicator")

        level = level_from_score(score, has_signals=True)
        # If genuinely no signals and providers unavailable -> UNKNOWN
        if no_hits and score < 25:
            if any_unavailable or score == 0:
                # Keep LOW only if several providers confirmed no-match; else UNKNOWN/LOW boundary
                matched_none = all(v in ("no_match", "unavailable", "not_configured") for v in provider_status.values()) if provider_status else True
                if matched_none and score == 0:
                    level = "UNKNOWN" if any_unavailable else "LOW"
                elif score == 0:
                    level = "LOW"

        recommendations = self._recommendations(level, signals)
        limitations = self._limitations(provider_status, context, ml_phishing_prob)
        confidence = self._confidence(signals, provider_status, ml_phishing_prob)

        return TrustAssessment(
            risk_score=score,
            risk_level=level,
            confidence=confidence,
            findings=findings,
            recommendations=recommendations,
            limitations=limitations,
        )

    def _recommendations(self, level: str, signals: dict) -> list[str]:
        recs: list[str] = []
        if level in ("HIGH", "CRITICAL"):
            recs.append("Do not enter credentials or one-time passcodes via this link/message")
            recs.append("Do not make a payment or share financial details")
            recs.append("Verify through an independent official channel (type the official site yourself or call a published number)")
        elif level == "MEDIUM":
            recs.append("Potentially suspicious — pause before clicking or replying")
            recs.append("Verify the sender and destination through an independent official channel")
        elif level == "LOW":
            recs.append("Low observed risk — still follow normal caution (check sender, avoid unexpected downloads)")
        else:  # UNKNOWN
            recs.append("Unknown risk — could not confirm safety; verify independently before trusting")
            recs.append("Avoid entering credentials until verified through an official channel")
        if signals.get("credential_request") or signals.get("MSG_CREDENTIAL_REQUEST"):
            if "Do not enter credentials or one-time passcodes via this link/message" not in recs:
                recs.append("Do not enter credentials or one-time passcodes via this link/message")
        return recs

    def _limitations(self, provider_status, context, ml_prob) -> list[str]:
        lims: list[str] = []
        for prov, status in (provider_status or {}).items():
            if status == "unavailable":
                lims.append(f"{prov}: live check unavailable — assessment relies on local signals only")
            elif status == "not_configured":
                lims.append(f"{prov}: not configured — no live signal from this provider")
        lims.append("No threat-intelligence 'no match' is treated as confirmed safe — unknown inputs remain unknown/observed risk")
        if ml_prob:
            lims.append("ML prediction is a supporting signal only, not proof of fraud or legitimacy")
        if context == "document":
            lims.append("Document check covers file integrity (hash/metadata) only — it does not prove issuer authenticity")
        if not lims:
            lims.append("Analysis is point-in-time and based on currently available signals")
        return lims

    def _confidence(self, signals, provider_status, ml_prob) -> float:
        # Simple transparent confidence: more corroborating signals -> higher
        n = sum(1 for v in (signals or {}).values() if v)
        live_ok = sum(1 for v in (provider_status or {}).values() if v in ("no_match", "match"))
        base = 0.4 + 0.1 * min(n, 4) + 0.05 * min(live_ok, 2)
        if ml_prob and ml_prob > 0.8:
            base += 0.05
        return round(min(0.95, max(0.35, base)), 2)
