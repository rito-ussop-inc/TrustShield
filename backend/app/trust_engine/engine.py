"""Trust Engine — combines signals into explainable assessment (TRD §11, PRD §7 FR-9).
Retains individual signals; never reduces to an unexplained number.
Uses observed-risk language; provides plain-language explanations for everyday users.
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
    plain_summary: dict | None = None


class TrustEngine:
    def assess(
        self,
        signals: dict,
        evidence,
        *,
        ml_phishing_prob: float = 0.0,
        provider_status: dict[str, str] | None = None,
        context: str = "",
        target_info: dict | None = None,
    ) -> TrustAssessment:
        provider_status = provider_status or {}
        target_info = target_info or {}
        score = score_from_signals(signals, ml_phishing_prob=ml_phishing_prob)
        has_signals = bool(signals) or ml_phishing_prob > 0.15 or bool(evidence)

        # Check provider statuses
        any_unavailable = any(v == "unavailable" for v in provider_status.values())
        all_unconfirmed = all(v in ("unavailable", "not_configured") for v in provider_status.values()) if provider_status else True

        # Check if any threat signals fired
        no_local_hits = all(
            not (isinstance(v, (int, float)) and v) and v is not True and v != 1
            for v in signals.values()
        ) if signals else True

        # Findings extraction: include genuine structural observations & detected risk indicators
        findings: list[str] = []
        ti_matches = [prov for prov, st in provider_status.items() if st == "match"]
        if ti_matches:
            findings.append(f"Threat-intelligence match: confirmed threat reported by {', '.join(ti_matches)}")

        for ev in evidence or []:
            ev_id = getattr(ev, "id", "") or (ev.get("id", "") if isinstance(ev, dict) else "")
            ev_cat = getattr(ev, "category", "") or (ev.get("category", "") if isinstance(ev, dict) else "")
            # Skip provider availability/configuration noise from technical observations
            if ev_cat == "missing-unknown" and ("UNAVAIL" in ev_id or "NOCONFIG" in ev_id or "NOMATCH" in ev_id):
                continue
            if ev_cat == "threat-intelligence" and "NOMATCH" in ev_id:
                continue
            title = ev.title if hasattr(ev, "title") else (ev.get("title", "") if isinstance(ev, dict) else "")
            if title and title not in findings:
                findings.append(title)

        if not findings:
            if no_local_hits:
                findings.append("No suspicious structural indicators or heuristic anomalies observed")
            else:
                findings.append("Assessment based on observed structural indicators")

        # Determine level: enforce UNKNOWN when coverage is insufficient
        is_unknown = False
        if no_local_hits and score < 25:
            if all_unconfirmed or any_unavailable:
                is_unknown = True
            elif score == 0:
                is_unknown = False  # Low observed risk

        level = level_from_score(score, has_signals=has_signals, force_unknown=is_unknown)

        recommendations = self._recommendations(level, signals)
        limitations = self._limitations(provider_status, context, ml_phishing_prob)
        confidence = self._confidence(signals, provider_status, ml_phishing_prob)
        plain_summary = self._build_plain_summary(level, signals, provider_status, target_info, context)

        return TrustAssessment(
            risk_score=score,
            risk_level=level,
            confidence=confidence,
            findings=findings,
            recommendations=recommendations,
            limitations=limitations,
            scoring_version=SCORING_VERSION,
            plain_summary=plain_summary,
        )

    def _build_plain_summary(
        self,
        level: str,
        signals: dict,
        provider_status: dict[str, str],
        target_info: dict,
        context: str,
    ) -> dict:
        host = target_info.get("hostname", "")
        reg_domain = target_info.get("registrable_domain", host)
        is_https = target_info.get("is_https", True)
        host_kws = target_info.get("suspicious_keywords_host", [])
        is_ip = target_info.get("is_ip_host", False)
        ti_matches = [p for p, st in provider_status.items() if st == "match"]

        headline = "Security Assessment Summary"
        explanation = "This link was analyzed for deceptive characteristics and threat intelligence matches."
        action = "Verify the destination before entering personal information."
        badge = f"{level} RISK"
        notice = None

        if ti_matches:
            headline = "🚨 Confirmed Dangerous Link (Blacklisted)"
            explanation = f"This website has been verified as malicious by global security threat databases ({', '.join(ti_matches)}). It is actively linked to cyberattacks, fake logins, or malware distribution."
            action = "🛑 Do NOT click this link or download any files. Close this page immediately."
            badge = "CONFIRMED THREAT"
        elif level in ("HIGH", "CRITICAL"):
            if is_ip:
                headline = "🚨 Warning: Direct IP Number Connection"
                explanation = f"This link directs to a raw computer number address ({host}) instead of an official company website name. Legitimate services almost never use raw IP numbers for public websites."
                action = "🛑 Do not enter passwords or credit card numbers on this page."
                badge = "HIGH RISK"
            elif host_kws:
                kws_str = ", ".join(f"'{k}'" for k in host_kws[:3])
                headline = "⚠️ Warning: Potential Fake Website / Phishing Lure"
                explanation = f"This link uses recognizable brand/security words like {kws_str} in the address, but the real destination domain is '{reg_domain}'. Scammers create lookalike names to trick people into typing passwords or credit cards."
                action = "🛑 Do not log in or provide payment details on this page. If you need to access this account, navigate to the official website directly."
                badge = "DECEPTIVE LINK"
            else:
                headline = "⚠️ Warning: Multiple Suspicious Patterns Detected"
                explanation = "This link exhibits structural patterns commonly associated with credential harvesting and deceptive links (such as unencrypted data transfer, unusual ports, or deep subdomain nesting)."
                action = "🛑 Avoid entering personal information or following instructions on this page."
                badge = "HIGH RISK"
        elif level == "MEDIUM":
            if host_kws:
                kws_str = ", ".join(f"'{k}'" for k in host_kws[:3])
                headline = "⚠️ Caution: Misleading Domain Keywords"
                explanation = f"This link mentions {kws_str}, but is hosted on '{reg_domain}' rather than the official service website. This is frequently done on scam pages."
                action = "👉 Be cautious: verify who sent you this link before opening or entering any login details."
                badge = "SUSPICIOUS"
            else:
                headline = "⚠️ Caution: Unusual Link Characteristics"
                explanation = f"We noticed suspicious traits on this link (such as being hosted on '{reg_domain}' with unencrypted HTTP or nested redirects). While not yet blacklisted, it warrants caution."
                action = "👉 Do not log in if you received this link in an unexpected message or email."
                badge = "USE CAUTION"
        elif level == "LOW":
            headline = f"✅ Standard Link ({reg_domain})"
            explanation = f"This link connects to '{reg_domain}' over an encrypted connection (HTTPS). No deceptive brand lookalikes or threat intelligence blacklist flags were detected."
            action = "💡 Safe to browse normally: Make sure '{reg_domain}' is the website you intended to visit before entering passwords."
            badge = "LOW OBSERVED RISK"
        else:  # UNKNOWN
            headline = "❓ Unverified Link (Insufficient Evidence)"
            explanation = "This link could not be verified by threat intelligence databases or had an unusual structure. Because new scam websites appear daily, absence of a report does not guarantee safety."
            action = "👉 Only open this link if you personally know and trust the sender."
            badge = "UNVERIFIED"

        if not is_https and level in ("HIGH", "MEDIUM"):
            notice = "🔒 Insecure Connection: This link uses plain HTTP (no SSL encryption). Any password or card number typed on this page can be intercepted by others on the same network."

        return {
            "headline": headline,
            "explanation": explanation,
            "actionAdvice": action,
            "verdictBadge": badge,
            "targetIdentity": reg_domain,
            "securityNotice": notice,
        }

    def _recommendations(self, level: str, signals: dict) -> list[str]:
        recs: list[str] = []
        if level in ("HIGH", "CRITICAL"):
            recs.append("Do not enter credentials, passwords, or one-time passcodes (OTP) on this page.")
            recs.append("Do not submit financial or payment details.")
            recs.append("Verify the destination independently by navigating to the official website directly.")
        elif level == "MEDIUM":
            recs.append("Exercise caution — suspicious indicators detected.")
            recs.append("Verify domain spelling and SSL certificate details before interacting.")
            recs.append("If this link was received unexpectedly via email or message, do not authenticate.")
        elif level == "LOW":
            recs.append("Low observed risk — no suspicious indicators found.")
            recs.append("Follow standard safety hygiene: verify the domain matches your intended service.")
        else:  # UNKNOWN
            recs.append("Insufficient evidence to confirm safety. Treat link as unverified.")
            recs.append("Do not enter sensitive credentials until verified through a trusted independent channel.")

        if signals.get("credential_request") or signals.get("MSG_CREDENTIAL_REQUEST") or signals.get("URL_LOGIN_PATH"):
            if "Do not enter credentials, passwords, or one-time passcodes (OTP) on this page." not in recs:
                recs.append("Do not enter credentials unless you have confirmed the domain identity.")
        return recs

    def _limitations(self, provider_status: dict[str, str], context: str, ml_prob: float) -> list[str]:
        lims: list[str] = []
        for prov, status in (provider_status or {}).items():
            if status == "unavailable":
                lims.append(f"{prov}: live check unavailable — assessment relies on local analysis only.")
            elif status == "not_configured":
                lims.append(f"{prov}: provider not configured — no live lookup performed.")

        lims.append("No threat-intelligence 'no match' is treated as proof of safety. Newly registered threats may not yet be cataloged.")
        lims.append("Static URL analysis does not execute JavaScript, follow live redirects, or evaluate on-page payloads.")

        if ml_prob > 0:
            lims.append("Model classification is a statistical indicator derived from URL structure, not an absolute guarantee.")

        if context == "document":
            lims.append("Document check evaluates cryptographic file hash only — it does not verify issuer authenticity.")

        return lims

    def _confidence(self, signals: dict, provider_status: dict[str, str], ml_prob: float) -> float:
        corroborating = sum(1 for v in (signals or {}).values() if v)
        live_checked = sum(1 for v in (provider_status or {}).values() if v in ("no_match", "match"))
        base = 0.45 + 0.08 * min(corroborating, 4) + 0.05 * min(live_checked, 2)
        if ml_prob and ml_prob > 0.85:
            base += 0.05
        return round(min(0.95, max(0.35, base)), 2)
