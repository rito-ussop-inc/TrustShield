"""Message rules -> Evidence."""
from __future__ import annotations
from app.evidence.models import make_evidence


def apply_message_rules(features: dict) -> tuple[list, dict]:
    evidence = []
    signals: dict[str, float] = {}

    def add(rid, title, desc, sev, skey=None, conf=None):
        evidence.append(make_evidence(id=rid, category="message-language", title=title, description=desc, severity=sev, source="message-rules", confidence=conf))
        if skey:
            signals[skey] = 1.0

    if features.get("urgency"):
        add("MSG_URGENCY", "Urgency / time-pressure language detected",
            "Messages that pressure quick action ('urgent', 'immediately', 'last chance') are a classic social-engineering tactic.", "MEDIUM", "MSG_URGENCY", 0.6)
        signals["urgency"] = 1.0
    if features.get("threat"):
        add("MSG_THREAT", "Threat of suspension / blocking / legal action",
            "Fear-based threats ('account will be blocked/suspended') push victims to act without verifying.", "MEDIUM", "MSG_THREAT", 0.65)
        signals["urgency"] = 1.0
    if features.get("authority"):
        add("MSG_AUTHORITY", "Authority / brand impersonation cues",
            "Message claims to be from a bank, government body or support team — verify via official channels.", "MEDIUM", "MSG_AUTHORITY", 0.55)
    if features.get("credential_request"):
        add("MSG_CREDENTIAL_REQUEST", "Credential / OTP / verification request",
            "Requests for passwords, OTPs or 'verify your account' are high-risk credential-theft indicators.", "HIGH", "MSG_CREDENTIAL_REQUEST", 0.8)
        signals["credential_request"] = 1.0
    if features.get("payment_request"):
        add("MSG_PAYMENT_REQUEST", "Payment / transfer / refund request",
            "Requests to pay, transfer funds or share bank details require independent verification.", "HIGH", "MSG_PAYMENT_REQUEST", 0.75)
    if features.get("reward"):
        add("MSG_REWARD", "Reward / prize / lottery language",
            "Unsolicited prizes, lottery wins and 'free gifts' are common bait.", "LOW", "MSG_REWARD", 0.5)
    if features.get("cta"):
        add("MSG_CTA", "Suspicious call-to-action (click/download/install)",
            "Urges clicking a link or installing something — inspect the destination before acting.", "LOW", "MSG_CTA", 0.5)
    if features.get("has_url"):
        add("MSG_URL_PRESENT", f"Message contains {features.get('url_count', 1)} link(s)",
            "Embedded links were extracted and analyzed separately; combined evidence drives the final score.", "INFO", "MSG_URL_PRESENT", 0.4)
    if features.get("impersonation"):
        add("MSG_IMPERSONATION", "Possible impersonation: authority claim + sensitive request",
            "Combination of trusted-brand claim with credential/payment request is a strong phishing pattern.", "HIGH", "MSG_AUTHORITY", 0.7)
        signals["domain_mismatch"] = 0.5
    if features.get("financial_urgency"):
        signals["urgency"] = 1.0

    return evidence, signals
