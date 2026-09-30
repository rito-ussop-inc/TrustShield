"""Message text features (TRD §7)."""
from __future__ import annotations
import re

URGENCY_WORDS = ["urgent", "immediately", "act now", "right now", "asap", "hurry", "last chance", "expires", "deadline"]
THREAT_WORDS = ["blocked", "suspended", "suspend", "locked", "deactivated", "arrest", "legal action", "penalty", "will be blocked", "will be suspended"]
AUTHORITY_WORDS = ["bank", "reserve bank", "rbi", "police", "income tax", "customs", "government", "support team", "security team", "admin"]
CREDENTIAL_WORDS = ["password", "otp", "one-time", "one time", "pin", "cvv", "login", "sign in", "verify your account", "confirm your account", "credentials"]
PAYMENT_WORDS = ["payment", "pay now", "upi", "transfer", "refund", "invoice", "billing", "account number", "bank account"]
REWARD_WORDS = ["prize", "winner", "won", "lottery", "congratulations", "free gift", "cashback", "offer", "reward"]
CTA_WORDS = ["click", "tap", "open the link", "follow the link", "download", "install", "scan"]


def _has_any(text_lower: str, phrases: list[str]) -> bool:
    return any(p in text_lower for p in phrases)


def extract_message_features(text: str, urls: list[str]) -> dict:
    low = (text or "").lower()
    return {
        "length": len(text or ""),
        "urgency": _has_any(low, URGENCY_WORDS),
        "threat": _has_any(low, THREAT_WORDS),
        "authority": _has_any(low, AUTHORITY_WORDS),
        "credential_request": _has_any(low, CREDENTIAL_WORDS),
        "payment_request": _has_any(low, PAYMENT_WORDS),
        "reward": _has_any(low, REWARD_WORDS),
        "cta": _has_any(low, CTA_WORDS),
        "has_url": len(urls) > 0,
        "url_count": len(urls),
        # financial urgency combo
        "financial_urgency": (_has_any(low, PAYMENT_WORDS) and _has_any(low, URGENCY_WORDS + THREAT_WORDS)),
        # impersonation cue: authority claim + request
        "impersonation": (_has_any(low, AUTHORITY_WORDS) and (_has_any(low, CREDENTIAL_WORDS + PAYMENT_WORDS))),
    }
