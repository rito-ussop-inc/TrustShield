"""Message normalization + URL extraction."""
from __future__ import annotations
import re

URL_RE = re.compile(r"(https?://[^\s<>'\"]+|www\.[^\s<>'\"]+)", re.IGNORECASE)


def normalize_message(text: str) -> str:
    t = (text or "").strip()
    # collapse whitespace, keep case for display but analysis lowercases as needed
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t[:10000]


def extract_urls(text: str) -> list[str]:
    found: list[str] = []
    for m in URL_RE.finditer(text or ""):
        u = m.group(1).rstrip(".,;:!?)]}")
        if u.lower().startswith("www."):
            u = "https://" + u
        if u not in found:
            found.append(u)
    return found[:10]
