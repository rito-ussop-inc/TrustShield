"""QR decoding via OpenCV (no system zbar dependency)."""
from __future__ import annotations
import io
from PIL import Image
import numpy as np


def decode_qr_bytes(data: bytes) -> tuple[str | None, str | None]:
    """Returns (payload, error)."""
    try:
        img = Image.open(io.BytesIO(data)).convert("RGB")
    except Exception:
        return None, "Could not open image — unsupported or corrupt file"
    try:
        import cv2
        arr = np.array(img)
        detector = cv2.QRCodeDetector()
        payload, points, _ = detector.detectAndDecode(arr)
        if payload:
            return payload, None
        # try multi
        try:
            ok, decoded, _, _ = detector.detectAndDecodeMulti(arr)
            if ok and decoded:
                for d in decoded:
                    if d:
                        return d, None
        except Exception:
            pass
        return None, "No QR code detected in image"
    except Exception as e:
        return None, f"QR decoder failure: {type(e).__name__}"


def classify_payload(payload: str) -> str:
    p = (payload or "").strip()
    low = p.lower()
    if low.startswith(("http://", "https://", "www.")):
        return "URL"
    if low.startswith("mailto:") or ("@" in p and "://" not in p and len(p) < 320 and " " not in p):
        # simple email heuristic
        if "@" in p and "." in p.split("@")[-1]:
            return "EMAIL"
    if low.startswith(("smsto:", "sms:", "tel:", "wifi:", "upi:", "bitcoin:")):
        return "OTHER"
    # loose URL without scheme
    if "." in p and " " not in p and len(p) < 2048 and p.count(".") >= 1:
        # could be bare domain — treat as URL if plausible
        if low.startswith("www.") or any(tld in low for tld in [".com", ".in", ".org", ".net", ".io", ".co"]):
            return "URL"
    if len(p) == 0:
        return "OTHER"
    return "TEXT"
