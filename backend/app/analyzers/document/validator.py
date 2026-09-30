"""Document integrity: validation, SHA-256, metadata, reference comparison."""
from __future__ import annotations
import hashlib
import mimetypes
from pathlib import Path

ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".csv", ".docx", ".zip"}
ALLOWED_MIME_PREFIX = ("application/pdf", "image/", "text/", "application/zip", "application/vnd.openxmlformats")


def validate_document(filename: str, content_type: str | None, size: int, max_mb: int) -> tuple[bool, str]:
    if size > max_mb * 1024 * 1024:
        return False, f"File exceeds {max_mb} MB limit"
    if size == 0:
        return False, "File is empty"
    ext = Path(filename or "").suffix.lower()
    if ext and ext not in ALLOWED_EXTENSIONS:
        return False, f"File type '{ext}' not supported for MVP integrity check"
    # MIME check (best-effort)
    if content_type:
        ct = content_type.split(";")[0].strip().lower()
        if not (ct.startswith(ALLOWED_MIME_PREFIX) or ct == "application/octet-stream"):
            return False, f"MIME type '{ct}' not allowed"
    return True, "ok"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_metadata(filename: str, size: int, content_type: str | None, digest: str) -> dict:
    return {
        "filename": filename,
        "size_bytes": size,
        "content_type": content_type or mimetypes.guess_type(filename or "")[0] or "unknown",
        "sha256": digest,
    }
