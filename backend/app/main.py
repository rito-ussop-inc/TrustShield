"""TrustShield FastAPI app — CORS restricted, rate-limited, structured errors."""
from __future__ import annotations
import time
import uuid
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.api.routes.analyze import router as analyze_router
from app.database.db import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("trustshield")

settings = get_settings()
limiter = Limiter(key_func=get_remote_address, default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"])

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        init_db()
        log.info("database initialized")
    except Exception as e:
        log.warning(f"db init failed: {e}")
    # ensure ML artifact exists (best-effort)
    try:
        from pathlib import Path
        from app.ml.message_classifier import train_and_save
        art = Path("ml/artifacts/message_classifier.joblib")
        if not art.exists():
            try:
                train_and_save(art)
                log.info("trained message classifier artifact")
            except Exception as e:
                log.warning(f"ml train skipped: {e}")
    except Exception as e:
        log.warning(f"ml init skipped: {e}")
    yield


app = FastAPI(title="TrustShield API", version="1.0.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, lambda req, exc: JSONResponse(status_code=429, content={"detail": "Rate limit exceeded, try again shortly"}))

origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    rid = str(uuid.uuid4())[:8]
    start = time.time()
    try:
        resp = await call_next(request)
        dur = round((time.time() - start) * 1000)
        log.info(f"rid={rid} endpoint={request.url.path} status={resp.status_code} dur_ms={dur}")
        resp.headers["X-Request-ID"] = rid
        return resp
    except Exception as e:
        log.error(f"rid={rid} endpoint={request.url.path} error={type(e).__name__}")
        return JSONResponse(status_code=500, content={"detail": "Internal error"})


@app.get("/health")
def health():
    return {"status": "ok", "service": "trustshield", "scoring_version": settings.SCORING_VERSION, "model_version": settings.MODEL_VERSION}


@app.get("/api/v1/providers/status")
def providers_status():
    s = get_settings()
    return {
        "phishtank": "configured" if s.PHISHTANK_API_KEY else "not_configured",
        "urlhaus": "configured" if s.URLHAUS_API_KEY else "available_without_key",
        "webrisk": "configured" if s.WEBRISK_API_KEY else "not_configured",
    }


app.include_router(analyze_router)
