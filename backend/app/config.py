"""Central configuration via environment variables (TRD §19)."""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "TrustShield"
    APP_ENV: str = "development"
    DATABASE_URL: str = "sqlite:///./trustshield.db"
    PHISHTANK_API_KEY: str = ""
    URLHAUS_API_KEY: str = ""
    WEBRISK_API_KEY: str = ""
    MODEL_PATH: str = "ml/artifacts/message_classifier.joblib"
    MODEL_VERSION: str = "msg-tfidf-lr-v1.0.0"
    SCORING_VERSION: str = "scoring-v1.0.0"
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"
    MAX_UPLOAD_MB: int = 10
    REQUEST_TIMEOUT_SECONDS: int = 5
    RATE_LIMIT_PER_MINUTE: int = 60


@lru_cache
def get_settings() -> Settings:
    return Settings()
