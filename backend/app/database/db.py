"""Database — PostgreSQL via DATABASE_URL, SQLite fallback for local/demo."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine, String, Text, Float, Integer, DateTime, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    input_type: Mapped[str] = mapped_column(String(16))
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    input_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class EvidenceRow(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("analyses.id"))
    category: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("analyses.id"))
    code: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))


class ProviderCheckRow(Base):
    __tablename__ = "provider_checks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id: Mapped[str] = mapped_column(String(36), ForeignKey("analyses.id"))
    provider: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    matched: Mapped[bool] = mapped_column(default=False)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


def _connect_args(db_url: str) -> dict:
    if db_url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


def get_engine():
    settings = get_settings()
    url = settings.DATABASE_URL
    return create_engine(url, connect_args=_connect_args(url), pool_pre_ping=True)


_engine = None
_Session = None


def init_db():
    global _engine, _Session
    _engine = get_engine()
    Base.metadata.create_all(_engine)
    _Session = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def get_session():
    global _Session
    if _Session is None:
        init_db()
    assert _Session is not None
    return _Session()
