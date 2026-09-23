"""
models.py
ORM models: Candidate (with lifecycle fields + Phase 3/4 enrichment signals),
CandidateEvent (audit trail), and Webhook (Phase 5: registered alert endpoints).
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base

STATUSES = ("new", "under_investigation", "takedown_requested", "resolved", "false_positive")


def utcnow():
    return datetime.now(timezone.utc)


class Candidate(Base):
    __tablename__ = "candidates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    decoded_domain: Mapped[Optional[str]] = mapped_column(String(255))
    matched_brand: Mapped[str] = mapped_column(String(255), index=True)
    detected_at: Mapped[str] = mapped_column(String(40), default=lambda: utcnow().isoformat(), index=True)

    is_live: Mapped[Optional[bool]] = mapped_column(Boolean)
    visual_similarity: Mapped[Optional[float]] = mapped_column(Float)
    has_login_form: Mapped[Optional[bool]] = mapped_column(Boolean)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, index=True)
    risk_level: Mapped[Optional[str]] = mapped_column(String(10), index=True)
    screenshot_path: Mapped[Optional[str]] = mapped_column(String(500))

    # Phase 4: SSIM visual detection
    ssim_similarity: Mapped[Optional[float]] = mapped_column(Float)
    combined_similarity: Mapped[Optional[float]] = mapped_column(Float)

    # Phase 3: extended enrichment signals
    has_mx: Mapped[Optional[bool]] = mapped_column(Boolean)
    has_spf: Mapped[Optional[bool]] = mapped_column(Boolean)
    has_dmarc: Mapped[Optional[bool]] = mapped_column(Boolean)
    ssl_issuer: Mapped[Optional[str]] = mapped_column(String(255))
    ssl_san_count: Mapped[Optional[int]] = mapped_column(Integer)
    ssl_validity_days: Mapped[Optional[int]] = mapped_column(Integer)
    ssl_is_free_or_short_lived: Mapped[Optional[bool]] = mapped_column(Boolean)
    favicon_hash: Mapped[Optional[str]] = mapped_column(String(50))

    # Lifecycle
    status: Mapped[str] = mapped_column(String(30), default="new", index=True)
    analyst_notes: Mapped[Optional[str]] = mapped_column(Text)
    status_changed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    events: Mapped[list["CandidateEvent"]] = relationship(
        back_populates="candidate", cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class CandidateEvent(Base):
    """One row per status change or analyst note = audit trail."""
    __tablename__ = "candidate_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    candidate_id: Mapped[int] = mapped_column(ForeignKey("candidates.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(30))       # status_change | note
    old_value: Mapped[Optional[str]] = mapped_column(String(100))
    new_value: Mapped[Optional[str]] = mapped_column(String(100))
    note: Mapped[Optional[str]] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(100), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    candidate: Mapped["Candidate"] = relationship(back_populates="events")


class Webhook(Base):
    """Phase 5: registered outbound alert endpoints (Slack/Teams/SIEM/generic)."""
    __tablename__ = "webhooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(String(1000))
    label: Mapped[Optional[str]] = mapped_column(String(255))
    min_risk_level: Mapped[str] = mapped_column(String(10), default="HIGH")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
