"""Durable provider circuit-breaker state (Phase 3F)."""

from __future__ import annotations

from sqlalchemy import Column, Float, Integer, String

from era.core.util import utcnow_iso
from era.models.base import Base


class CircuitBreakerStateRow(Base):
    """One persisted state-machine snapshot per provider id."""

    __tablename__ = "circuit_breaker_state"

    provider_id = Column(String, primary_key=True)
    state = Column(String, nullable=False, default="CLOSED")
    consecutive_failures = Column(Integer, nullable=False, default=0)
    # UNIX wall-clock time. A monotonic timestamp cannot survive a restart.
    opened_at = Column(Float, nullable=True)
    updated_at = Column(String, nullable=False, default=utcnow_iso)
