"""Versioned policy store model."""

from __future__ import annotations

from sqlalchemy import JSON, Column, Integer, String

from era.core.util import utcnow_iso
from era.models.base import Base


class PolicyVersion(Base):
    __tablename__ = "policy_version"

    id = Column(Integer, primary_key=True, autoincrement=True)
    version = Column(Integer, unique=True, nullable=False)
    document = Column(JSON, nullable=False)  # serialized Policy
    created_at = Column(String, nullable=False, default=utcnow_iso)
    changed_by = Column(String, nullable=False, default="system")
