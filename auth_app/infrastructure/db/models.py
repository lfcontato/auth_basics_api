# caminho: auth_app/infrastructure/db/models.py
# Funções:
# - Declarar modelos SQLAlchemy (AdminModel, AdminSessionModel, AdminContactModel)

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from auth_app.infrastructure.db.base import Base


class AdminModel(Base):
    __tablename__ = 'admins'

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    owner_id: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    system_role: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_role: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    subscription_plan: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    account_status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    is_verified: Mapped[bool] = mapped_column(Boolean, server_default=text('false'), default=False, nullable=False)
    verification_code_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    verification_code_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_channel: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    contacts: Mapped[list['AdminContactModel']] = relationship('AdminContactModel', back_populates='admin', cascade='all,delete-orphan')
    sessions: Mapped[list['AdminSessionModel']] = relationship('AdminSessionModel', back_populates='admin', cascade='all,delete-orphan')

    __table_args__ = (
        Index('ix_admin_username_ci', func.lower(username), unique=True),
        Index('ix_admin_email_ci', func.lower(email), unique=True),
        CheckConstraint('char_length(username) BETWEEN 4 AND 50', name='ck_admin_username_len'),
        CheckConstraint('char_length(email) BETWEEN 6 AND 254', name='ck_admin_email_len'),
    )


class AdminSessionModel(Base):
    __tablename__ = 'admins_sessions_local'

    id: Mapped[int] = mapped_column(primary_key=True)
    admin_id: Mapped[int] = mapped_column(ForeignKey('admins.id', ondelete='CASCADE'), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    family_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    refresh_token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    admin: Mapped['AdminModel'] = relationship('AdminModel', back_populates='sessions')

    __table_args__ = (Index('ix_admin_sessions_active', 'admin_id', 'expires_at', 'revoked_at'),)


class AdminContactModel(Base):
    __tablename__ = 'admin_contacts'

    id: Mapped[int] = mapped_column(primary_key=True)
    admin_id: Mapped[int] = mapped_column(ForeignKey('admins.id', ondelete='CASCADE'), nullable=False, index=True)
    contact_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    contact_value: Mapped[str] = mapped_column(String(128), nullable=False)
    is_main: Mapped[bool] = mapped_column(Boolean, server_default=text('false'), default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    admin: Mapped['AdminModel'] = relationship('AdminModel', back_populates='contacts')

    __table_args__ = (UniqueConstraint('contact_type', 'contact_value', name='ux_admin_contact_type_value'),)
