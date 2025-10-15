# caminho: auth_app/domain/admins/entities.py
# Funções:
# - Admin: entidade agregadora principal do contexto de Administradores
# - AdminContact: value object de contato vinculado ao Admin
# - AdminSession: entidade para controle de refresh tokens

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(slots=True)
class AdminContact:
    contact_type: str
    contact_value: str
    is_main: bool = False
    id: Optional[int] = None
    admin_id: Optional[int] = None


@dataclass(slots=True)
class AdminSession:
    session_id: str
    family_id: str
    refresh_token_hash: str
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None
    last_ip: Optional[str] = None
    user_agent: Optional[str] = None
    id: Optional[int] = None
    admin_id: Optional[int] = None

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and self.expires_at > datetime.now(tz=self.expires_at.tzinfo)


@dataclass(slots=True)
class Admin:
    email: str
    username: str
    password_hash: str
    owner_id: int
    system_role: str
    resource_role: str
    subscription_plan: str
    account_status: str
    verification_code_hash: Optional[str] = None
    verification_code_expires_at: Optional[datetime] = None
    verification_channel: Optional[str] = None
    is_verified: bool = False
    id: Optional[int] = None
    contacts: list[AdminContact] = field(default_factory=list)
