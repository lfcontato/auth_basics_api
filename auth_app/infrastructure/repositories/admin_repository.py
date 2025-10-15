# caminho: auth_app/infrastructure/repositories/admin_repository.py
# Funções:
# - AdminRepositoryImpl: implementação SQLAlchemy do protocolo AdminRepository
# - AdminSessionRepositoryImpl: implementação para sessões
# - AdminContactRepositoryImpl: implementação para contatos

from __future__ import annotations

from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from auth_app.domain.admins.entities import Admin, AdminContact, AdminSession
from auth_app.domain.admins.repositories import (
    AdminContactRepository,
    AdminRepository,
    AdminSessionRepository,
)
from auth_app.infrastructure.db.models import AdminContactModel, AdminModel, AdminSessionModel


def _to_domain_admin(model: AdminModel) -> Admin:
    return Admin(
        id=model.id,
        email=model.email,
        username=model.username,
        password_hash=model.password_hash,
        owner_id=model.owner_id,
        system_role=model.system_role,
        resource_role=model.resource_role,
        subscription_plan=model.subscription_plan,
        account_status=model.account_status,
        is_verified=model.is_verified,
        verification_channel=model.verification_channel,
        verification_code_hash=model.verification_code_hash,
        verification_code_expires_at=model.verification_code_expires_at,
        contacts=[],
    )


class AdminRepositoryImpl(AdminRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, admin: Admin) -> Admin:
        model = AdminModel(
            email=admin.email,
            username=admin.username,
            password_hash=admin.password_hash,
            owner_id=admin.owner_id,
            system_role=admin.system_role,
            resource_role=admin.resource_role,
            subscription_plan=admin.subscription_plan,
            account_status=admin.account_status,
            is_verified=admin.is_verified,
            verification_channel=admin.verification_channel,
            verification_code_hash=admin.verification_code_hash,
            verification_code_expires_at=admin.verification_code_expires_at,
        )
        self._session.add(model)
        await self._session.flush()
        await self._session.commit()
        await self._session.refresh(model)
        return _to_domain_admin(model)

    async def get_by_id(self, admin_id: int) -> Optional[Admin]:
        stmt = select(AdminModel).where(AdminModel.id == admin_id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return _to_domain_admin(model) if model else None

    async def get_by_login(self, login: str) -> Optional[Admin]:
        stmt = select(AdminModel).where((func.lower(AdminModel.email) == login) | (func.lower(AdminModel.username) == login))
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return _to_domain_admin(model) if model else None

    async def list(self, offset: int, limit: int, system_roles: Sequence[str] | None = None) -> Sequence[Admin]:
        stmt = select(AdminModel).order_by(AdminModel.id)
        if system_roles is not None:
            normalized_roles = [role.lower() for role in system_roles]
            if not normalized_roles:
                return []
            stmt = stmt.where(func.lower(AdminModel.system_role).in_(normalized_roles))
        stmt = stmt.offset(offset).limit(limit)
        result = await self._session.execute(stmt)
        return [_to_domain_admin(model) for model in result.scalars().all()]

    async def remove(self, admin_id: int) -> bool:
        stmt = select(AdminModel).where(AdminModel.id == admin_id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:
            return False
        await self._session.delete(model)
        await self._session.flush()
        await self._session.commit()
        return True

    async def mark_verified(self, admin_id: int) -> Admin:
        stmt = (
            update(AdminModel)
            .where(AdminModel.id == admin_id)
            .values(
                is_verified=True,
                verification_code_hash=None,
                verification_code_expires_at=None,
            )
            .returning(AdminModel)
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:  # pragma: no cover - consistência garantida pelo serviço
            raise ValueError('Admin not found')
        await self._session.flush()
        await self._session.commit()
        return _to_domain_admin(model)

    async def update_verification_code(self, admin: Admin) -> Admin:
        stmt = (
            update(AdminModel)
            .where(AdminModel.id == admin.id)
            .values(
                verification_code_hash=admin.verification_code_hash,
                verification_code_expires_at=admin.verification_code_expires_at,
                verification_channel=admin.verification_channel,
                is_verified=False,
            )
            .returning(AdminModel)
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        await self._session.flush()
        await self._session.commit()
        return _to_domain_admin(model)

    async def update_password(self, admin_id: int, password_hash: str) -> Admin:
        stmt = (
            update(AdminModel)
            .where(AdminModel.id == admin_id)
            .values(password_hash=password_hash)
            .returning(AdminModel)
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:
            raise ValueError('Admin not found')
        await self._session.flush()
        await self._session.commit()
        return _to_domain_admin(model)

    async def update_email(self, admin_id: int, email: str) -> Admin:
        stmt = (
            update(AdminModel)
            .where(AdminModel.id == admin_id)
            .values(
                email=email,
                is_verified=False,
                verification_code_hash=None,
                verification_code_expires_at=None,
                account_status='pending_verification',
            )
            .returning(AdminModel)
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:
            raise ValueError('Admin not found')
        await self._session.flush()
        await self._session.commit()
        return _to_domain_admin(model)

    async def update_account_status(self, admin_id: int, account_status: str) -> Admin:
        stmt = select(AdminModel).where(AdminModel.id == admin_id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:
            raise ValueError('Admin not found')

        new_status = account_status.strip().lower()
        current_status = (model.account_status or '').strip().lower()
        if model.is_verified and new_status != current_status:
            raise ValueError('Account status locked for verified admin')

        model.account_status = new_status or model.account_status
        await self._session.flush()
        await self._session.commit()
        await self._session.refresh(model)
        return _to_domain_admin(model)


class AdminSessionRepositoryImpl(AdminSessionRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, session_obj: AdminSession) -> AdminSession:
        model = AdminSessionModel(
            admin_id=session_obj.admin_id,
            session_id=session_obj.session_id,
            family_id=session_obj.family_id,
            refresh_token_hash=session_obj.refresh_token_hash,
            expires_at=session_obj.expires_at,
            revoked_at=session_obj.revoked_at,
            revoked_reason=session_obj.revoked_reason,
            last_ip=session_obj.last_ip,
            user_agent=session_obj.user_agent,
        )
        self._session.add(model)
        await self._session.flush()
        await self._session.commit()
        await self._session.refresh(model)
        session_obj.id = model.id
        return session_obj

    async def get_by_session_id(self, session_id: str) -> Optional[AdminSession]:
        stmt = select(AdminSessionModel).where(AdminSessionModel.session_id == session_id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:
            return None
        return AdminSession(
            id=model.id,
            admin_id=model.admin_id,
            session_id=model.session_id,
            family_id=model.family_id,
            refresh_token_hash=model.refresh_token_hash,
            expires_at=model.expires_at,
            revoked_at=model.revoked_at,
            revoked_reason=model.revoked_reason,
            last_ip=model.last_ip,
            user_agent=model.user_agent,
        )

    async def revoke(self, session_id: str, reason: str) -> AdminSession:
        stmt = update(AdminSessionModel).where(AdminSessionModel.session_id == session_id).values(revoked_at=datetime.utcnow(), revoked_reason=reason).returning(AdminSessionModel)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        await self._session.flush()
        await self._session.commit()
        return AdminSession(
            id=model.id,
            admin_id=model.admin_id,
            session_id=model.session_id,
            family_id=model.family_id,
            refresh_token_hash=model.refresh_token_hash,
            expires_at=model.expires_at,
            revoked_at=model.revoked_at,
            revoked_reason=model.revoked_reason,
            last_ip=model.last_ip,
            user_agent=model.user_agent,
        )


class AdminContactRepositoryImpl(AdminContactRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def bulk_create(self, admin_id: int, contacts: Sequence[AdminContact]) -> Sequence[AdminContact]:
        models = [
            AdminContactModel(
                admin_id=admin_id,
                contact_type=contact.contact_type,
                contact_value=contact.contact_value,
                is_main=contact.is_main,
            )
            for contact in contacts
        ]
        self._session.add_all(models)
        await self._session.flush()
        await self._session.commit()
        for model in models:
            await self._session.refresh(model)
        return [
            AdminContact(
                id=model.id,
                admin_id=model.admin_id,
                contact_type=model.contact_type,
                contact_value=model.contact_value,
                is_main=model.is_main,
            )
            for model in models
        ]

    async def list_by_admin(self, admin_id: int) -> Sequence[AdminContact]:
        stmt = select(AdminContactModel).where(AdminContactModel.admin_id == admin_id)
        result = await self._session.execute(stmt)
        return [
            AdminContact(
                id=model.id,
                admin_id=model.admin_id,
                contact_type=model.contact_type,
                contact_value=model.contact_value,
                is_main=model.is_main,
            )
            for model in result.scalars().all()
        ]
