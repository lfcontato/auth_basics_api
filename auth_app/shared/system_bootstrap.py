# caminho: auth_app/shared/system_bootstrap.py
# Funções:
# - bootstrap_root_admin(): garante criação do administrador root na inicialização

from __future__ import annotations

from pwdlib import PasswordHash
from sqlalchemy import func, select

from auth_app.config import get_settings
from auth_app.infrastructure.db.base import SessionLocal
from auth_app.infrastructure.db.models import AdminModel
from auth_app.shared.logging import log_info, log_warning


async def bootstrap_root_admin() -> None:
    """Cria o administrador root padrão caso ainda não exista."""
    settings = get_settings()
    username = (settings.ROOT_AUTH_USER or '').strip().lower()
    email = (settings.ROOT_AUTH_EMAIL or '').strip().lower()
    password = (settings.ROOT_AUTH_PASSWORD.get_secret_value() or '').strip()
    
    log_warning('ROOT_ADMIN_BOOTSTRAP_STARTUP', {'reason': 'bootstrap_root_admin'})

    if not username or not email or not password:
        log_warning('ROOT_ADMIN_BOOTSTRAP_SKIPPED', {'reason': 'missing_credentials'})
        return

    log_warning('ROOT_ADMIN_BOOTSTRAP_STARTUP', {'reason': 'bootstrap_root_admin_2'})

    async with SessionLocal() as session:
        stmt = select(AdminModel).where(func.lower(AdminModel.email) == email)
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        log_warning('ROOT_ADMIN_BOOTSTRAP_STARTUP', {'reason': 'bootstrap_root_admin_3'})

        if existing is None:
            log_warning('ROOT_ADMIN_BOOTSTRAP_STARTUP', {'reason': 'no_existing'})
            stmt = select(AdminModel).where(func.lower(AdminModel.username) == username)
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

        if existing is not None:
            log_warning('ROOT_ADMIN_BOOTSTRAP_STARTUP', {'reason': 'existing'})
            log_info('ROOT_ADMIN_BOOTSTRAP_EXISTS', {'admin_id': existing.id})
            return

        password_hash = PasswordHash.recommended().hash(password)
        model = AdminModel(
            email=email,
            username=username,
            password_hash=password_hash,
            owner_id=0,
            system_role='root',
            resource_role='owner',
            subscription_plan='lifetime',
            account_status='active',
            is_verified=True,
        )
        session.add(model)
        await session.flush()
        model.owner_id = model.id
        await session.commit()
        log_info('ROOT_ADMIN_BOOTSTRAP_CREATED', {'admin_id': model.id})
