# caminho: auth_app/interfaces/api/dependencies.py
# Funções:
# - get_admin_service(): instancia AdminService com adapters concretos

from __future__ import annotations

from fastapi import Depends
from pwdlib import PasswordHash

from auth_app.application.admins.use_cases import AdminAdapters, AdminService
from auth_app.config import get_settings
from auth_app.infrastructure.cache.redis import get_redis_client
from auth_app.infrastructure.db.base import get_session
from auth_app.infrastructure.repositories.admin_repository import (
    AdminContactRepositoryImpl,
    AdminRepositoryImpl,
    AdminSessionRepositoryImpl,
)
from auth_app.infrastructure.security.jwt import JWTService
from auth_app.shared.email_notifications import EmailVerificationNotifier
from auth_app.shared.rate_limit import NullVerificationRateLimiter, RedisVerificationRateLimiter
from auth_app.shared.security_lock import NullSecurityLockManager, RedisSecurityLockManager


async def get_admin_service(
    session=Depends(get_session),
    redis_client=Depends(get_redis_client),
):
    settings = get_settings()
    jwt_service = JWTService(settings.SECRET_KEY, settings.SECRET_ALGORITHM)
    password_hasher = PasswordHash.recommended()
    verification_notifier = EmailVerificationNotifier(settings)
    adapters = AdminAdapters(
        admins=AdminRepositoryImpl(session),
        sessions=AdminSessionRepositoryImpl(session),
        contacts=AdminContactRepositoryImpl(session),
    )
    if redis_client is None:  # pragma: no cover - segurança defensiva
        security_lock = NullSecurityLockManager()
        verification_rate_limiter = NullVerificationRateLimiter()
        password_recovery_rate_limiter = NullVerificationRateLimiter()
        token_issue_rate_limiter = NullVerificationRateLimiter()
        token_refresh_rate_limiter = NullVerificationRateLimiter()
        verify_link_rate_limiter = NullVerificationRateLimiter()
    else:
        security_lock = RedisSecurityLockManager(
            redis_client,
            block_duration_seconds=settings.SECURITY_BLOCK_DURATION_SECONDS,
            max_login_failures=settings.SECURITY_MAX_LOGIN_FAILURES,
            max_password_failures=settings.SECURITY_MAX_PASSWORD_CHANGE_FAILURES,
        )
        verification_rate_limiter = RedisVerificationRateLimiter(
            redis_client,
            interval_seconds=settings.VERIFICATION_RESEND_INTERVAL_SECONDS,
            prefix='verification:resend',
        )
        password_recovery_rate_limiter = RedisVerificationRateLimiter(
            redis_client,
            interval_seconds=settings.PASSWORD_RECOVERY_INTERVAL_SECONDS,
            prefix='password:recovery',
        )
        token_issue_rate_limiter = RedisVerificationRateLimiter(
            redis_client,
            interval_seconds=settings.TOKEN_ISSUE_INTERVAL_SECONDS,
            prefix='auth:token',
        )
        token_refresh_rate_limiter = RedisVerificationRateLimiter(
            redis_client,
            interval_seconds=settings.TOKEN_REFRESH_INTERVAL_SECONDS,
            prefix='auth:refresh',
        )
        verify_link_rate_limiter = RedisVerificationRateLimiter(
            redis_client,
            interval_seconds=settings.VERIFY_LINK_INTERVAL_SECONDS,
            prefix='auth:verify-link',
        )
    return AdminService(
        adapters=adapters,
        settings=settings,
        password_hasher=password_hasher,
        jwt_service=jwt_service,
        verification_notifier=verification_notifier,
        security_lock=security_lock,
        verification_rate_limiter=verification_rate_limiter,
        password_recovery_rate_limiter=password_recovery_rate_limiter,
        token_issue_rate_limiter=token_issue_rate_limiter,
        token_refresh_rate_limiter=token_refresh_rate_limiter,
        verify_link_rate_limiter=verify_link_rate_limiter,
        redis_client=redis_client,
    )
