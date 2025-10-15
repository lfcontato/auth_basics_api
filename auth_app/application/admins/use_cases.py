# caminho: auth_app/application/admins/use_cases.py
# Funções:
# - Casos de uso de administradores: criar, listar, obter, remover, emitir tokens, refresh, verificar e reenviar códigos

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from secrets import choice, token_urlsafe
from string import digits
from typing import Protocol, Sequence
from uuid import uuid4

from fastapi import HTTPException
from pwdlib import PasswordHash

from redis.asyncio import Redis

from auth_app.application.admins.dto import (
    AdminCreateInput,
    AdminChangeEmailRequest,
    AdminChangePasswordRequest,
    AdminMessageResponse,
    AdminOutput,
    AdminResendVerificationRequest,
    AdminPasswordRecoveryRequest,
    AdminTokenPair,
    AdminUnlockStatusResponse,
    AdminVerificationRequest,
    AdminVerificationResponse,
)
from auth_app.config.settings import Settings
from auth_app.domain.admins.entities import Admin, AdminContact, AdminSession
from auth_app.domain.admins.enums import (
    SYSTEM_ROLE_SUPERUSER,
    can_manage_system_role,
    managed_system_roles,
)
from auth_app.domain.admins.repositories import AdminContactRepository, AdminRepository, AdminSessionRepository
from auth_app.infrastructure.security.jwt import JWTService
from auth_app.shared.logging import log_info, log_warning
from auth_app.shared.rate_limit import NullVerificationRateLimiter, VerificationRateLimiter
from auth_app.shared.security_lock import LockState, NullSecurityLockManager, SecurityLockManager


@dataclass(slots=True)
class AdminAdapters:
    admins: AdminRepository
    sessions: AdminSessionRepository
    contacts: AdminContactRepository


class AdminVerificationNotifier(Protocol):
    async def send(
        self,
        *,
        admin_name: str,
        login: str,
        recipients: Sequence[str],
        code: str,
        expires_at_iso: str,
    ) -> None: ...


class AdminService:
    def __init__(
        self,
        adapters: AdminAdapters,
        settings: Settings,
        password_hasher: PasswordHash,
        jwt_service: JWTService,
        verification_notifier: AdminVerificationNotifier | None = None,
        security_lock: SecurityLockManager | None = None,
        verification_rate_limiter: VerificationRateLimiter | None = None,
        password_recovery_rate_limiter: VerificationRateLimiter | None = None,
        redis_client: Redis | None = None,
        token_issue_rate_limiter: VerificationRateLimiter | None = None,
        token_refresh_rate_limiter: VerificationRateLimiter | None = None,
        verify_link_rate_limiter: VerificationRateLimiter | None = None,
    ) -> None:
        self._admins = adapters.admins
        self._sessions = adapters.sessions
        self._contacts = adapters.contacts
        self._settings = settings
        self._hasher = password_hasher
        self._jwt = jwt_service
        self._verification_notifier = verification_notifier
        self._locks = security_lock or NullSecurityLockManager()
        self._verification_rate_limiter = verification_rate_limiter or NullVerificationRateLimiter()
        self._password_recovery_rate_limiter = password_recovery_rate_limiter or NullVerificationRateLimiter()
        self._redis = redis_client
        self._token_issue_rate_limiter = token_issue_rate_limiter or NullVerificationRateLimiter()
        self._token_refresh_rate_limiter = token_refresh_rate_limiter or NullVerificationRateLimiter()
        self._verify_link_rate_limiter = verify_link_rate_limiter or NullVerificationRateLimiter()

    # -- Casos de Uso ---------------------------------------------------------

    async def create_admin(
        self,
        payload: AdminCreateInput,
        acting_admin_id: int | None = None,
        acting_system_role: str | None = None,
    ) -> AdminOutput:
        # if acting_system_role is not None and acting_system_role.lower() != SYSTEM_ROLE_SUPERUSER:
        #     log_warning('ADMIN_CREATE_FORBIDDEN', {'acting_admin_id': acting_admin_id})
        #     raise HTTPException(
        #         status_code=HTTPStatus.FORBIDDEN,
        #         detail={'code': 'ADMIN_CREATE_FORBIDDEN'},
        #     )

        # if acting_system_role is not None and acting_system_role.lower() != SYSTEM_ROLE_SUPERUSER:
        #     log_warning('ADMIN_CREATE_FORBIDDEN', {'acting_admin_id': acting_admin_id})
        #     raise HTTPException(
        #         status_code=HTTPStatus.FORBIDDEN,
        #         detail={'code': 'ADMIN_CREATE_FORBIDDEN'},
        #     )

        if acting_system_role is not None and not can_manage_system_role(acting_system_role, payload.system_role):
            log_warning(
                'ADMIN_HIERARCHY_FORBIDDEN',
                {'acting_system_role': acting_system_role, 'system_role': payload.system_role},
            )
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN,
                detail={'code': 'ADMIN_SYSTEM_ROLE_FORBIDDEN'},
            )
        
        password_hash = self._hasher.hash(payload.password.strip())
        requested_channel = (payload.verification_channel or '').strip().lower()
        if requested_channel and requested_channel != 'email':
            log_warning(
                'ADMIN_CREATE_CHANNEL_UNSUPPORTED',
                {'requested_channel': requested_channel, 'acting_admin_id': acting_admin_id},
            )
        verification_channel = 'email'
        admin = Admin(
            email=payload.email.lower(),
            username=payload.username.lower(),
            password_hash=password_hash,
            owner_id=acting_admin_id or 0,
            system_role=payload.system_role,
            resource_role=payload.resource_role,
            subscription_plan=payload.subscription_plan,
            account_status='pending_verification',
            verification_channel=verification_channel,
            contacts=[
                AdminContact(
                    contact_type=contact.contact_type.lower(),
                    contact_value=contact.contact_value.strip(),
                    is_main=contact.is_main,
                )
                for contact in payload.contacts
            ],
        )

        await self._ensure_unique(admin.email, admin.username)

        admin = await self._admins.add(admin)
        if admin.contacts:
            await self._contacts.bulk_create(admin.id, admin.contacts)

        channel_for_issue = admin.verification_channel or 'email'
        admin, code = await self._issue_verification_code(admin, channel_for_issue)
        await self._maybe_notify_verification(admin, code)
        log_info('ADMIN_CREATED', {'admin_id': admin.id})
        return self._to_output(admin)

    async def list_admins(self, offset: int, limit: int, acting_admin_id: int) -> Sequence[AdminOutput]:
        acting_admin = await self._require_admin(acting_admin_id)
        manageable_roles = managed_system_roles(acting_admin.system_role)
        if acting_admin.system_role.lower() == SYSTEM_ROLE_SUPERUSER:
            admins = await self._admins.list(offset, limit)
        elif not manageable_roles:
            return []
        else:
            admins = await self._admins.list(offset, limit, system_roles=manageable_roles)
        return [self._to_output(admin) for admin in admins]

    async def get_admin(self, admin_id: int, acting_admin_id: int) -> AdminOutput:
        acting_admin = await self._require_admin(acting_admin_id)
        if admin_id == acting_admin_id:
            return self._to_output(acting_admin)

        admin = await self._admins.get_by_id(admin_id)
        if admin is None:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail={'code': 'ADMIN_NOT_FOUND'})

        if not can_manage_system_role(acting_admin.system_role, admin.system_role):
            log_warning(
                'ADMIN_HIERARCHY_FORBIDDEN',
                {'acting_admin_id': acting_admin_id, 'target_admin_id': admin_id},
            )
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN,
                detail={'code': 'ADMIN_SYSTEM_ROLE_FORBIDDEN'},
            )
        return self._to_output(admin)

    async def delete_admin(self, admin_id: int, acting_admin_id: int) -> None:
        if admin_id == acting_admin_id:
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN,
                detail={'code': 'ADMIN_SELF_DELETE_FORBIDDEN'},
            )

        acting_admin = await self._require_admin(acting_admin_id)
        target = await self._admins.get_by_id(admin_id)
        if target is None:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail={'code': 'ADMIN_NOT_FOUND'})

        if not can_manage_system_role(acting_admin.system_role, target.system_role):
            log_warning(
                'ADMIN_HIERARCHY_FORBIDDEN',
                {'acting_admin_id': acting_admin_id, 'target_admin_id': admin_id},
            )
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN,
                detail={'code': 'ADMIN_SYSTEM_ROLE_FORBIDDEN'},
            )

        deleted = await self._admins.remove(admin_id)
        if not deleted:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail={'code': 'ADMIN_NOT_FOUND'})
        log_info('ADMIN_DELETED', {'admin_id': admin_id, 'acting_admin_id': acting_admin_id})

    async def issue_token(self, login: str, password: str, client_ip: str = '', user_agent: str = '') -> AdminTokenPair:
        login_normalized = login.lower()
        allowed, retry_in = await self._token_issue_rate_limiter.acquire(login_normalized)
        if not allowed:
            raise HTTPException(
                status_code=HTTPStatus.TOO_MANY_REQUESTS,
                detail={'code': 'TOKEN_ISSUE_RATE_LIMITED', 'retry_in_seconds': retry_in},
            )
        admin = await self._admins.get_by_login(login_normalized)
        password_clean = password.strip()

        if admin is not None:
            lock_state = await self._locks.get_block(admin.id, 'login')
            if lock_state is not None:
                log_warning(
                    'ADMIN_LOGIN_BLOCKED_ATTEMPT',
                    {'admin_id': admin.id, 'login': login_normalized, 'ip': client_ip, 'user_agent': user_agent},
                )
                raise HTTPException(
                    status_code=HTTPStatus.LOCKED,
                    detail={
                        'code': 'ADMIN_ACCOUNT_LOCKED',
                        'retry_in_seconds': lock_state.ttl_seconds,
                    },
                )

        if admin is None or not self._hasher.verify(password_clean, admin.password_hash):
            if admin is not None:
                locked = await self._locks.register_failure(
                    admin.id,
                    'login',
                    last_ip=(client_ip or '')[:64],
                    user_agent=(user_agent or '')[:128],
                )
                if locked:
                    log_warning(
                        'ADMIN_LOGIN_LOCKED',
                        {'admin_id': admin.id, 'login': login_normalized, 'ip': client_ip, 'user_agent': user_agent},
                    )
                    await self._maybe_notify_security_lock(
                        admin,
                        scope='login',
                        last_ip=(client_ip or '')[:64],
                        user_agent=(user_agent or '')[:128],
                    )
            log_warning('ADMIN_INVALID_CREDENTIALS', {'login': login})
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail={'code': 'ADMIN_INVALID_CREDENTIALS'})

        await self._locks.reset_failures(admin.id, 'login')

        session_id = str(uuid4())
        family_id = str(uuid4())
        access_token = self._jwt.create_access_token(
            subject=admin.username,
            email=admin.email,
            admin_id=admin.id,
            system_role=admin.system_role,
            expires_seconds=self._settings.TOKEN_ACCESS_EXPIRE_SECONDS,
        )
        refresh_token = self._jwt.create_refresh_token(
            subject=admin.username,
            email=admin.email,
            session_id=session_id,
            system_role=admin.system_role,
            expires_seconds=self._settings.TOKEN_REFRESH_EXPIRE_SECONDS,
        )

        session = AdminSession(
            session_id=session_id,
            family_id=family_id,
            refresh_token_hash=self._hasher.hash(refresh_token),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self._settings.TOKEN_REFRESH_EXPIRE_SECONDS),
            last_ip=client_ip[:64] or None,
            user_agent=user_agent[:64] or None,
            admin_id=admin.id,
        )

        await self._sessions.add(session)
        log_info('ADMIN_TOKEN_ISSUED', {'admin_id': admin.id, 'session_id': session_id})
        return AdminTokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self._settings.TOKEN_ACCESS_EXPIRE_SECONDS,
            refresh_expires_in=self._settings.TOKEN_REFRESH_EXPIRE_SECONDS,
        )

    async def refresh_token(self, refresh_token: str, client_ip: str = '', user_agent: str = '') -> AdminTokenPair:
        payload = self._jwt.decode_refresh_token(refresh_token)
        identifier = (payload.email or payload.subject or '').lower()
        allowed, retry_in = await self._token_refresh_rate_limiter.acquire(identifier or 'unknown')
        if not allowed:
            raise HTTPException(
                status_code=HTTPStatus.TOO_MANY_REQUESTS,
                detail={'code': 'TOKEN_REFRESH_RATE_LIMITED', 'retry_in_seconds': retry_in},
            )
        admin = await self._admins.get_by_login((payload.email or payload.subject).lower())
        if admin is None:
            log_warning('ADMIN_REFRESH_SUBJECT_NOT_FOUND', {'login': payload.subject})
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail={'code': 'ADMIN_REFRESH_SUBJECT_NOT_FOUND'})

        stored_session = await self._sessions.get_by_session_id(payload.session_id)
        if stored_session is None or not stored_session.is_active:
            log_warning('ADMIN_REFRESH_SESSION_INVALID', {'session_id': payload.session_id})
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail={'code': 'ADMIN_REFRESH_SESSION_INVALID'})

        if not self._hasher.verify(refresh_token, stored_session.refresh_token_hash):
            await self._sessions.revoke(payload.session_id, 'COMPROMISED')
            log_warning('ADMIN_REFRESH_HASH_MISMATCH', {'session_id': payload.session_id})
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail={'code': 'ADMIN_REFRESH_HASH_MISMATCH'})

        await self._sessions.revoke(payload.session_id, 'ROTATED')
        session_id = str(uuid4())
        access_token = self._jwt.create_access_token(
            subject=admin.username,
            email=admin.email,
            admin_id=admin.id,
            system_role=admin.system_role,
            expires_seconds=self._settings.TOKEN_ACCESS_EXPIRE_SECONDS,
        )
        new_refresh_token = self._jwt.create_refresh_token(
            subject=admin.username,
            email=admin.email,
            session_id=session_id,
            system_role=admin.system_role,
            expires_seconds=self._settings.TOKEN_REFRESH_EXPIRE_SECONDS,
        )

        session = AdminSession(
            session_id=session_id,
            family_id=stored_session.family_id,
            refresh_token_hash=self._hasher.hash(new_refresh_token),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self._settings.TOKEN_REFRESH_EXPIRE_SECONDS),
            last_ip=client_ip[:64] or None,
            user_agent=user_agent[:64] or None,
            admin_id=admin.id,
        )
        await self._sessions.add(session)
        log_info('ADMIN_REFRESH_ISSUED', {'admin_id': admin.id, 'session_id': session_id})
        return AdminTokenPair(
            access_token=access_token,
            refresh_token=new_refresh_token,
            expires_in=self._settings.TOKEN_ACCESS_EXPIRE_SECONDS,
            refresh_expires_in=self._settings.TOKEN_REFRESH_EXPIRE_SECONDS,
        )

    async def change_password(
        self,
        admin_id: int,
        payload: AdminChangePasswordRequest,
        acting_admin_id: int,
        client_ip: str = '',
        user_agent: str = '',
    ) -> AdminMessageResponse:
        if admin_id != acting_admin_id:
            raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail={'code': 'ADMIN_PASSWORD_FORBIDDEN'})

        lock_state = await self._locks.get_block(admin_id, 'password')
        if lock_state is not None:
            log_warning(
                'ADMIN_PASSWORD_BLOCKED_ATTEMPT',
                {'admin_id': admin_id, 'ip': client_ip, 'user_agent': user_agent},
            )
            raise HTTPException(
                status_code=HTTPStatus.LOCKED,
                detail={
                    'code': 'ADMIN_ACCOUNT_LOCKED',
                    'retry_in_seconds': lock_state.ttl_seconds,
                },
            )

        admin = await self._admins.get_by_id(admin_id)
        if admin is None:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail={'code': 'ADMIN_NOT_FOUND'})

        current_password = payload.current_password.strip()
        new_password = payload.new_password.strip()
        new_password_confirm = payload.new_password_confirm.strip()

        if new_password != new_password_confirm:
            locked = await self._locks.register_failure(
                admin_id,
                'password',
                last_ip=(client_ip or '')[:64],
                user_agent=(user_agent or '')[:128],
            )
            if locked:
                await self._maybe_notify_security_lock(
                    admin,
                    scope='password',
                    last_ip=(client_ip or '')[:64],
                    user_agent=(user_agent or '')[:128],
                )
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail={'code': 'ADMIN_PASSWORD_CONFIRM_MISMATCH'},
            )

        if not self._hasher.verify(current_password, admin.password_hash):
            locked = await self._locks.register_failure(
                admin_id,
                'password',
                last_ip=(client_ip or '')[:64],
                user_agent=(user_agent or '')[:128],
            )
            if locked:
                await self._maybe_notify_security_lock(
                    admin,
                    scope='password',
                    last_ip=(client_ip or '')[:64],
                    user_agent=(user_agent or '')[:128],
                )
            raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail={'code': 'ADMIN_INVALID_CURRENT_PASSWORD'})

        if self._hasher.verify(new_password, admin.password_hash):
            locked = await self._locks.register_failure(
                admin_id,
                'password',
                last_ip=(client_ip or '')[:64],
                user_agent=(user_agent or '')[:128],
            )
            if locked:
                await self._maybe_notify_security_lock(
                    admin,
                    scope='password',
                    last_ip=(client_ip or '')[:64],
                    user_agent=(user_agent or '')[:128],
                )
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail={'code': 'ADMIN_PASSWORD_UNCHANGED'},
            )

        new_hash = self._hasher.hash(new_password)
        await self._admins.update_password(admin_id, new_hash)
        await self._locks.reset_failures(admin_id, 'password')
        await self._notify_password_change(admin, last_ip=client_ip)
        log_info('ADMIN_PASSWORD_CHANGED', {'admin_id': admin_id})
        return AdminMessageResponse(message='Senha atualizada com sucesso.')

    async def change_email(
        self,
        admin_id: int,
        payload: AdminChangeEmailRequest,
        acting_admin_id: int,
    ) -> AdminOutput:
        if admin_id != acting_admin_id:
            raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail={'code': 'ADMIN_EMAIL_FORBIDDEN'})

        admin = await self._admins.get_by_id(admin_id)
        if admin is None:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail={'code': 'ADMIN_NOT_FOUND'})

        new_email = payload.new_email.lower()
        existing = await self._admins.get_by_login(new_email)
        if existing is not None and existing.id != admin_id:
            raise HTTPException(status_code=HTTPStatus.CONFLICT, detail={'code': 'ADMIN_EMAIL_EXISTS'})

        admin = await self._admins.update_email(admin_id, new_email)
        admin, code = await self._issue_verification_code(admin, 'email')
        await self._maybe_notify_verification(admin, code)
        log_info('ADMIN_EMAIL_CHANGED', {'admin_id': admin_id})
        return self._to_output(admin)

    async def recover_password(self, payload: AdminPasswordRecoveryRequest) -> AdminMessageResponse:
        email = payload.email.lower()
        admin = await self._admins.get_by_login(email)
        if admin is None:
            log_warning('ADMIN_PASSWORD_RECOVERY_NOT_FOUND', {'email': email})
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail={'code': 'ADMIN_NOT_FOUND'})

        token = (payload.recovery_token or '').strip()
        if not token:
            allowed, retry_in = await self._password_recovery_rate_limiter.acquire(email)
            if not allowed:
                raise HTTPException(
                    status_code=HTTPStatus.TOO_MANY_REQUESTS,
                    detail={'code': 'PASSWORD_RECOVERY_RATE_LIMITED', 'retry_in_seconds': retry_in},
                )

            generated_token = await self._issue_password_recovery_token(admin)
            await self._notify_password_recovery(admin, generated_token)
            log_info('PASSWORD_RECOVERY_TOKEN_CREATED', {'admin_id': admin.id})
            return AdminMessageResponse(message='Token de recuperação enviado para o e-mail cadastrado.')

        await self._validate_password_recovery_token(admin, token)
        new_password = (payload.new_password or '').strip()
        new_hash = self._hasher.hash(new_password)
        admin = await self._admins.update_password(admin.id, new_hash)
        await self._locks.reset_failures(admin.id, 'password')

        await self._notify_password_change(admin, last_ip=None)
        log_info('ADMIN_PASSWORD_RECOVERED', {'admin_id': admin.id})
        return AdminMessageResponse(message='Senha redefinida com sucesso.')

    async def unlock_admin(self, email: str, acting_admin_id: int, acting_system_role: str) -> AdminMessageResponse:
        role = self._ensure_privileged_role(acting_system_role)

        admin = await self._admins.get_by_login(email.lower())
        if admin is None:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail={'code': 'ADMIN_NOT_FOUND'})

        await self._locks.reset_all(admin.id)
        log_info(
            'ADMIN_UNLOCKED_MANUALLY',
            {'admin_id': admin.id, 'acting_admin_id': acting_admin_id, 'acting_role': role},
        )
        return AdminMessageResponse(message='Conta desbloqueada com sucesso.')

    async def trigger_password_recovery(self, admin_id: int, acting_admin_id: int, acting_system_role: str) -> AdminMessageResponse:
        self._ensure_privileged_role(acting_system_role)

        admin = await self._admins.get_by_id(admin_id)
        if admin is None:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail={'code': 'ADMIN_NOT_FOUND'})

        allowed, retry_in = await self._password_recovery_rate_limiter.acquire(admin.email)
        if not allowed:
            raise HTTPException(
                status_code=HTTPStatus.TOO_MANY_REQUESTS,
                detail={'code': 'PASSWORD_RECOVERY_RATE_LIMITED', 'retry_in_seconds': retry_in},
            )

        token = await self._issue_password_recovery_token(admin)
        await self._notify_password_recovery(admin, token)
        log_info(
            'ADMIN_PASSWORD_RECOVERY_TRIGGERED',
            {'admin_id': admin.id, 'acting_admin_id': acting_admin_id},
        )
        return AdminMessageResponse(message='Token de recuperação enviado para o e-mail do administrador.')

    async def get_unlock_status(self, email: str, acting_admin_id: int, acting_system_role: str) -> AdminUnlockStatusResponse:
        self._ensure_privileged_role(acting_system_role)

        admin = await self._admins.get_by_login(email.lower())
        if admin is None:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail={'code': 'ADMIN_NOT_FOUND'})

        login_state = await self._locks.get_block(admin.id, 'login')
        password_state = await self._locks.get_block(admin.id, 'password')
        return self._build_unlock_status(admin, login_state, password_state)

    async def list_unlock_status(self, acting_admin_id: int, acting_system_role: str) -> list[AdminUnlockStatusResponse]:
        self._ensure_privileged_role(acting_system_role)
        blocks = await self._locks.list_blocks()
        grouped: dict[int, dict[str, LockState]] = {}
        for block in blocks:
            scoped = grouped.setdefault(block.admin_id, {})
            scoped[block.scope] = block

        results: list[AdminUnlockStatusResponse] = []
        for admin_id, scopes in grouped.items():
            admin = await self._admins.get_by_id(admin_id)
            if admin is None:
                continue
            login_state = scopes.get('login')
            password_state = scopes.get('password')
            unlock_status = self._build_unlock_status(admin, login_state, password_state)
            results.append(unlock_status)
        return results

    @staticmethod
    def _ensure_privileged_role(role: str) -> str:
        normalized = (role or '').lower()
        if normalized not in {'root', 'admin'}:
            raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail={'code': 'ADMIN_UNLOCK_FORBIDDEN'})
        return normalized

    @staticmethod
    def _build_unlock_status(
        admin: Admin,
        login_state: LockState | None,
        password_state: LockState | None,
    ) -> AdminUnlockStatusResponse:
        reference_state = login_state or password_state
        return AdminUnlockStatusResponse(
            email=admin.email,
            is_blocked_login=login_state is not None,
            is_blocked_password=password_state is not None,
            login_retry_in_seconds=login_state.ttl_seconds if login_state else None,
            password_retry_in_seconds=password_state.ttl_seconds if password_state else None,
            last_ip=reference_state.last_ip if reference_state else None,
            user_agent=reference_state.user_agent if reference_state else None,
            blocked_at=reference_state.blocked_at if reference_state else None,
        )

    async def _maybe_notify_security_lock(
        self,
        admin: Admin,
        *,
        scope: str,
        last_ip: str | None,
        user_agent: str | None,
    ) -> None:
        if self._verification_notifier is None:
            return
        blocked_at = datetime.now(timezone.utc).isoformat()
        try:
            log_warning(
                'SECURITY_EMAIL_SENDING',
                {
                    'admin_id': admin.id,
                    'scope': scope,
                    'recipient': admin.email,
                    'last_ip': last_ip,
                },
            )
            await self._verification_notifier.send_security_alert(
                admin_name=admin.username,
                login=admin.email,
                recipients=[admin.email],
                last_ip=last_ip,
                user_agent=user_agent,
                blocked_at_iso=blocked_at,
            )
        except Exception as exc:  # pragma: no cover - envio não deve quebrar fluxo
            log_warning('SECURITY_EMAIL_FAILED', {'admin_id': admin.id, 'error': str(exc)})

    async def _notify_password_recovery(self, admin: Admin, token: str) -> None:
        if self._verification_notifier is None:
            return
        try:
            log_info('PASSWORD_RECOVERY_EMAIL_SENDING', {'admin_id': admin.id})
            await self._verification_notifier.send_password_recovery(
                admin_name=admin.username,
                login=admin.email,
                recipients=[admin.email],
                token=token,
            )
        except Exception as exc:  # pragma: no cover
            log_warning('PASSWORD_RECOVERY_EMAIL_FAILED', {'admin_id': admin.id, 'error': str(exc)})

    async def _notify_password_change(self, admin: Admin, last_ip: str | None) -> None:
        if self._verification_notifier is None:
            return
        try:
            log_info('PASSWORD_CHANGED_EMAIL_SENDING', {'admin_id': admin.id})
            changed_at = datetime.now(timezone.utc).isoformat()
            await self._verification_notifier.send_password_changed_confirmation(
                admin_name=admin.username,
                login=admin.email,
                recipients=[admin.email],
                changed_at_iso=changed_at,
                last_ip=last_ip,
            )
        except Exception as exc:  # pragma: no cover
            log_warning('PASSWORD_CHANGED_EMAIL_FAILED', {'admin_id': admin.id, 'error': str(exc)})

    def _password_recovery_admin_key(self, admin_id: int) -> str:
        return f'password:recovery:admin:{admin_id}'

    def _password_recovery_token_key(self, token: str) -> str:
        return f'password:recovery:token:{token}'

    async def _issue_password_recovery_token(self, admin: Admin) -> str:
        if self._redis is None:
            raise HTTPException(status_code=HTTPStatus.SERVICE_UNAVAILABLE, detail={'code': 'PASSWORD_RECOVERY_UNAVAILABLE'})

        token = token_urlsafe(32)
        token_key = self._password_recovery_token_key(token)
        admin_key = self._password_recovery_admin_key(admin.id)

        previous_token = await self._redis.get(admin_key)
        if previous_token:
            await self._redis.delete(self._password_recovery_token_key(previous_token))

        await self._redis.set(
            token_key,
            str(admin.id),
            ex=self._settings.PASSWORD_RECOVERY_TOKEN_EXPIRE_SECONDS,
        )
        await self._redis.set(
            admin_key,
            token,
            ex=self._settings.PASSWORD_RECOVERY_TOKEN_EXPIRE_SECONDS,
        )
        return token

    async def _validate_password_recovery_token(self, admin: Admin, token: str) -> None:
        if self._redis is None:
            raise HTTPException(status_code=HTTPStatus.SERVICE_UNAVAILABLE, detail={'code': 'PASSWORD_RECOVERY_UNAVAILABLE'})

        token_key = self._password_recovery_token_key(token)
        stored_admin_id = await self._redis.get(token_key)
        if stored_admin_id is None or int(stored_admin_id) != admin.id:
            log_warning('PASSWORD_RECOVERY_TOKEN_INVALID', {'admin_id': admin.id})
            raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail={'code': 'PASSWORD_RECOVERY_TOKEN_INVALID'})

        await self._redis.delete(token_key)
        await self._redis.delete(self._password_recovery_admin_key(admin.id))

    async def verify_admin(self, payload: AdminVerificationRequest) -> AdminMessageResponse:
        identifier_context: dict[str, str | int] = {}
        admin = None
        if payload.admin_id is not None:
            identifier_context['admin_id'] = payload.admin_id
            admin = await self._admins.get_by_id(payload.admin_id)
        elif payload.login:
            login = payload.login.lower()
            allowed, retry_in = await self._verify_link_rate_limiter.acquire(login)
            if not allowed:
                raise HTTPException(
                    status_code=HTTPStatus.TOO_MANY_REQUESTS,
                    detail={'code': 'VERIFY_LINK_RATE_LIMITED', 'retry_in_seconds': retry_in},
                )
            identifier_context['login'] = login
            admin = await self._admins.get_by_login(login)
        else:
            log_warning('ADMIN_VERIFICATION_IDENTIFIER_MISSING', {})
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail={
                    'code': 'VERIFICATION_IDENTIFIER_REQUIRED',
                    'message': 'Identificador de administrador ausente.',
                },
            )

        if admin is None:
            log_warning('ADMIN_VERIFICATION_LINK_NOT_AVAILABLE', identifier_context)
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND,
                detail={'code': 'LINK_NOT_AVAILABLE', 'message': 'Link não disponível.'},
            )

        if admin.is_verified:
            log_info('ADMIN_ALREADY_VERIFIED', {'admin_id': admin.id})
            raise HTTPException(
                status_code=HTTPStatus.CONFLICT,
                detail={'code': 'LINK_NOT_AVAILABLE', 'message': 'Conta já confirmada.'},
            )

        if not admin.verification_code_hash or not admin.verification_code_expires_at:
            log_warning('ADMIN_VERIFICATION_MISSING', {'admin_id': admin.id})
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND,
                detail={'code': 'LINK_NOT_AVAILABLE', 'message': 'Link não disponível.'},
            )

        if admin.verification_code_expires_at <= datetime.now(timezone.utc):
            log_warning('ADMIN_VERIFICATION_EXPIRED', {'admin_id': admin.id})
            raise HTTPException(
                status_code=HTTPStatus.GONE,
                detail={'code': 'LINK_EXPIRED', 'message': 'Link expirado.'},
            )

        if not self._hasher.verify(payload.verification_code, admin.verification_code_hash):
            log_warning('ADMIN_VERIFICATION_INVALID', {'admin_id': admin.id})
            raise HTTPException(
                status_code=HTTPStatus.UNAUTHORIZED,
                detail={'code': 'VERIFICATION_CODE_INVALID', 'message': 'Código de verificação inválido.'},
            )

        if admin.account_status != 'active':
            try:
                admin = await self._admins.update_account_status(admin.id, 'active')
            except ValueError as exc:
                log_warning(
                    'ADMIN_ACCOUNT_STATUS_LOCKED',
                    {'admin_id': admin.id, 'error': str(exc)},
                )
                raise HTTPException(
                    status_code=HTTPStatus.CONFLICT,
                    detail={'code': 'ADMIN_ACCOUNT_STATUS_LOCKED', 'message': 'Estado de conta não pode ser alterado após verificação.'},
                ) from exc

        admin = await self._admins.mark_verified(admin.id)
        log_info('ADMIN_VERIFIED', {'admin_id': admin.id})
        return AdminMessageResponse(message='Conta verificada com sucesso.')

    async def resend_verification_code(self, request: AdminResendVerificationRequest) -> AdminVerificationResponse:
        email = request.email.lower()
        allowed, retry_in = await self._verification_rate_limiter.acquire(email)
        if not allowed:
            raise HTTPException(
                status_code=HTTPStatus.TOO_MANY_REQUESTS,
                detail={'code': 'VERIFICATION_RESEND_RATE_LIMITED', 'retry_in_seconds': retry_in},
            )

        admin = await self._admins.get_by_login(email)
        if admin is None:
            log_warning('ADMIN_VERIFICATION_RESEND_NOT_FOUND', {'email': email})
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND,
                detail={'code': 'ADMIN_NOT_FOUND'},
            )

        if admin.is_verified:
            log_info('ADMIN_VERIFICATION_RESEND_ALREADY_VERIFIED', {'admin_id': admin.id})
            raise HTTPException(
                status_code=HTTPStatus.CONFLICT,
                detail={'code': 'ADMIN_ALREADY_VERIFIED'},
            )

        if admin.verification_code_expires_at is not None:
            remaining = (admin.verification_code_expires_at - datetime.now(timezone.utc)).total_seconds()
            if remaining > self._settings.VERIFICATION_CODE_THROTTLE_SECONDS:
                raise HTTPException(
                    status_code=HTTPStatus.TOO_MANY_REQUESTS,
                    detail={
                        'code': 'VERIFICATION_CODE_STILL_VALID',
                        'retry_in_seconds': int(remaining - self._settings.VERIFICATION_CODE_THROTTLE_SECONDS),
                    },
                )

        requested_channel = (request.channel or '').strip().lower()
        stored_channel = (admin.verification_channel or '').strip().lower()
        channel = requested_channel or stored_channel or None
        admin, code = await self._issue_verification_code(admin, channel)
        await self._maybe_notify_verification(admin, code)
        log_info('ADMIN_VERIFICATION_REGENERATED', {'admin_id': admin.id, 'channel': channel or ''})
        return AdminVerificationResponse(
            admin_id=admin.id,
            channel=admin.verification_channel,
            expires_at=admin.verification_code_expires_at,
        )

    # -- Helpers ----------------------------------------------------------------

    async def _require_admin(self, admin_id: int) -> Admin:
        admin = await self._admins.get_by_id(admin_id)
        if admin is None:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail={'code': 'ADMIN_NOT_FOUND'})
        return admin

    async def _issue_verification_code(self, admin: Admin, channel: str | None) -> tuple[Admin, str]:
        code = ''.join(self._random_digits(self._settings.VERIFICATION_CODE_LENGTH))
        admin = replace(
            admin,
            verification_code_hash=self._hasher.hash(code),
            verification_code_expires_at=datetime.now(timezone.utc) + timedelta(seconds=self._settings.VERIFICATION_CODE_EXPIRE_SECONDS),
            verification_channel=channel,
            is_verified=False,
        )
        admin = await self._admins.update_verification_code(admin)
        return admin, code

    async def _maybe_notify_verification(self, admin: Admin, code: str) -> None:
        if self._verification_notifier is None:
            return
        if admin.verification_channel != 'email':
            return
        if admin.verification_code_expires_at is None:
            return

        try:
            contacts = await self._contacts.list_by_admin(admin.id)
        except Exception:  # pragma: no cover - falha inesperada no repositório
            contacts = []

        recipient_candidates = []
        for contact in contacts:
            if (contact.contact_type or '').lower() != 'email':
                continue
            value = contact.contact_value.strip()
            if value:
                recipient_candidates.append(value)
        recipient_candidates.append(admin.email)

        seen = set()
        recipients: list[str] = []
        for address in recipient_candidates:
            key = address.lower()
            if key not in seen:
                seen.add(key)
                recipients.append(address)

        try:
            log_warning(
                'ADMIN_VERIFICATION_EMAIL_SENDING',
                {
                    'admin_id': admin.id,
                    'recipients': recipients,
                    'expires_at': admin.verification_code_expires_at.isoformat(),
                },
            )
            await self._verification_notifier.send(
                admin_name=admin.username,
                login=admin.email,
                recipients=recipients,
                code=code,
                expires_at_iso=admin.verification_code_expires_at.isoformat(),
            )
        except Exception as exc:  # pragma: no cover - notificação não deve quebrar fluxo
            log_warning('ADMIN_VERIFICATION_EMAIL_FAILED', {'admin_id': admin.id, 'error': str(exc)})

    @staticmethod
    def _to_output(admin: Admin) -> AdminOutput:
        return AdminOutput(
            id=admin.id,
            email=admin.email,
            username=admin.username,
            owner_id=admin.owner_id,
            system_role=admin.system_role,
            resource_role=admin.resource_role,
            subscription_plan=admin.subscription_plan,
            account_status=admin.account_status,
            is_verified=admin.is_verified,
            verification_channel=admin.verification_channel,
        )

    @staticmethod
    def _random_digits(length: int) -> list[str]:
        return [choice(digits) for _ in range(length)]

    async def _ensure_unique(self, email: str, username: str) -> None:
        existing_email = await self._admins.get_by_login(email)
        if existing_email is not None:
            log_warning('ADMIN_ALREADY_EXISTS', {'email': email})
            raise HTTPException(status_code=HTTPStatus.CONFLICT, detail={'code': 'ADMIN_EMAIL_EXISTS'})

        existing_username = await self._admins.get_by_login(username)
        if existing_username is not None:
            log_warning('ADMIN_ALREADY_EXISTS', {'username': username})
            raise HTTPException(status_code=HTTPStatus.CONFLICT, detail={'code': 'ADMIN_USERNAME_EXISTS'})
