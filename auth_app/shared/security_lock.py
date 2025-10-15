# caminho: auth_app/shared/security_lock.py
# Funções:
# - SecurityLockManager: abstrai controle de bloqueio por tentativas
# - RedisSecurityLockManager: implementa bloqueio via Redis
# - NullSecurityLockManager: no-op para cenários sem Redis (ex.: testes)

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

import redis.asyncio as redis


@dataclass(slots=True)
class LockState:
    admin_id: int
    scope: str
    ttl_seconds: int
    last_ip: str | None = None
    user_agent: str | None = None
    blocked_at: str | None = None


class SecurityLockManager(Protocol):
    async def get_block(self, admin_id: int, scope: str) -> LockState | None: ...
    async def register_failure(
        self,
        admin_id: int,
        scope: str,
        *,
        last_ip: str = '',
        user_agent: str = '',
    ) -> bool: ...
    async def reset_failures(self, admin_id: int, scope: str) -> None: ...
    async def reset_all(self, admin_id: int) -> None: ...
    async def list_blocks(self) -> list[LockState]: ...


class NullSecurityLockManager(SecurityLockManager):
    async def get_block(self, admin_id: int, scope: str) -> LockState | None:  # pragma: no cover - usado em testes
        return None

    async def register_failure(
        self,
        admin_id: int,
        scope: str,
        *,
        last_ip: str = '',
        user_agent: str = '',
    ) -> bool:  # pragma: no cover - usado em testes
        return False

    async def reset_failures(self, admin_id: int, scope: str) -> None:  # pragma: no cover - usado em testes
        return None

    async def reset_all(self, admin_id: int) -> None:  # pragma: no cover - usado em testes
        return None

    async def list_blocks(self) -> list[LockState]:  # pragma: no cover - usado em testes
        return []


class RedisSecurityLockManager(SecurityLockManager):
    def __init__(
        self,
        client: redis.Redis,
        *,
        block_duration_seconds: int,
        max_login_failures: int,
        max_password_failures: int,
    ) -> None:
        self._client = client
        self._block_duration = max(1, block_duration_seconds)
        self._limits = {
            'login': max(1, max_login_failures),
            'password': max(1, max_password_failures),
        }

    async def get_block(self, admin_id: int, scope: str) -> LockState | None:
        lock_key = self._lock_key(scope, admin_id)
        data = await self._client.hgetall(lock_key)
        if not data:
            return None
        ttl = await self._client.ttl(lock_key)
        ttl = ttl if ttl and ttl > 0 else self._block_duration
        return LockState(
            admin_id=admin_id,
            scope=scope,
            ttl_seconds=ttl,
            last_ip=data.get('last_ip') or None,
            user_agent=data.get('user_agent') or None,
            blocked_at=data.get('blocked_at') or None,
        )

    async def register_failure(
        self,
        admin_id: int,
        scope: str,
        *,
        last_ip: str = '',
        user_agent: str = '',
    ) -> bool:
        scope = scope.lower()
        limit = self._limits.get(scope)
        if limit is None:
            return False

        failure_key = self._failure_key(scope, admin_id)
        attempts = await self._client.incr(failure_key)
        if attempts == 1:
            await self._client.expire(failure_key, self._block_duration)

        if attempts >= limit:
            lock_key = self._lock_key(scope, admin_id)
            await self._client.hset(
                lock_key,
                mapping={
                    'attempts': str(attempts),
                    'last_ip': last_ip or '',
                    'user_agent': user_agent or '',
                    'blocked_at': datetime.now(timezone.utc).isoformat(),
                },
            )
            await self._client.expire(lock_key, self._block_duration)
            return True
        return False

    async def reset_failures(self, admin_id: int, scope: str) -> None:
        scope = scope.lower()
        await self._client.delete(self._failure_key(scope, admin_id))

    async def reset_all(self, admin_id: int) -> None:
        keys = []
        for scope in self._limits.keys():
            keys.append(self._failure_key(scope, admin_id))
            keys.append(self._lock_key(scope, admin_id))
        if keys:
            await self._client.delete(*keys)

    async def list_blocks(self) -> list[LockState]:
        pattern = 'security:*:lock:*'
        results: list[LockState] = []
        async for key in self._client.scan_iter(match=pattern):
            try:
                _, scope, _, admin_id_raw = key.split(':', 3)
                admin_id = int(admin_id_raw)
            except (ValueError, AttributeError):  # pragma: no cover - chave inesperada
                continue

            data = await self._client.hgetall(key)
            ttl = await self._client.ttl(key)
            ttl = ttl if ttl and ttl > 0 else self._block_duration
            results.append(
                LockState(
                    admin_id=admin_id,
                    scope=scope,
                    ttl_seconds=ttl,
                    last_ip=data.get('last_ip') or None,
                    user_agent=data.get('user_agent') or None,
                    blocked_at=data.get('blocked_at') or None,
                )
            )
        return results

    @staticmethod
    def _failure_key(scope: str, admin_id: int) -> str:
        return f'security:{scope}:fail:{admin_id}'

    @staticmethod
    def _lock_key(scope: str, admin_id: int) -> str:
        return f'security:{scope}:lock:{admin_id}'
