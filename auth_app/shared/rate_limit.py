# caminho: auth_app/shared/rate_limit.py
# Funções:
# - VerificationRateLimiter: controla tentativas de reenvio com Redis
# - NullVerificationRateLimiter: implementação no-op para testes

from __future__ import annotations

from typing import Protocol

import redis.asyncio as redis


class VerificationRateLimiter(Protocol):
    async def acquire(self, login: str) -> tuple[bool, int]: ...


class RedisVerificationRateLimiter:
    def __init__(self, client: redis.Redis, interval_seconds: int, *, prefix: str = 'verification:resend') -> None:
        self._client = client
        self._interval = max(1, int(interval_seconds))
        self._prefix = prefix

    async def acquire(self, login: str) -> tuple[bool, int]:
        key = self._key(login)
        added = await self._client.set(key, '1', nx=True, ex=self._interval)
        
        if added:
            return True, self._interval

        ttl = await self._client.ttl(key)
        if ttl is None or ttl < 0:
            ttl = self._interval
        return False, int(ttl)

    def _key(self, login: str) -> str:
        return f'{self._prefix}:{login.lower()}'


class NullVerificationRateLimiter:
    async def acquire(self, login: str) -> tuple[bool, int]:  # pragma: no cover - usado em testes
        return True, 0
