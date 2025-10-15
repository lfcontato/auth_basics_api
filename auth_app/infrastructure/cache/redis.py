# caminho: auth_app/infrastructure/cache/redis.py
# Funções:
# - get_redis_client(): fornece instância Redis assíncrona via FastAPI Depends

from __future__ import annotations

from collections.abc import AsyncGenerator

import redis.asyncio as redis

from auth_app.config import get_settings


async def get_redis_client() -> AsyncGenerator[redis.Redis, None]:
    settings = get_settings()
    client = redis.from_url(settings.REDIS_URL, encoding='utf-8', decode_responses=True)
    try:
        yield client
    finally:
        close = getattr(client, 'aclose', None)
        if callable(close):
            await close()
        else:  # pragma: no cover - versões antigas
            client.close()
