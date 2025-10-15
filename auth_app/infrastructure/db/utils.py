# caminho: auth_app/infrastructure/db/utils.py
# Funções:
# - try_flush(), try_commit(): auxiliares para flush/commit com rollback seguro

from __future__ import annotations

from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession


async def try_flush(session: AsyncSession) -> None:
    try:
        await session.flush()
    except (DBAPIError, SQLAlchemyError):  # pragma: no cover
        await session.rollback()
        raise


async def try_commit(session: AsyncSession) -> None:
    try:
        await session.commit()
    except (DBAPIError, SQLAlchemyError):  # pragma: no cover
        await session.rollback()
        raise
