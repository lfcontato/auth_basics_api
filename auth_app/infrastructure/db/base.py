# caminho: auth_app/infrastructure/db/base.py
# Funções:
# - create_async_engine_settings(): configura engine async do SQLAlchemy
# - get_session(): fornece AsyncSession via FastAPI Depends

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import registry

from auth_app.config import get_settings

mapper_registry = registry()
Base = mapper_registry.generate_base()


def create_async_engine_settings():
    settings = get_settings()
    engine = create_async_engine(
        settings.DATABASE_URL,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT_S,
        pool_pre_ping=True,
        pool_recycle=1800,
    )
    return engine


engine = create_async_engine_settings()
SessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    session: AsyncSession = SessionLocal()
    try:
        yield session
        # COMMIT IMPLÍCITO (se não estiver em modo autocommit, 
        # ou se você não tiver feito rollback/commit manualmente)
    except Exception:
        # Rollback em caso de erro
        await session.rollback()
        raise
    finally:
        # Garante que a sessão está fechada e limpa
        await session.close()
