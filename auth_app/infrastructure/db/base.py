# caminho: auth_app/infrastructure/db/base.py
# Funções:
# - create_async_engine_settings(): configura engine async do SQLAlchemy
# - get_session(): fornece AsyncSession via FastAPI Depends

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import registry
from sqlalchemy.pool import QueuePool, NullPool 

from auth_app.config import get_settings

mapper_registry = registry()
Base = mapper_registry.generate_base()

def create_async_engine_settings():
    settings = get_settings()

    # Define o timeout de conexão/comando para o driver asyncpg (30 segundos como padrão)
    connect_args = {
        # Aumente este valor se a conexão cair durante a migração longa
        "timeout": 60,  
        # Pode ser necessário para alguns ambientes cloud/serviços de proxy
        # "ssl": "require" 
    }
    
    engine = create_async_engine(
        settings.DATABASE_URL,
        
        # Parâmetros do Pool
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT_S,
        ssl=settings.POSTGRES_SSL_MODE if hasattr(settings, 'POSTGRES_SSL_MODE') else 'disable',
        
        # 🚨 SOLUÇÃO DE CONEXÃO: Verifica a conexão antes de usar, forçando a reabertura se cair
        pool_pre_ping=True, 
        
        # 🚨 REMOÇÃO/AJUSTE: pool_recycle não é ideal em ambientes com timeout de rede
        # Mantenha pool_recycle=1800 se você souber que o DB fecha conexões inativas.
        # Caso contrário, definir como -1 ou remover pode ser melhor. 
        # Vamos manter o seu valor, mas confie no pool_pre_ping para a recuperação.
        pool_recycle=1800, 
        
        # 🚨 NOVO: Passa o timeout de comando/conexão para o driver asyncpg
        connect_args=connect_args,
        
        # 🚨 OPCIONAL: Use NullPool para scripts Alembic que não usam o pool continuamente
        # poolclass=NullPool 
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
        # await session.close()
        pass
