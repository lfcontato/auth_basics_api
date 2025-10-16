# caminho: auth_app/interfaces/api/app.py
# Funções:
# - create_application(): configura FastAPI com middlewares e rotas

from __future__ import annotations

from fastapi import FastAPI
from contextlib import asynccontextmanager

from auth_app.config import get_settings
from auth_app.interfaces.api.routers import admin, auth
from auth_app.shared.logging import setup_logging
from auth_app.shared.system_bootstrap import bootstrap_root_admin
from auth_app.shared.logging import log_info, log_warning


@asynccontextmanager
async def lifespan(app: FastAPI):
    # CÓDIGO DE INICIALIZAÇÃO (Startup)
    # AQUI VOCÊ PODE GARANTIR A EXECUÇÃO DO SEU BOOTSTRAP
    log_warning('ROOT_ADMIN_BOOTSTRAP_STARTUP', {'reason': 'lifespan'})
    await bootstrap_root_admin()
    
    yield
    
    # CÓDIGO DE DESLIGAMENTO (Shutdown)
    log_warning('APP_SHUTDOWN', {'reason': 'lifespan'})


def create_application() -> FastAPI:
    settings = get_settings()
    setup_logging(level=settings.LOG_LEVEL)

    app = FastAPI(
        title='auth-app',
        version='0.2.0',
        lifespan=lifespan
    )
    
    app.include_router(auth.router)
    app.include_router(admin.router)

    return app
