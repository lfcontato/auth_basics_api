# caminho: auth_app/interfaces/api/app.py
# Funções:
# - create_application(): configura FastAPI com middlewares e rotas

from __future__ import annotations

from fastapi import FastAPI

from auth_app.config import get_settings
# from auth_app.interfaces.api.routers import admin, auth
from auth_app.shared.logging import setup_logging
# from auth_app.shared.system_bootstrap import bootstrap_root_admin


def create_application() -> FastAPI:
    settings = get_settings()
    setup_logging(level=settings.LOG_LEVEL)
    app = FastAPI(
        title='auth-app',
        version='0.2.0',
    )
    # app.include_router(auth.router)
    # app.include_router(admin.router)

    # @app.on_event('startup')
    # async def _bootstrap_root_admin() -> None:  # pragma: no cover - efeito colateral na inicialização
    #     await bootstrap_root_admin()

    return app
