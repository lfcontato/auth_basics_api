# caminho: auth_app/config/__init__.py
# Funções:
# - get_settings(): retorna instância única de Settings

from __future__ import annotations

from functools import lru_cache

from auth_app.config.settings import Settings


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()