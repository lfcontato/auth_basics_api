# caminho: auth_app/config/settings.py
# Funções:
# - Settings: carrega configurações via Pydantic Settings

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
        extra='ignore',
        case_sensitive=False,
    )

    DEPLOYMENT_ENVIRONMENT: str = 'development'
    LOG_LEVEL: str = 'WARNING'
    
    
