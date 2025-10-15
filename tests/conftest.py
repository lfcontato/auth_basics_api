import pytest
from fastapi.testclient import TestClient

from pydantic_settings import BaseSettings, SettingsConfigDict
from auth_app.config.settings import Settings
from auth_app.config import get_settings
from auth_app.interfaces.api.app import create_application, setup_logging

# 1. Defina a classe de teste (herda as regras de carregamento do .env)
class TestSettings(Settings):
    DEPLOYMENT_ENVIRONMENT: str = 'development'
    LOG_LEVEL: str = 'DEBUG'
    # Você pode manter o model_config, mas a herança geralmente já é suficiente:
    # model_config = SettingsConfigDict(env_file='.env.test', ...) 

# 2. Defina a função de sobrescrita
def override_get_settings():
    return TestSettings()


@pytest.fixture
def client(session):
    # 3. Sobrescreva a dependência ANTES de inicializar o TestClient
    create_application.dependency_overrides[Settings] = override_get_settings
    
    # 4. Use o cliente
    with TestClient(create_application) as client:
        yield client

    # 5. Limpe a sobrescrita
    create_application.dependency_overrides.clear()
