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

    PROJECT_NAME: str = 'auth-app'
    PROJECT_VERSION: str = '0.1.0'
    PROJECT_DESCRIPTION: str = 'description project'

    DATABASE_URL: str = 'postgresql+asyncpg://postgres:postgres@localhost:5432/auth_app'
    REDIS_URL: str = 'redis://localhost:6379/0'
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 40
    DB_POOL_TIMEOUT_S: float = 30.0

    OTEL_SERVICE_NAME: str = 'auth-app'
    OTEL_EXPORTER_OTLP_ENDPOINT: str = 'http://otel-collector:4317'
    OTEL_PYTHON_LOG_LEVEL: str = 'WARNING'
    OTEL_LOG_LEVEL: str = 'WARNING'
    LOG_LEVEL: str = 'INFO'
    EMAIL_SERVER_USERNAME: str = ''
    EMAIL_SERVER_NAME: str = ''
    EMAIL_SERVER_PASSWORD: str = ''
    EMAIL_SERVER_SMTP_HOST: str = 'localhost'
    EMAIL_SERVER_SMTP_PORT: int = 587
    EMAIL_SERVER_SMTP_ENCRYPTION: str = 'STARTTLS'
    EMAIL_SERVER_TEMPLATE_DIR: str = 'template_email'
    EMAIL_TEMPLATE_NAME: str = 'email_notifications.html'
    EMAIL_FROM_ADDRESS: str | None = None
    EMAIL_FROM_NAME: str | None = None
    EMAIL_CC_ADDRESSES: str | None = None
    EMAIL_BCC_ADDRESSES: str | None = None
    EMAIL_SUBJECT: str = 'Confirme seu e-mail'
    EMAIL_VERIFICATION_SUBJECT: str = ''
    SECURITY_EMAIL_SUBJECT: str = ''
    PASSWORD_RECOVERY_SUBJECT: str = ''
    PASSWORD_CHANGED_SUBJECT: str = ''
    EMAIL_BODY: str | None = None
    EMAIL_VERIFICATION_LINK_BASE: str = 'http://localhost:8000/auth/verify-link'

    PAGINATION_LIMIT: int = 20
    PAGINATION_MAX_LIMIT: int = 100

    SECRET_KEY: str = 'a-string-secret-at-least-256-bits-long'
    SECRET_ALGORITHM: str = 'HS256'
    TOKEN_ACCESS_EXPIRE_SECONDS: int = 1800
    TOKEN_REFRESH_EXPIRE_SECONDS: int = 2592000

    VERIFICATION_CODE_LENGTH: int = 4
    VERIFICATION_CODE_EXPIRE_SECONDS: int = 600

    ROOT_AUTH_USER: str = 'admin'
    ROOT_AUTH_EMAIL: str = 'admin@example.com'
    ROOT_AUTH_PASSWORD: str = 'stringst'

    SECURITY_BLOCK_DURATION_SECONDS: int = 900
    SECURITY_MAX_LOGIN_FAILURES: int = 5
    SECURITY_MAX_PASSWORD_CHANGE_FAILURES: int = 3
    SECURITY_TEMPLATE_NAME: str = 'security_notifications.html'
    VERIFICATION_RESEND_INTERVAL_SECONDS: int = 60
    VERIFICATION_CODE_THROTTLE_SECONDS: int = 60
    PASSWORD_RECOVERY_TEMPLATE_NAME: str = 'password_recovery.html'
    PASSWORD_CHANGED_TEMPLATE_NAME: str = 'password_changed.html'
    PASSWORD_RECOVERY_INTERVAL_SECONDS: int = 300
    PASSWORD_RECOVERY_TOKEN_EXPIRE_SECONDS: int = 1800
    PASSWORD_RECOVERY_LINK_BASE: str = ''
    TOKEN_ISSUE_INTERVAL_SECONDS: int = 5
    TOKEN_REFRESH_INTERVAL_SECONDS: int = 5
    VERIFY_LINK_INTERVAL_SECONDS: int = 5
