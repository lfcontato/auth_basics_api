# caminho: auth_app/settings.py
# Conteúdo:
# - Settings: carrega configurações do .env com validações/tipos
# - Montagem automática do DATABASE_URL (se não vier no .env)
# - Constantes de conveniência para import direto (REDIS_URL, DATABASE_URL, etc.)

from __future__ import annotations

from typing import Literal, Optional

from pydantic import AliasChoices, EmailStr, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Carrega variáveis de ambiente do .env com defaults sensatos e validações."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # -------------------------------------------------------------------------
    # Sistema / Log
    # -------------------------------------------------------------------------
    DEPLOYMENT_ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    LOG_LEVEL: Literal["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "FATAL"] = "WARNING"

    # -------------------------------------------------------------------------
    # Postgres
    # - Se DATABASE_URL não for informado, é montado a partir dos campos abaixo
    # -------------------------------------------------------------------------
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "auth_app"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: SecretStr = SecretStr("postgres")

    DATABASE_URL: Optional[str] = Field(
        default=None,
        description="Ex.: postgresql+asyncpg://user:pass@host:5432/db",
        validation_alias=AliasChoices("DATABASE_URL"),
    )

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def build_database_url_if_missing(cls, v, info):
        """Monta postgresql+asyncpg://... a partir das partes quando não vier pronto no .env."""
        if v and isinstance(v, str) and v.strip():
            # Garantir que o esquema esteja correto
            if not v.startswith("postgresql+asyncpg://"):
                raise ValueError("DATABASE_URL deve usar o esquema 'postgresql+asyncpg://'.")
            return v

        # Monta a URL a partir dos campos individuais
        data = info.data
        user = data.get("POSTGRES_USER", "postgres")
        pwd = data.get("POSTGRES_PASSWORD", SecretStr("postgres"))
        host = data.get("POSTGRES_HOST", "localhost")
        port = data.get("POSTGRES_PORT", 5432)
        db = data.get("POSTGRES_DB", "auth_app")

        return f"postgresql+asyncpg://{user}:{pwd.get_secret_value()}@{host}:{port}/{db}"

    # -------------------------------------------------------------------------
    # Redis
    # -------------------------------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 40
    DB_POOL_TIMEOUT_S: float = 30.0    

    # -------------------------------------------------------------------------
    # OpenTelemetry
    # -------------------------------------------------------------------------
    OTEL_SERVICE_NAME: str = "auth_app"
    OTEL_RESOURCE_ATTRIBUTES: str = "service.version=0.1.0,deployment.environment=development"
    OTEL_EXPORTER_OTLP_ENDPOINT: str = "http://localhost:4317"
    OTEL_EXPORTER_OTLP_INSECURE: bool = True
    OTEL_EXPORTER_OTLP_PROTOCOL: Literal["grpc", "http/protobuf"] = "grpc"

    # Flags de instrumentação/logging do OTEL (strings/bools comuns no .env)
    OTEL_PYTHON_LOGGING_AUTO_INSTRUMENTATION_ENABLED: bool = True
    OTEL_PYTHON_LOG_CORRELATION: bool = True
    OTEL_LOGS_EXPORTER: Literal["otlp", "none"] = "otlp"
    OTEL_METRICS_EXPORTER: Literal["otlp", "none"] = "otlp"
    OTEL_TRACES_EXPORTER: Literal["otlp", "none"] = "otlp"

    OTEL_EXPORTER_OTLP_LOGS_TIMEOUT: int = 10000
    OTEL_LOG_LEVEL: Literal["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"] = "WARN"
    OTEL_PYTHON_LOG_LEVEL: Literal["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "FATAL"] = "WARNING"
    OTEL_METRIC_EXPORT_INTERVAL: int = 5000
    OTEL_TRACES_SAMPLER: str = "parentbased_always_on"

    # -------------------------------------------------------------------------
    # Paginação
    # -------------------------------------------------------------------------
    PAGINATION_LIMIT: int = 20
    PAGINATION_MAX_LIMIT: int = 100

    # -------------------------------------------------------------------------
    # Token / Segurança de autenticação
    # -------------------------------------------------------------------------
    SECRET_KEY: SecretStr = SecretStr("a-string-secret-at-least-256-bits-long")
    SECRET_ALGORITHM: str = "HS256"
    TOKEN_ACCESS_EXPIRE_SECONDS: int = 1800
    TOKEN_REFRESH_EXPIRE_SECONDS: int = 2_592_000  # 30 dias
    VERIFICATION_CODE_LENGTH: int = 4
    VERIFICATION_CODE_EXPIRE_SECONDS: int = 300

    TOKEN_ISSUE_INTERVAL_SECONDS: int = 5
    TOKEN_REFRESH_INTERVAL_SECONDS: int = 5
    VERIFY_LINK_INTERVAL_SECONDS: int = 5

    # -------------------------------------------------------------------------
    # SMTP / E-mail
    # -------------------------------------------------------------------------
    EMAIL_SERVER_USERNAME: EmailStr = "noreply@example.com"
    EMAIL_SERVER_NAME: str = "blockmap"
    EMAIL_SERVER_PASSWORD: SecretStr = SecretStr("changeme")
    EMAIL_SERVER_SMTP_HOST: str = "email-ssl.com.br"
    EMAIL_SERVER_SMTP_PORT: int = 465
    EMAIL_SERVER_SMTP_ENCRYPTION: Literal["SSL/TLS", "STARTTLS"] = "SSL/TLS"

    EMAIL_SERVER_TEMPLATE_DIR: str = "template_email"
    EMAIL_TEMPLATE_NAME: str = "email_notifications.html"
    SECURITY_TEMPLATE_NAME: str = "security_notifications.html"

    EMAIL_FROM_ADDRESS: EmailStr = "noreply@example.com"
    EMAIL_FROM_NAME: str = "blockmap"
    EMAIL_CC_ADDRESSES: str = ""
    EMAIL_BCC_ADDRESSES: str = ""

    EMAIL_SUBJECT: str = "Confirme seu acesso à plataforma BlockMap"
    EMAIL_VERIFICATION_SUBJECT: str = "Confirme seu acesso à plataforma BlockMap"
    SECURITY_EMAIL_SUBJECT: str = "Alerta de segurança - BlockMap"
    PASSWORD_RECOVERY_SUBJECT: str = "Redefinição de senha - BlockMap"
    PASSWORD_CHANGED_SUBJECT: str = "Senha atualizada - BlockMap"

    EMAIL_BODY: str = "Corpo da mensagem ou caminho para um template."
    EMAIL_VERIFICATION_LINK_BASE: str = "http://localhost:8000/admin/auth/verify-link"

    # -------------------------------------------------------------------------
    # Usuário inicial
    # -------------------------------------------------------------------------
    ROOT_AUTH_USER: str = "admin"
    ROOT_AUTH_EMAIL: EmailStr = "admin@example.com"
    ROOT_AUTH_PASSWORD: SecretStr = SecretStr("stringst")

    # -------------------------------------------------------------------------
    # Segurança adicional
    # -------------------------------------------------------------------------
    SECURITY_BLOCK_DURATION_SECONDS: int = 900
    SECURITY_MAX_LOGIN_FAILURES: int = 5
    SECURITY_MAX_PASSWORD_CHANGE_FAILURES: int = 3
    VERIFICATION_RESEND_INTERVAL_SECONDS: int = 60
    VERIFICATION_CODE_THROTTLE_SECONDS: int = 60
    PASSWORD_RECOVERY_TEMPLATE_NAME: str = "password_recovery.html"
    PASSWORD_CHANGED_TEMPLATE_NAME: str = "password_changed.html"
    PASSWORD_RECOVERY_INTERVAL_SECONDS: int = 300
    PASSWORD_RECOVERY_TOKEN_EXPIRE_SECONDS: int = 1800
    PASSWORD_RECOVERY_LINK_BASE: str = ""

    # -------------------------------------------------------------------------
    # Conveniências derivadas
    # -------------------------------------------------------------------------
    @property
    def POSTGRES_DSN_SAFE(self) -> str:
        """Retorna o DSN sem a senha (útil para logs)."""
        return self.DATABASE_URL.replace(
            f":{self.POSTGRES_PASSWORD.get_secret_value()}@", ":***@", 1
        )




    
    
