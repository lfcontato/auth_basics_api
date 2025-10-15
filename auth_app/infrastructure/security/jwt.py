# caminho: auth_app/infrastructure/security/jwt.py
# Funções:
# - JWTService: gera e valida tokens JWT (access e refresh)

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from jwt import DecodeError, ExpiredSignatureError, InvalidTokenError, decode, encode


@dataclass(slots=True)
class RefreshPayload:
    subject: str
    email: str | None
    session_id: str
    system_role: str | None


class JWTService:
    def __init__(self, secret_key: str, algorithm: str) -> None:
        self._secret = secret_key
        self._algorithm = algorithm

    def create_access_token(
        self,
        subject: str,
        email: str,
        admin_id: int,
        system_role: str,
        expires_seconds: int,
    ) -> str:
        return self._encode(
            data={
                'sub': subject,
                'email': email,
                'admin': True,
                'admin_id': admin_id,
                'system_role': system_role,
            },
            expires_seconds=expires_seconds,
        )

    def create_refresh_token(
        self,
        subject: str,
        email: str,
        session_id: str,
        system_role: str,
        expires_seconds: int,
    ) -> str:
        return self._encode(
            data={
                'sub': subject,
                'email': email,
                'admin': True,
                'sid': session_id,
                'system_role': system_role,
            },
            expires_seconds=expires_seconds,
        )

    def decode_refresh_token(self, token: str) -> RefreshPayload:
        try:
            payload = decode(token, self._secret, algorithms=[self._algorithm])
        except ExpiredSignatureError:  # pragma: no cover - validado externamente
            raise
        except (InvalidTokenError, DecodeError):  # pragma: no cover - validado externamente
            raise

        return RefreshPayload(
            subject=str(payload.get('sub', '')),
            email=payload.get('email'),
            session_id=str(payload.get('sid', '')),
            system_role=payload.get('system_role'),
        )

    def _encode(self, data: dict, expires_seconds: int) -> str:
        payload = {
            **data,
            'exp': datetime.now(timezone.utc) + timedelta(seconds=expires_seconds),
        }
        secret_key = self._secret.get_secret_value()
        return encode(payload, secret_key, algorithm=self._algorithm)    
