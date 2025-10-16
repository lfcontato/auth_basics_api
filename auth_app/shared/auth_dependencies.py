# caminho: auth_app/shared/auth_dependencies.py
# Funções:
# - require_authenticated_admin(): valida Bearer token e retorna claims basicos

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt import DecodeError, ExpiredSignatureError, InvalidTokenError, decode

from auth_app.config import get_settings

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/admin/auth/token')

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl='/admin/auth/token',
    auto_error=False # <-- CHAVE: Desativa o erro automático do FastAPI
)



async def require_authenticated_admin(token: str = Depends(oauth2_scheme)) -> dict[str, str]:
    settings = get_settings()
    try:
        payload = decode(token, settings.SECRET_KEY.get_secret_value(), algorithms=[settings.SECRET_ALGORITHM])
    except ExpiredSignatureError as exc:  # pragma: no cover - tratado em endpoints
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='TOKEN_EXPIRED') from exc
    except (InvalidTokenError, DecodeError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='INVALID_TOKEN') from exc

    if not payload.get('admin'):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='NOT_ADMIN')

    admin_id = payload.get('admin_id')
    try:
        admin_id_int = int(admin_id)
    except (TypeError, ValueError) as exc:  # pragma: no cover - garante consistência do token
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='INVALID_ADMIN') from exc

    system_role = (payload.get('system_role') or '').lower()
    if not system_role:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='INVALID_SYSTEM_ROLE')

    return {
        'username': payload.get('sub', ''),
        'email': payload.get('email', ''),
        'admin_id': admin_id_int,
        'system_role': system_role,
    }
