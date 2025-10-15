# caminho: auth_app/interfaces/api/routers/auth.py
# Funções:
# - Endpoints de autenticação (login, refresh, verify)

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, status

from auth_app.application.admins.dto import (
    AdminMessageResponse,
    AdminProtectedVerificationRequest,
    AdminPasswordRecoveryRequest,
    AdminVerificationRequest,
)
from auth_app.application.admins.use_cases import AdminService
from auth_app.interfaces.api.dependencies import get_admin_service
from auth_app.shared.auth_dependencies import require_authenticated_admin

router = APIRouter(prefix='/admin/auth', tags=['auth'])


@router.post(
    '/token',
    status_code=status.HTTP_200_OK,
    summary='Emitir tokens',
    description="""Realiza autenticação via formulário (`username`/`password`) e retorna par de tokens JWT.

Inclui o `admin_id`, `email` e `admin=true` nas claims para consumo interno.

**Proteções**:
- Rate limit configurável via `TOKEN_ISSUE_INTERVAL_SECONDS` por login.
- Bloqueio temporário após falhas consecutivas (monitorado em Redis).
- Registro de IP/User-Agent em caso de bloqueio.
""",
)
async def issue_token(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    service: AdminService = Depends(get_admin_service),
):
    client_ip = request.headers.get('x-forwarded-for', request.client.host if request.client else '')
    user_agent = request.headers.get('user-agent', '')
    return await service.issue_token(username, password, client_ip=client_ip or '', user_agent=user_agent)


@router.post(
    '/token/refresh',
    status_code=status.HTTP_200_OK,
    summary='Renovar tokens',
    description="""Recebe um refresh token válido e emite novo par access/refresh.

Revoga a sessão anterior e cria uma nova, mantendo o `family_id` para auditoria.

**Proteções**:
- Rate limit configurável via `TOKEN_REFRESH_INTERVAL_SECONDS` por sessão/login.
- Bloqueio temporário da sessão quando o hash não confere.
""",
)
async def refresh_token(
    request: Request,
    refresh_token: str = Form(...),
    service: AdminService = Depends(get_admin_service),
):
    client_ip = request.headers.get('x-forwarded-for', request.client.host if request.client else '')
    user_agent = request.headers.get('user-agent', '')
    return await service.refresh_token(refresh_token, client_ip=client_ip or '', user_agent=user_agent)


@router.post(
    '/verify',
    response_model=AdminMessageResponse,
    status_code=status.HTTP_200_OK,
    summary='Confirmar conta (API protegida)',
    description="""Valida o código de verificação informado para o administrador autenticado.

Retorna mensagens claras para cenários de link expirado, já utilizado ou inválido.

**Proteções**:
- Exige Bearer token válido (apenas admins autenticados).
- Respeita rate limit do envio de códigos e bloqueios temporários configurados.
""",
)
async def verify_admin(
    payload: AdminProtectedVerificationRequest,
    current_admin=Depends(require_authenticated_admin),
    service: AdminService = Depends(get_admin_service),
) -> AdminMessageResponse:
    admin_id = int(current_admin['admin_id'])
    request_payload = AdminVerificationRequest(admin_id=admin_id, verification_code=payload.verification_code)
    return await service.verify_admin(request_payload)


@router.get(
    '/verify-link',
    response_model=AdminMessageResponse,
    status_code=status.HTTP_200_OK,
    summary='Confirmar conta via link',
    description="""Endpoint consumido pelo link enviado por e-mail.

Aceita os parâmetros `login` e `code` e responde com mensagens de sucesso ou erro conforme o estado da verificação.

**Proteções**:
- Rate limit (`VERIFY_LINK_INTERVAL_SECONDS`) por login.
- Códigos expiram após `VERIFICATION_CODE_EXPIRE_SECONDS`.
""",
)
async def verify_admin_link(
    login: str,
    code: str,
    service: AdminService = Depends(get_admin_service),
) -> AdminMessageResponse:
    payload = AdminVerificationRequest(login=login, verification_code=code)
    return await service.verify_admin(payload)


@router.post(
    '/password-recovery',
    response_model=AdminMessageResponse,
    status_code=status.HTTP_200_OK,
    summary='Recuperar senha',
    description="""Permite redefinir a senha informando e-mail e nova senha.

Sem `recovery_token` no payload, gera um token temporário (via e-mail) respeitando o rate limit `PASSWORD_RECOVERY_INTERVAL_SECONDS`. Com token válido, redefine a senha e envia e-mail de confirmação.

**Proteções**:
- Tokens expiram em `PASSWORD_RECOVERY_TOKEN_EXPIRE_SECONDS` e são validados no Redis.
- Rate limit configurável por e-mail.
- E-mail transacional de confirmação após alteração.
""",
)
async def recover_password(
    payload: AdminPasswordRecoveryRequest,
    service: AdminService = Depends(get_admin_service),
) -> AdminMessageResponse:
    return await service.recover_password(payload)
