# caminho: auth_app/interfaces/api/routers/admin.py
# Funções:
# - CRUD e verificação de admins via FastAPI

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status

# DTO  - Objeto de Transferência de Dados
from auth_app.application.admins.dto import (
    AdminCreateInput,
    AdminChangeEmailRequest,
    AdminChangePasswordRequest,
    AdminMessageResponse,
    AdminOutput,
    AdminResendVerificationRequest,
    AdminUnlockStatusResponse,
    AdminUnlockRequest,
    AdminVerificationResponse,
    AdminListResponse,
)
from auth_app.application.admins.use_cases import AdminService
from auth_app.config import get_settings
from auth_app.interfaces.api.dependencies import get_admin_service
from auth_app.shared.auth_dependencies import require_authenticated_admin

router = APIRouter(prefix='/admin', tags=['admin'])


@router.post(
    '/',
    response_model=AdminOutput,
    status_code=status.HTTP_201_CREATED,
    summary='Criar administrador',
    description="""Cria um novo administrador com credenciais iniciais, contatos opcionais e gera um código de verificação.

    **Fluxo**:
    1. Valida unicidade de `email` e `username`.
    2. Persiste o admin, contatos e código de verificação.
    3. Dispara e-mail de confirmação (canal fixo `email`).

    **Proteções**:
    - Apenas usuários `system_role=root` podem criar novas contas.
    - Código inicial tem expiração (`VERIFICATION_CODE_EXPIRE_SECONDS`).
    """,
)
async def create_admin(
    payload: AdminCreateInput,
    current_admin=Depends(require_authenticated_admin),
    service: AdminService = Depends(get_admin_service),
) -> AdminOutput:
    acting_admin_id = int(current_admin['admin_id'])
    acting_system_role = current_admin['system_role']
    return await service.create_admin(
        payload,
        acting_admin_id=acting_admin_id,
        acting_system_role=acting_system_role,
    )


@router.get(
    '/',
    response_model=AdminListResponse,
    summary='Listar administradores',
    description="""Retorna administradores paginados em ordem crescente de `id`.

Use os parâmetros `offset` e `limit` para navegar entre páginas.

**Proteções**:
- Exige autenticação Bearer.
- Retorna apenas registros que o solicitante pode gerenciar (hierarquia `system_role`).
""",
)
async def list_admins(
    offset: int = Query(0, ge=0),
    limit: int = Query(get_settings().PAGINATION_LIMIT, ge=1, le=get_settings().PAGINATION_MAX_LIMIT),
    current_admin=Depends(require_authenticated_admin),
    service: AdminService = Depends(get_admin_service),
) -> AdminListResponse:
    acting_admin_id = int(current_admin['admin_id'])
    admins = await service.list_admins(offset, limit, acting_admin_id)
    return AdminListResponse(offset=offset, limit=limit, items=list(admins))


@router.get(
    '/{admin_id}',
    response_model=AdminOutput,
    summary='Detalhar administrador',
    description="""Busca um administrador específico pelo `admin_id`.

Retorna 404 quando o registro não existe.

**Proteções**:
- Exige autenticação Bearer.
- Apenas admins com `system_role` superior podem visualizar outros registros.
""",
)
async def get_admin(
    admin_id: int,
    current_admin=Depends(require_authenticated_admin),
    service: AdminService = Depends(get_admin_service),
) -> AdminOutput:
    acting_admin_id = int(current_admin['admin_id'])
    return await service.get_admin(admin_id, acting_admin_id)


@router.delete(
    '/{admin_id}',
    status_code=status.HTTP_204_NO_CONTENT,
    summary='Remover administrador',
    description="""Exclui o administrador informado e seus contatos associados.

Retorna 404 caso o registro já tenha sido removido.

**Proteções**:
- Exige autenticação Bearer.
- Impede autoexclusão e remoção de papéis superiores.
""",
)
async def delete_admin(
    admin_id: int,
    current_admin=Depends(require_authenticated_admin),
    service: AdminService = Depends(get_admin_service),
) -> None:
    acting_admin_id = int(current_admin['admin_id'])
    await service.delete_admin(admin_id, acting_admin_id)


@router.post(
    '/verification-code',
    response_model=AdminVerificationResponse,
    summary='Reenviar código de verificação',
    description="""Regenera o código de verificação para o administrador informado via `email`.

Se `channel` não for enviado, reaproveita o último canal registrado. Disponível apenas para contas ainda não verificadas.

**Proteções**:
- Rate limit (`VERIFICATION_RESEND_INTERVAL_SECONDS`) e throttle enquanto o código atual está válido.
- Envia e-mail de verificação e registra tentativa no log.
""",
)
async def resend_verification(
    payload: AdminResendVerificationRequest,
    service: AdminService = Depends(get_admin_service),
) -> AdminVerificationResponse:
    return await service.resend_verification_code(payload)


@router.patch(
    '/password',
    response_model=AdminMessageResponse,
    status_code=status.HTTP_200_OK,
    summary='Alterar senha',
    description="""Permite ao próprio administrador trocar a senha.

**Regras**:
- Necessário informar a senha atual correta.
- Nova senha deve ser confirmada e diferente da atual.
- Disponível apenas para o usuário autenticado dono do recurso.

**Proteções**:
- Rate limit/lock por falhas consecutivas monitorado em Redis.
- E-mail de confirmação enviado após alteração.
""",
)
async def change_password(
    request: Request,
    payload: AdminChangePasswordRequest,
    current_admin=Depends(require_authenticated_admin),
    service: AdminService = Depends(get_admin_service),
) -> AdminMessageResponse:
    acting_admin_id = int(current_admin['admin_id'])
    client_ip = request.headers.get('x-forwarded-for', request.client.host if request.client else '')
    user_agent = request.headers.get('user-agent', '')
    return await service.change_password(
        acting_admin_id,
        payload,
        acting_admin_id,
        client_ip=client_ip or '',
        user_agent=user_agent,
    )


@router.patch(
    '/email',
    response_model=AdminOutput,
    status_code=status.HTTP_200_OK,
    summary='Alterar e-mail',
    description="""Atualiza o e-mail do administrador autenticado e reinicia o processo de verificação.

Após a alteração:
1. `is_verified` volta para `false`.
2. Um novo código é gerado.
3. Um e-mail de confirmação é enviado automaticamente.
""",
)
async def change_email(
    payload: AdminChangeEmailRequest,
    current_admin=Depends(require_authenticated_admin),
    service: AdminService = Depends(get_admin_service),
) -> AdminOutput:
    acting_admin_id = int(current_admin['admin_id'])
    return await service.change_email(acting_admin_id, payload, acting_admin_id)


@router.post(
    '/unlock',
    response_model=AdminMessageResponse,
    summary='Desbloquear administrador',
    description="""Remove bloqueios temporários aplicados por tentativas malsucedidas.

Disponível apenas para administradores com `system_role` igual a `root` ou `admin` e requer informar o e-mail da conta alvo.
""",
)
async def unlock_admin(
    payload: AdminUnlockRequest,
    current_admin=Depends(require_authenticated_admin),
    service: AdminService = Depends(get_admin_service),
) -> AdminMessageResponse:
    acting_admin_id = int(current_admin['admin_id'])
    acting_system_role = current_admin['system_role']
    return await service.unlock_admin(payload.email, acting_admin_id, acting_system_role)


@router.post(
    '/{admin_id}/password-recovery',
    response_model=AdminMessageResponse,
    summary='Disparar recuperação de senha',
    description="""Gera e envia o token de recuperação de senha para o administrador informado.

**Fluxo**:
- Respeita o rate limit `PASSWORD_RECOVERY_INTERVAL_SECONDS`.
- Envia e-mail contendo token e link (quando configurado) para redefinição.
""",
)
async def trigger_password_recovery(
    admin_id: int,
    current_admin=Depends(require_authenticated_admin),
    service: AdminService = Depends(get_admin_service),
) -> AdminMessageResponse:
    acting_admin_id = int(current_admin['admin_id'])
    acting_system_role = current_admin['system_role']
    return await service.trigger_password_recovery(admin_id, acting_admin_id, acting_system_role)


@router.get(
    '/unlock',
    response_model=AdminUnlockStatusResponse,
    summary='Consultar bloqueios do administrador',
    description="""Retorna o estado de bloqueio (login e troca de senha) associado ao e-mail informado.

Disponível para `system_role` igual a `root` ou `admin`.""",
)
async def get_unlock_status(
    email: str,
    current_admin=Depends(require_authenticated_admin),
    service: AdminService = Depends(get_admin_service),
) -> AdminUnlockStatusResponse:
    acting_admin_id = int(current_admin['admin_id'])
    acting_system_role = current_admin['system_role']
    return await service.get_unlock_status(email, acting_admin_id, acting_system_role)


@router.get(
    '/unlock/all',
    response_model=list[AdminUnlockStatusResponse],
    summary='Listar bloqueios ativos',
    description='Retorna todos os bloqueios temporários registrados no Redis para administradores.',
)
async def list_unlock_status(
    current_admin=Depends(require_authenticated_admin),
    service: AdminService = Depends(get_admin_service),
) -> list[AdminUnlockStatusResponse]:
    acting_admin_id = int(current_admin['admin_id'])
    acting_system_role = current_admin['system_role']
    return await service.list_unlock_status(acting_admin_id, acting_system_role)
