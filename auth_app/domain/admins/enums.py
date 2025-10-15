# caminho: auth_app/domain/admins/enums.py
# Funções:
# - Define os value objects de papéis, planos e status de conta dos administradores.
# - Fornece utilitários para obter escolhas, defaults e ordenação hierárquica.

from __future__ import annotations

from typing import Annotated, Any, Literal, Sequence, get_args, get_origin

from pydantic import Field, StringConstraints

SC = StringConstraints
LowerStr = SC(strip_whitespace=True, to_lower=True)


def _choices_from_annotated_literal(annotation: Any) -> tuple[str, ...]:
    """Extrai as opções de um tipo Annotated que contém um Literal."""
    if get_origin(annotation) is Literal:
        literal = annotation
    else:
        literal = next((arg for arg in get_args(annotation) if get_origin(arg) is Literal), None)
    if literal is None:
        msg = f'Annotation {annotation!r} does not include a typing.Literal.'
        raise TypeError(msg)
    return tuple(str(value) for value in get_args(literal))


# ─────────────────────────────────────────────────────────────────────────────
# Papéis de permissão — Sistema (escopo global)
# Representa o papel do usuário no sistema como um todo (login/conta).
# Ordem de privilégio: guest < user < admin < root.
# Use para gates globais (ex.: acessar painel admin).
# ─────────────────────────────────────────────────────────────────────────────
SystemRole = Annotated[
    str,
    Literal['guest', 'user', 'admin', 'root'],
    LowerStr,
]
SYSTEM_ROLE_CHOICES: tuple[str, ...] = _choices_from_annotated_literal(SystemRole)
SYSTEM_ROLE_DEFAULT: str = 'guest'
SYSTEM_ROLE_PRIORITY: dict[str, int] = {role: idx for idx, role in enumerate(SYSTEM_ROLE_CHOICES)}
SYSTEM_ROLE_SUPERUSER: str = 'root'


# ─────────────────────────────────────────────────────────────────────────────
# Papéis de permissão — Recurso (escopo local/ACL)
# Representa o papel do membro dentro de um recurso específico.
# Ordem de privilégio: viewer < editor < admin < owner.
# ─────────────────────────────────────────────────────────────────────────────
ResourceRole = Annotated[
    str,
    Literal['viewer', 'editor', 'admin', 'owner'],
    LowerStr,
]
RESOURCE_ROLE_CHOICES: tuple[str, ...] = _choices_from_annotated_literal(ResourceRole)
RESOURCE_ROLE_DEFAULT: str = 'viewer'


# ─────────────────────────────────────────────────────────────────────────────
# Planos de assinatura
# Define o ciclo/estado do plano. 'trial' é temporário; os demais são ciclos.
# ─────────────────────────────────────────────────────────────────────────────
SubscriptionPlan = Annotated[
    str,
    Literal['trial', 'monthly', 'semiannual', 'annual', 'lifetime'],
    LowerStr,
]
SUBSCRIPTION_PLAN_CHOICES: tuple[str, ...] = _choices_from_annotated_literal(SubscriptionPlan)
SUBSCRIPTION_PLAN_DEFAULT: str = 'trial'


# ─────────────────────────────────────────────────────────────────────────────
# Status da Conta (escopo global)
# Define o estado de autenticação/uso da conta no sistema (vale para qualquer
# papel, inclusive admin). Apenas 'active' permite login normal.
# locked = bloqueio temporário por segurança; suspended = bloqueio administrativo
# reversível; disabled/archived/deleted = sem acesso (políticas de retenção).
# ─────────────────────────────────────────────────────────────────────────────
AccountStatus = Annotated[
    str,
    Literal[
        'invited',
        'pending_verification',
        'active',
        'password_reset_required',
        'locked',
        'suspended',
        'disabled',
        'archived',
        'deleted',
    ],
    LowerStr,
    Field(description='Estado global da conta; controla se o usuário pode autenticar e operar.'),
]
ACCOUNT_STATUS_CHOICES: tuple[str, ...] = _choices_from_annotated_literal(AccountStatus)
ACCOUNT_STATUS_DEFAULT: str = None

# contact_type: Literal['email', 'sms', 'whatsapp', 'telegram', 'phone', 'other'] = 'email'

ContactType = Annotated[
    str,
    Literal['email', 'sms', 'whatsapp', 'telegram', 'phone', 'other'],
    LowerStr,
]

CONTACT_TYPE_CHOICES: tuple[str, ...] = _choices_from_annotated_literal(ContactType)
CONTACT_TYPE_DEFAULT: str = None


def managed_system_roles(role: str) -> Sequence[str]:
    """Retorna os papéis que podem ser administrados por alguém com o papel informado."""
    role_key = role.lower()
    if role_key == SYSTEM_ROLE_SUPERUSER:
        return SYSTEM_ROLE_CHOICES
    priority = SYSTEM_ROLE_PRIORITY.get(role_key)
    if priority is None:
        return ()
    return tuple(candidate for candidate, value in SYSTEM_ROLE_PRIORITY.items() if value < priority)


def can_manage_system_role(acting_role: str, target_role: str) -> bool:
    """Determina se o papel `acting_role` pode gerenciar `target_role`."""
    acting = acting_role.lower()
    target = target_role.lower()
    if acting == SYSTEM_ROLE_SUPERUSER:
        return True
    acting_priority = SYSTEM_ROLE_PRIORITY.get(acting)
    target_priority = SYSTEM_ROLE_PRIORITY.get(target)
    if acting_priority is None or target_priority is None:
        return False
    return acting_priority > target_priority
