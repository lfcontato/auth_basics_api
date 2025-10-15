# caminho: auth_app/application/admins/dto.py
# Funções:
# - DTOs Pydantic para entrada/saída de casos de uso de Admin

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator

from auth_app.config.constants import (
    PASSWORD_LENGTH_MIN, 
    PASSWORD_LENGTH_MAX, 
    VERIFICATION_CODE_LENGTH_MIN, 
    VERIFICATION_CODE_LENGTH_MAX,
    USERNAME_LENGTH_MIN,
    USERNAME_LENGTH_MAX
)


from auth_app.domain.admins.enums import (
    AccountStatus,
    ACCOUNT_STATUS_DEFAULT,
    ResourceRole,
    RESOURCE_ROLE_DEFAULT,
    SubscriptionPlan,
    SUBSCRIPTION_PLAN_DEFAULT,
    SystemRole,
    SYSTEM_ROLE_DEFAULT,
    ContactType,
    CONTACT_TYPE_DEFAULT
)


class AdminContactInput(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)

    contact_type: Optional[ContactType] = Field(default=CONTACT_TYPE_DEFAULT)
    contact_value: str = Field(min_length=3, max_length=128)
    is_main: bool = False


class AdminCreateInput(BaseModel):
    model_config = ConfigDict(extra='forbid', populate_by_name=True)

    email: EmailStr
    password: str = Field(min_length=PASSWORD_LENGTH_MIN, max_length=PASSWORD_LENGTH_MAX)
    username: str = Field(min_length=USERNAME_LENGTH_MIN, max_length=USERNAME_LENGTH_MAX)
    system_role: SystemRole = Field(default=SYSTEM_ROLE_DEFAULT)
    resource_role: ResourceRole = Field(default=RESOURCE_ROLE_DEFAULT)
    subscription_plan: SubscriptionPlan = Field(default=SUBSCRIPTION_PLAN_DEFAULT)
    account_status: Optional[AccountStatus] = Field(default=ACCOUNT_STATUS_DEFAULT)
    contacts: list[AdminContactInput] = Field(default_factory=list)
    verification_channel: Optional[ContactType] = Field(default=CONTACT_TYPE_DEFAULT)


class AdminOutput(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    username: str
    owner_id: int
    system_role: SystemRole
    resource_role: ResourceRole
    subscription_plan: SubscriptionPlan
    account_status: AccountStatus
    is_verified: bool
    verification_channel: Optional[str]


class AdminListResponse(BaseModel):
    offset: int
    limit: int
    items: list[AdminOutput]


class AdminTokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal['bearer'] = 'bearer'
    expires_in: int
    refresh_expires_in: int


class AdminVerificationBase(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)

    verification_code: str = Field(min_length=VERIFICATION_CODE_LENGTH_MIN, max_length=VERIFICATION_CODE_LENGTH_MAX)


class AdminProtectedVerificationRequest(AdminVerificationBase):
    # Não precisa repetir model_config nem verification_code
    pass


class AdminVerificationRequest(AdminVerificationBase):
    login: Optional[str] = Field(default=None, min_length=4, max_length=254)
    admin_id: Optional[int] = Field(default=None, ge=1)



class AdminVerificationResponse(BaseModel):
    admin_id: int
    channel: Optional[str]
    expires_at: datetime


class AdminResendVerificationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)

    email: EmailStr
    channel: Optional[str] = Field(default=None, max_length=32)


class AdminChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)

    current_password: str = Field(min_length=PASSWORD_LENGTH_MIN, max_length=PASSWORD_LENGTH_MAX)
    new_password: str = Field(min_length=PASSWORD_LENGTH_MIN, max_length=PASSWORD_LENGTH_MAX)
    new_password_confirm: str = Field(min_length=PASSWORD_LENGTH_MIN, max_length=PASSWORD_LENGTH_MAX)


class AdminChangeEmailRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)

    new_email: EmailStr


class AdminUnlockRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)

    email: EmailStr


class AdminUnlockStatusResponse(BaseModel):
    email: EmailStr
    is_blocked_login: bool
    is_blocked_password: bool
    login_retry_in_seconds: int | None = None
    password_retry_in_seconds: int | None = None
    last_ip: str | None = None
    user_agent: str | None = None
    blocked_at: str | None = None


class AdminPasswordRecoveryRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)

    email: EmailStr
    recovery_token: Optional[str] = Field(default=None, min_length=8, max_length=256)
    new_password: Optional[str] = Field(min_length=PASSWORD_LENGTH_MIN, max_length=PASSWORD_LENGTH_MAX)
    new_password_confirm: Optional[str] = Field(min_length=PASSWORD_LENGTH_MIN, max_length=PASSWORD_LENGTH_MAX)

    @model_validator(mode='after')
    def _validate_payload(self) -> 'AdminPasswordRecoveryRequest':
        token = (self.recovery_token or '').strip()
        new_password = self.new_password
        new_password_confirm = self.new_password_confirm
        if token:
            if not new_password or not new_password_confirm:
                raise ValueError('PASSWORD_RECOVERY_PASSWORD_REQUIRED')
        else:
            if new_password or new_password_confirm:
                raise ValueError('PASSWORD_RECOVERY_TOKEN_REQUIRED')
        return self


class AdminMessageResponse(BaseModel):
    message: str
