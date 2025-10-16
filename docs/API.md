# /admin/

**Fluxo**:
1. Valida unicidade de `email` e `username`.
2. Persiste o admin, contatos e código de verificação.
3. Dispara e-mail de confirmação (canal fixo `email`).

**Proteções**:
- Apenas usuários `system_role=root` podem criar novas contas.
- Código inicial tem expiração (`VERIFICATION_CODE_EXPIRE_SECONDS`).

```json
{
  "email": "luis.fernando.pereira.procempa@gmail.com",
  "password": "stringst",
  "username": "luis.fernando.pereira.procempa"
}

{
  "email": "luis.fernando.pereira@gmail.com",
  "password": "stringst",
  "username": "luis.fernando.pereira"
}

{
  "email": "user@example.com",
  "password": "stringst",
  "username": "user",
  "system_role": "admin",
  "verification_channel": "string"
}


{
  "email": "admin2@example.com",
  "password": "stringst",
  "username": "admin2",
  "system_role": "admin",
  "verification_channel": "string"
}


// ADMIN_VERIFICATION_EMAIL_SENDING
```


# /admin/verification-code

Regenera o código de verificação para o administrador informado via email.

```json
{
  "email": "luis.fernando.pereira.procempa@gmail.com",
  "channel": "email"
}
```

# /admin/auth/password-recovery
```json
{
  "email": "luis.fernando.pereira.procempa@gmail.com"
}
```
# recovery_link
# http://admin/auth/verify-link/admin/auth/recovery/DwG9ueH6aopL0aL5jaz1dmqP85EG6eiNR2Vonhilq84