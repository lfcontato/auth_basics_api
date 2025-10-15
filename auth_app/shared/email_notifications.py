# caminho: auth_app/shared/email_notifications.py
# Funções:
# - EmailVerificationNotifier: envia códigos de verificação via SMTP renderizando templates Jinja2

from __future__ import annotations

import asyncio
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from pathlib import Path
from typing import Sequence
from urllib.parse import urlencode

from jinja2 import Environment, FileSystemLoader, TemplateNotFound, select_autoescape

from auth_app.config.settings import Settings
from auth_app.shared.logging import log_error, log_info, log_warning


def _clean_addresses(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [addr.strip() for addr in raw.split(',') if addr.strip()]


def _resolve_template_dir(settings: Settings) -> Path:
    template_dir = Path(settings.EMAIL_SERVER_TEMPLATE_DIR or '')
    if not template_dir.is_absolute():
        package_root = Path(__file__).resolve().parents[1]
        template_dir = package_root / template_dir
    return template_dir


class EmailVerificationNotifier:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        template_dir = _resolve_template_dir(settings)
        self._template_dir = template_dir
        self._env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(['html', 'xml']),
        )

    async def send(
        self,
        *,
        admin_name: str,
        login: str,
        recipients: Sequence[str],
        code: str,
        expires_at_iso: str,
    ) -> None:
        if not recipients:
            log_info('EMAIL_VERIFICATION_SKIPPED_NO_RECIPIENTS', {'login': login})
            return

        smtp_host = self._settings.EMAIL_SERVER_SMTP_HOST
        smtp_username = self._settings.EMAIL_SERVER_USERNAME
        smtp_password = self._settings.EMAIL_SERVER_PASSWORD

        if not smtp_host or not smtp_username or not smtp_password:
            missing = [item for item, value in {
                'host': smtp_host,
                'username': smtp_username,
                'password': smtp_password,
            }.items() if not value]
            log_warning('EMAIL_VERIFICATION_SKIPPED_SMTP_MISCONFIGURED', {'missing': missing})
            return

        html_body = await asyncio.to_thread(self._render_template, admin_name, code, login, expires_at_iso)
        plain_body = self._settings.EMAIL_BODY or (
            f'Olá {admin_name},\n\n'
            f'Seu código de verificação é {code}. '
            f'Use o link abaixo para confirmar seu e-mail:\n{self._build_link(login, code)}\n\n'
            'Se você não solicitou este código, ignore esta mensagem.'
        )
        subject = (
            self._settings.EMAIL_VERIFICATION_SUBJECT
            or self._settings.EMAIL_SUBJECT
            or 'Confirme seu e-mail'
        )

        email_message = self._compose_message(
            subject=subject,
            recipients=recipients,
            html_body=html_body,
            plain_body=plain_body,
        )

        await asyncio.to_thread(self._deliver, email_message, recipients)

    async def send_security_alert(
        self,
        *,
        admin_name: str,
        login: str,
        recipients: Sequence[str],
        last_ip: str | None,
        user_agent: str | None,
        blocked_at_iso: str | None,
    ) -> None:
        if not recipients:
            log_info('SECURITY_EMAIL_SKIPPED_NO_RECIPIENTS', {'login': login})
            return

        smtp_host = self._settings.EMAIL_SERVER_SMTP_HOST
        smtp_username = self._settings.EMAIL_SERVER_USERNAME
        smtp_password = self._settings.EMAIL_SERVER_PASSWORD

        if not smtp_host or not smtp_username or not smtp_password:
            missing = [item for item, value in {
                'host': smtp_host,
                'username': smtp_username,
                'password': smtp_password,
            }.items() if not value]
            log_warning('SECURITY_EMAIL_SKIPPED_SMTP_MISCONFIGURED', {'missing': missing})
            return

        html_body = await asyncio.to_thread(
            self._render_security_template,
            admin_name,
            login,
            last_ip,
            user_agent,
            blocked_at_iso,
        )
        plain_body = (
            f'Olá {admin_name},\n\n'
            'Detectamos múltiplas tentativas de acesso que levaram ao bloqueio temporário da sua conta.\n'
            f'Login afetado: {login}\n'
            f'Origem: {last_ip or "N/A"}\n'
            f'User-Agent: {user_agent or "N/A"}\n'
            f'Bloqueado em: {blocked_at_iso or "N/A"}\n'
            '\nSe não reconhece esta atividade, altere sua senha assim que o bloqueio expirar.'
        )
        subject = (
            self._settings.SECURITY_EMAIL_SUBJECT
            or self._settings.EMAIL_SUBJECT
            or f'Alerta de segurança - {self._settings.PROJECT_NAME}'
        )

        email_message = self._compose_message(
            subject=subject,
            recipients=recipients,
            html_body=html_body,
            plain_body=plain_body,
        )

        await asyncio.to_thread(self._deliver, email_message, recipients)

    async def send_password_recovery(
        self,
        *,
        admin_name: str,
        login: str,
        recipients: Sequence[str],
        token: str,
    ) -> None:
        if not recipients:
            log_info('PASSWORD_RECOVERY_EMAIL_SKIPPED_NO_RECIPIENTS', {'login': login})
            return

        smtp_host = self._settings.EMAIL_SERVER_SMTP_HOST
        smtp_username = self._settings.EMAIL_SERVER_USERNAME
        smtp_password = self._settings.EMAIL_SERVER_PASSWORD

        if not smtp_host or not smtp_username or not smtp_password:
            missing = [item for item, value in {
                'host': smtp_host,
                'username': smtp_username,
                'password': smtp_password,
            }.items() if not value]
            log_warning('PASSWORD_RECOVERY_EMAIL_SKIPPED_SMTP_MISCONFIGURED', {'missing': missing})
            return

        recovery_link = self._build_password_recovery_link(login, token)
        html_body = await asyncio.to_thread(
            self._render_password_recovery_template,
            admin_name,
            login,
            token,
            recovery_link,
        )

        plain_body = (
            f'Olá {admin_name},\n\n'
            'Utilize o token abaixo para redefinir sua senha:\n'
            f'Token: {token}\n\n'
            f'Link direto: {recovery_link or "(não configurado)"}\n\n'
            'Se não reconhece esta solicitação, ignore este e-mail e altere sua senha assim que possível.\n'
        )
        subject = (
            self._settings.PASSWORD_RECOVERY_SUBJECT
            or self._settings.EMAIL_SUBJECT
            or f'Redefinição de senha - {self._settings.PROJECT_NAME}'
        )

        email_message = self._compose_message(
            subject=subject,
            recipients=recipients,
            html_body=html_body,
            plain_body=plain_body,
        )

        await asyncio.to_thread(self._deliver, email_message, recipients)

    async def send_password_changed_confirmation(
        self,
        *,
        admin_name: str,
        login: str,
        recipients: Sequence[str],
        changed_at_iso: str | None,
        last_ip: str | None,
    ) -> None:
        if not recipients:
            log_info('PASSWORD_CHANGED_EMAIL_SKIPPED_NO_RECIPIENTS', {'login': login})
            return

        smtp_host = self._settings.EMAIL_SERVER_SMTP_HOST
        smtp_username = self._settings.EMAIL_SERVER_USERNAME
        smtp_password = self._settings.EMAIL_SERVER_PASSWORD

        if not smtp_host or not smtp_username or not smtp_password:
            missing = [item for item, value in {
                'host': smtp_host,
                'username': smtp_username,
                'password': smtp_password,
            }.items() if not value]
            log_warning('PASSWORD_CHANGED_EMAIL_SKIPPED_SMTP_MISCONFIGURED', {'missing': missing})
            return

        html_body = await asyncio.to_thread(
            self._render_password_changed_template,
            admin_name,
            login,
            changed_at_iso,
            last_ip,
        )

        plain_body = (
            f'Olá {admin_name},\n\n'
            'Confirmamos que a senha da sua conta foi atualizada. Caso não reconheça essa alteração, redefina-a imediatamente e procure o suporte.\n'
        )
        subject = (
            self._settings.PASSWORD_CHANGED_SUBJECT
            or self._settings.EMAIL_SUBJECT
            or f'Senha atualizada - {self._settings.PROJECT_NAME}'
        )

        email_message = self._compose_message(
            subject=subject,
            recipients=recipients,
            html_body=html_body,
            plain_body=plain_body,
        )

        await asyncio.to_thread(self._deliver, email_message, recipients)

    def _render_template(self, admin_name: str, code: str, login: str, expires_at_iso: str) -> str:
        try:
            template = self._env.get_template(self._settings.EMAIL_TEMPLATE_NAME)
        except TemplateNotFound as exc:  # pragma: no cover - configuração incorreta
            log_error('EMAIL_TEMPLATE_NOT_FOUND', {'template': self._settings.EMAIL_TEMPLATE_NAME})
            raise RuntimeError(f'Email template {self._settings.EMAIL_TEMPLATE_NAME} not found in {self._template_dir}') from exc

        verification_link = self._build_link(login, code)
        return template.render(
            admin_name=admin_name,
            verification_code=code,
            verification_link=verification_link,
            expires_at=expires_at_iso,
        )

    def _render_security_template(
        self,
        admin_name: str,
        login: str,
        last_ip: str | None,
        user_agent: str | None,
        blocked_at_iso: str | None,
    ) -> str:
        try:
            template = self._env.get_template(self._settings.SECURITY_TEMPLATE_NAME)
        except TemplateNotFound as exc:  # pragma: no cover - configuração incorreta
            log_error('SECURITY_TEMPLATE_NOT_FOUND', {'template': self._settings.SECURITY_TEMPLATE_NAME})
            raise RuntimeError(f'Security template {self._settings.SECURITY_TEMPLATE_NAME} not found in {self._template_dir}') from exc

        return template.render(
            admin_name=admin_name,
            login=login,
            last_ip=last_ip,
            user_agent=user_agent,
            blocked_at=blocked_at_iso,
            product_name=self._settings.PROJECT_NAME,
        )

    def _render_password_recovery_template(
        self,
        admin_name: str,
        login: str,
        token: str,
        recovery_link: str,
    ) -> str:
        try:
            template = self._env.get_template(self._settings.PASSWORD_RECOVERY_TEMPLATE_NAME)
        except TemplateNotFound as exc:  # pragma: no cover
            log_error('PASSWORD_RECOVERY_TEMPLATE_NOT_FOUND', {'template': self._settings.PASSWORD_RECOVERY_TEMPLATE_NAME})
            raise RuntimeError(
                f'Password recovery template {self._settings.PASSWORD_RECOVERY_TEMPLATE_NAME} not found in {self._template_dir}'
            ) from exc

        return template.render(
            admin_name=admin_name,
            login=login,
            product_name=self._settings.PROJECT_NAME,
            token=token,
            recovery_link=recovery_link,
        )

    def _render_password_changed_template(
        self,
        admin_name: str,
        login: str,
        changed_at_iso: str | None,
        last_ip: str | None,
    ) -> str:
        try:
            template = self._env.get_template(self._settings.PASSWORD_CHANGED_TEMPLATE_NAME)
        except TemplateNotFound as exc:  # pragma: no cover
            log_error('PASSWORD_CHANGED_TEMPLATE_NOT_FOUND', {'template': self._settings.PASSWORD_CHANGED_TEMPLATE_NAME})
            raise RuntimeError(
                f'Password changed template {self._settings.PASSWORD_CHANGED_TEMPLATE_NAME} not found in {self._template_dir}'
            ) from exc

        return template.render(
            admin_name=admin_name,
            login=login,
            changed_at=changed_at_iso,
            last_ip=last_ip,
            product_name=self._settings.PROJECT_NAME,
        )

    def _build_password_recovery_link(self, login: str, token: str) -> str:
        base = getattr(self._settings, 'PASSWORD_RECOVERY_LINK_BASE', '') or ''
        if not base:
            return ''
        path = base.rstrip('/')
        return f'{path}/admin/auth/recovery/{token}'

    def _compose_message(
        self,
        *,
        subject: str,
        recipients: Sequence[str],
        html_body: str,
        plain_body: str,
    ) -> EmailMessage:
        message = EmailMessage()
        sender_address = (self._settings.EMAIL_FROM_ADDRESS or self._settings.EMAIL_SERVER_USERNAME or '').strip()
        sender_name = (self._settings.EMAIL_FROM_NAME or self._settings.EMAIL_SERVER_NAME or '').strip()

        message['Subject'] = subject
        message['From'] = formataddr((sender_name, sender_address)) if sender_address else sender_name or 'Auth App'
        message['To'] = ', '.join(recipients)

        cc_list = _clean_addresses(self._settings.EMAIL_CC_ADDRESSES)
        bcc_list = _clean_addresses(self._settings.EMAIL_BCC_ADDRESSES)
        if cc_list:
            message['Cc'] = ', '.join(cc_list)

        message['Message-ID'] = make_msgid()
        message.set_content(plain_body)
        message.add_alternative(html_body, subtype='html')

        return message

    def _deliver(self, message: EmailMessage, to_recipients: Sequence[str]) -> None:
        cc_list = _clean_addresses(self._settings.EMAIL_CC_ADDRESSES)
        bcc_list = _clean_addresses(self._settings.EMAIL_BCC_ADDRESSES)
        all_recipients = list(dict.fromkeys([*to_recipients, *cc_list, *bcc_list]))

        encryption = (self._settings.EMAIL_SERVER_SMTP_ENCRYPTION or '').upper()
        context = ssl.create_default_context()

        if encryption in {'SSL', 'SSL/TLS'}:
            with smtplib.SMTP_SSL(self._settings.EMAIL_SERVER_SMTP_HOST, self._settings.EMAIL_SERVER_SMTP_PORT, context=context) as smtp:
                smtp.login(self._settings.EMAIL_SERVER_USERNAME, self._settings.EMAIL_SERVER_PASSWORD)
                smtp.send_message(message, to_addrs=all_recipients)
                return

        with smtplib.SMTP(self._settings.EMAIL_SERVER_SMTP_HOST, self._settings.EMAIL_SERVER_SMTP_PORT) as smtp:
            smtp.ehlo()
            if encryption in {'STARTTLS', 'TLS'}:
                smtp.starttls(context=context)
                smtp.ehlo()
            smtp.login(self._settings.EMAIL_SERVER_USERNAME, self._settings.EMAIL_SERVER_PASSWORD)
            smtp.send_message(message, to_addrs=all_recipients)

    def _build_link(self, login: str, code: str) -> str:
        base = self._settings.EMAIL_VERIFICATION_LINK_BASE or ''
        if not base:
            return ''
        query = urlencode({'login': login, 'code': code})
        separator = '&' if '?' in base else '?'
        return f'{base}{separator}{query}'
