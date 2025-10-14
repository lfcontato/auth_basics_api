# caminho: auth_app/shared/logging.py
# Funções:
# - setup_logging(): inicializa logging com OTEL
# - log_info/log_warning/log_error: atalhos padronizados

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

# from opentelemetry import _logs as otel_logs  # noqa: PLC2701
# from opentelemetry.instrumentation.logging import LoggingInstrumentor
# from opentelemetry.sdk._logs import LoggerProvider  # noqa: PLC2701

LOG_FORMAT = '%(asctime)s %(levelname)s [%(name)s] %(message)s'
LOG_DATEFMT = '%Y-%m-%d %H:%M:%S'
LOG_DIR = Path(__file__).resolve().parent.parent / 'logs'
LOG_FILE = LOG_DIR / 'auth_app.log'
CONFIG_STATE = {'logging': False, 'otel': False}


def setup_logging(level: str = 'INFO') -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if not CONFIG_STATE['logging']:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATEFMT))

        file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATEFMT))

        root = logging.getLogger()
        root.setLevel(level.upper())
        root.handlers = [stream_handler, file_handler]
        CONFIG_STATE['logging'] = True
    else:
        logging.getLogger().setLevel(level.upper())

    # if not CONFIG_STATE['otel']:
    #     LoggerProvider()  # ensure init (OTEL)
    #     otel_logs.set_logger_provider(LoggerProvider())
    #     LoggingInstrumentor().instrument(set_logging_format=False)
    #     CONFIG_STATE['otel'] = True


def _log(event: str, payload: dict[str, Any | str | int], level: str) -> None:
    logger = logging.getLogger('auth_app')
    getattr(logger, level.lower())('%s | %s', event, payload)


def log_info(event: str, payload: dict[str, Any | str | int]) -> None:
    _log(event, payload, 'info')


def log_warning(event: str, payload: dict[str, Any | str | int]) -> None:
    _log(event, payload, 'warning')


def log_error(event: str, payload: dict[str, Any | str | int]) -> None:
    _log(event, payload, 'error')
