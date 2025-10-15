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
CONFIG_STATE = {'logging': False, 'otel': False, 'vercel' : False}


import logging
import sys
import os # Novo import necessário
# from logging.handlers import RotatingFileHandler # Não é mais necessário para o Vercel
# ... outros imports de Path ou LOG_DIR, etc.


CONFIG_STATE = {'logging': False, 'otel': False, 'vercel' : False}
# O CONFIG_STATE['vercel'] pode ser usado para controle local

def setup_logging(level: str = 'INFO') -> None:
    # 1. VERIFICAÇÃO DO AMBIENTE VERCEL/LAMBDA
    # A variável 'VERCEL' ou 'AWS_EXECUTION_ENV' indica o ambiente serverless.
    IS_SERVERLESS_ENV = os.environ.get('VERCEL') == '1' or 'AWS_LAMBDA' in os.environ.get('AWS_EXECUTION_ENV', '')
    
    # 2. CONFIGURAÇÃO DE LOGS (SOMENTE STREAM)
    if not CONFIG_STATE['logging']:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATEFMT))

        root = logging.getLogger()
        root.setLevel(level.upper())

        # Adiciona o StreamHandler (funciona em todo lugar)
        root.addHandler(stream_handler) 
        
        # 3. BLOQUEAR ESCRITA DE ARQUIVOS NO VERCEL
        # Se NÃO for o ambiente serverless E você quiser logs em arquivo,
        # OU se você quiser logs em arquivo mesmo no serverless, mas no /tmp
        if not IS_SERVERLESS_ENV:
            # Esta linha deve ser removida ou colocada DENTRO deste bloco 'if':
            LOG_DIR.mkdir(parents=True, exist_ok=True) 

            # DESCOMENTE e use o file_handler SOMENTE se não for serverless,
            # ou altere LOG_FILE para usar o /tmp, mas é melhor evitar.
            file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding='utf-8')
            file_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATEFMT))
            root.addHandler(file_handler)
            
        CONFIG_STATE['logging'] = True
    else:
        logging.getLogger().setLevel(level.upper())
        

def _log(event: str, payload: dict[str, Any | str | int], level: str) -> None:
    logger = logging.getLogger('auth_app')
    getattr(logger, level.lower())('%s | %s', event, payload)


def log_info(event: str, payload: dict[str, Any | str | int]) -> None:
    _log(event, payload, 'info')


def log_warning(event: str, payload: dict[str, Any | str | int]) -> None:
    _log(event, payload, 'warning')


def log_error(event: str, payload: dict[str, Any | str | int]) -> None:
    _log(event, payload, 'error')
