# caminho: auth_app/infrastructure/db/__init__.py
# Funções:
# - expõe Base para migrations

from __future__ import annotations

from auth_app.infrastructure.db.base import Base
from auth_app.infrastructure.db import models  # noqa: F401

__all__ = ['Base']
