# caminho: auth_app/main.py
# Funções:
# - app: instancia FastAPI criada via create_application()

from __future__ import annotations

from auth_app.interfaces.api.app import create_application

app = create_application()