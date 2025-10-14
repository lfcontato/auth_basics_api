python --version
Python 3.12.11

poetry --version
Poetry (version 2.1.4)

# Criar o ambiente virtual onde tem o arquivo pyproject.toml
poetry install 
poetry add fastapi
poetry add uvicorn
poetry env activate

# utilizar ambiente virtual onde tem o arquivo pyproject.toml
poetry self add poetry-plugin-shell
poetry env activate
poetry shell