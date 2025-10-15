#!/bin/bash

# # # Criar Rede para Portainer: overlay quando estiver em maquinas diferentes poder reconhecer a rede
# docker network create --driver=overlay agent_network

# Construir (criar) uma imagem Postgres
docker volume create postgres_data
# docker run -d --name auth_app_db -p 5432:5432 -e POSTGRES_DB=auth_app -e POSTGRES_USER=app_user -e POSTGRES_PASSWORD=app_password -v postgres_data:/var/lib/postgresql/data postgres

# Construir (criar) uma imagem Docker com composer
docker compose up -d


# Construir (criar) uma imagem Docker
# Aplica a tag específica (0.0.1) E a tag latest
# docker build -f Dockerfile -t auth_app:0.0.1 -t auth_app:latest .

# docker run -d -p 8000:8000 --name auth_app auth_app:latest

# Verifique a estrutura de arquivos no contêiner e executa o servidor de dentro do container
# docker run -it --rm auth_app:latest /bin/bash
# # poetry run uvicorn auth_app.app:app --port 8000 --host 0.0.0.0

docker ps -a