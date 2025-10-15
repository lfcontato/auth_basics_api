#!/bin/bash

docker compose down
docker compose build --no-cache

# Remove todas as imagens não utilizadas (se houver)
docker rmi $(docker images -q) 2>/dev/null || true

# Remove contêineres parados, redes, cache de build E VOLUMES NÃO UTILIZADOS.
docker system prune -af --volumes 

# Remove explicitamente todos os volumes que não estão em uso por um contêiner.
# O $(docker volume ls -q) lista todos os IDs de volume.
docker volume rm $(docker volume ls -q) 2>/dev/null || true

# Remove todas as imagens não utilizadas (se houver)
docker rmi $(docker images -q) 2>/dev/null || true

# Para todos os contêineres rodando (se houver)
docker stop $(docker ps -q) 2>/dev/null || true

# Remove todos os contêineres (rodando ou parados) (se houver)
docker rm -f $(docker ps -aq) 2>/dev/null || true

docker ps -a