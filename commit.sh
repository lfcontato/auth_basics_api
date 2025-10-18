#!/bin/bash

# =================================================================
# 1. Configurações do Banco de Dados PostgreSQL
# =================================================================

POSTGRES_HOST='localhost'
POSTGRES_PORT=5432
POSTGRES_DB='auth_app'
POSTGRES_USER='postgres'
POSTGRES_PASSWORD='postgres'
# POSTGRES_SSL_MODE='disable' # Não é necessário para pg_dump local

# =================================================================
# 2. Configurações de Backup
# =================================================================

# Define o diretório de backup
BACKUP_DIR="backup/sql"

# Obtém a data e hora atual no formato ano-mês-dia-hora-minuto-segundo
current_date=$(date '+%Y-%m-%d-%H-%M-%S')

# Define o nome do arquivo de backup: [nome_do_banco]_[data].sql
BACKUP_FILE="${BACKUP_DIR}/${POSTGRES_DB}_${current_date}.sql"

# Cria o diretório de backup se ele não existir
mkdir -p "$BACKUP_DIR"

# =================================================================
# 3. Execução do Backup (pg_dump)
# =================================================================

echo "Iniciando backup do banco de dados: ${POSTGRES_DB}..."

# Exporta a senha para que o pg_dump não precise solicitá-la
# Esta é a forma mais comum de automatizar o pg_dump
export PGPASSWORD="${POSTGRES_PASSWORD}"

# Executa o pg_dump
# -h: host | -p: porta | -U: usuário | -d: database
# O formato de texto simples é usado aqui.
pg_dump \
  -h "${POSTGRES_HOST}" \
  -p "${POSTGRES_PORT}" \
  -U "${POSTGRES_USER}" \
  -d "${POSTGRES_DB}" \
  > "${BACKUP_FILE}"

# Remove a variável de ambiente de senha por segurança
unset PGPASSWORD

# Verifica se o backup foi bem-sucedido
if [ $? -eq 0 ]; then
  echo "Backup concluído com sucesso: ${BACKUP_FILE}"
else
  echo "ERRO: O backup falhou. Verifique as configurações de conexão."
  exit 1
fi

# =================================================================
# 4. Commit e Push para o Git
# =================================================================

# Obtém o nome do computador para a mensagem de commit
computer_name=$(hostname)

echo "Preparando para o commit no Git..."

# Configurações globais do Git (se necessário, apenas na primeira execução)
# git config --global user.name "luis.fernando.pereira@gmail.com"
# git config --global user.email "luis.fernando.pereira@gmail.com"
# git config --global credential.helper store

# Adiciona todos os arquivos modificados/novos (incluindo o backup)
git add .

# Adiciona o commit
# Adicionei a parte "Backup" na mensagem para clareza
git commit -m "Backup: ${POSTGRES_DB} - ${computer_name} ${current_date}"

# Envia para o repositório remoto
git push

echo "Operação concluída. Backup e push realizados."