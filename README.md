# auth_basics_api
O sistema auth_basics_api utiliza JWT para autenticação, gerencia administradores de forma hierárquica, permite recuperação segura de senha, protege contra brute force. Consolidadando bases arquiteturais que tornam o auth_app seguro, escalável e alinhado a padrões modernos.

```bash
# Criar o projeto na pasta workspace
poetry new --flat auth_basics_api --name auth_app

# Entre na pasta do seu projeto e execute o comando para inicializar o Git:
git init

# Adicionar e Fazer o Primeiro Commit
git add .

# Faz o commit inicial
git commit -m "feat: initial project setup with Poetry"


# Adicione o repositório remoto:
git remote add origin git@github.com:lfcontato/auth_basics_api

# Envie os arquivos para o repositório remoto:
git branch -M main     # Renomeia o branch principal para 'main' (convenção moderna)
git push -u origin main

```