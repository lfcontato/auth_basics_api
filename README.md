# auth_basics_api
O sistema auth_basics_api utiliza JWT para autenticação, gerencia administradores de forma hierárquica, permite recuperação segura de senha, protege contra brute force. Consolidadando bases arquiteturais que tornam o auth_app seguro, escalável e alinhado a padrões modernos.

```bash
# CRIAR O PROJETO NA PASTA workspace
poetry new --flat auth_basics_api --name auth_app
cd auth_basics_api

# INICIALIZAR O GIT LOCAL (JÁ FEITO)
git init

# ADICIONAR E FAZER O PRIMEIRO COMMIT (JÁ FEITO)
git add .
git commit -m "feat: initial project setup with Poetry"

# ADICIONAR O REPOSITÓRIO REMOTO
# Certifique-se de que o repositório 'lfcontato/auth_basics_api' existe no GitHub.
git remote add origin git@github.com:lfcontato/auth_basics_api.git

# RENOMEAR O BRANCH LOCAL PARA 'main'
git branch -M main

# 6. ENVIAR PARA O GITHUB (PUSH)
# O comando '-u origin main' define 'origin/main' como o upstream do seu branch 'main'.
git push -u origin main

```