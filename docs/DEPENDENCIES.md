# Instalar as dependências de desenvolvimento do projeto
```bash
# - ruff
poetry add --group dev ruff

# - pytest
poetry add --group dev pytest pytest-cov

# - taskipy
poetry add --group dev taskipy
# For taskipy, a possible solution would be to set the `python` property to ">=3.12,<4.0"
# *** Ajustar a versão do python no arquivo pyproject.toml:
# *** requires-python = ">=3.12,<4.0"
# *** executar o comando novamente:
# *** poetry add --group dev taskipy
```



# Instalar as dependências do projeto
```bash
# - pydantic-settings
poetry add pydantic-settings
# - pwdlib
poetry add "pwdlib[argon2]"
# - redis
poetry add redis
# - pyjwt
poetry add pyjwt
# - sqlalchemy
poetry add sqlalchemy
# - pydantic[email]
poetry add 'pydantic[email]'
# - asyncpg
poetry add asyncpg
# - jinja2
poetry add jinja2
# - python-multipart
poetry add python-multipart

```