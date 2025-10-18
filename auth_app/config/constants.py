# auth_app/config/constants.py

from auth_app.config import get_settings
settings = get_settings()

# Constantes para o Nome de Usuário (Username)
USERNAME_LENGTH_MIN = 4
USERNAME_LENGTH_MAX = 50

# Constantes para a Senha
PASSWORD_LENGTH_MIN = 8
PASSWORD_LENGTH_MAX = 64

# Constantes para Código de Verificação
VERIFICATION_CODE_LENGTH_MIN = 4
VERIFICATION_CODE_LENGTH_MAX = 32



# Declaração da URL de Obtenção do Token
OAUTH2_SCHEME_TOKEN_URL='/admin/auth/token'
