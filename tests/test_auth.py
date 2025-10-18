from datetime import datetime, timedelta
from http import HTTPStatus

# from freezegun import freeze_time
from jwt import decode

# from auth_basics.schemas import ExceptionResponse, JwtRefreshResponse, JwtResponse
# from auth_basics.settings import Settings

PAGINATION_LIMIT = Settings().PAGINATION_LIMIT


def test_create_user_token(client, user):
    response = client.post(
        'auth/token/',
        data={
            'username': user.email,
            'password': user.password_clean,
        },
    )

    assert response.status_code == HTTPStatus.OK

    # valida a resposta contra o schema correto
    data = JwtRefreshResponse.model_validate(response.json())
    assert isinstance(data, JwtRefreshResponse)
    assert data.token_type == 'Bearer'

    # valida se é um usuario do perfil user
    jwt_decoded = decode(data.access_token, Settings().SECRET_KEY, algorithms=[Settings().SECRET_ALGORITHM])
    assert 'exp' in jwt_decoded
    assert 'sid' not in jwt_decoded
    assert jwt_decoded['role'] == 'user'

    # # valida se é um usuario do perfil user
    # jwt_refresh_decoded = decode(data.refresh_token, Settings().SECRET_KEY, algorithms=[Settings().SECRET_ALGORITHM])
    # assert 'exp' in jwt_refresh_decoded
    # assert 'sid' in jwt_refresh_decoded
    # assert jwt_refresh_decoded['role'] == 'user'
