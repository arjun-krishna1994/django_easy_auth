import jwt
import warnings
from calendar import timegm
from datetime import datetime

from rest_framework_jwt.compat import get_username, get_username_field
from rest_framework_jwt.settings import api_settings as jwt_api_settings
import models
from django.contrib.auth.models import User


def jwt_payload_handler(user):
    username_field = get_username_field()
    username = get_username(user)

    payload = {
        'user_id': user.pk,
        'email': user.email,
        'username': username,
        'exp': datetime.utcnow() + jwt_api_settings.JWT_EXPIRATION_DELTA,
    }

    payload[username_field] = username

    # Include original issued at time for a brand new token,
    # to allow token refresh
    if jwt_api_settings.JWT_ALLOW_REFRESH:
        payload['orig_iat'] = timegm(
            datetime.utcnow().utctimetuple()
        )

    return payload


def jwt_get_user_id_from_payload_handler(payload):
    """
    Override this function if user_id is formatted differently in payload
    """
    warnings.warn(
        'The following will be removed in the future. '
        'Use `JWT_PAYLOAD_GET_USERNAME_HANDLER` instead.',
        DeprecationWarning
    )

    return payload.get('user_id')


def jwt_get_username_from_payload_handler(payload):
    """
    Override this function if username is formatted differently in payload
    """
    return payload.get('username')


def jwt_encode_handler(payload):
    return jwt.encode(
        payload,
        jwt_api_settings.JWT_SECRET_KEY,
        jwt_api_settings.JWT_ALGORITHM
    ).decode('utf-8')


def jwt_decode_handler(token):
    options = {
        'verify_exp': jwt_api_settings.JWT_VERIFY_EXPIRATION,
    }

    return jwt.decode(
        token,
        jwt_api_settings.JWT_SECRET_KEY,
        jwt_api_settings.JWT_VERIFY,
        options=options,
        leeway=jwt_api_settings.JWT_LEEWAY,
        audience=jwt_api_settings.JWT_AUDIENCE,
        issuer=jwt_api_settings.JWT_ISSUER,
        algorithms=[jwt_api_settings.JWT_ALGORITHM]
    )


def jwt_response_payload_handler(token, user=None, request=None):
    """
    Returns the response data for both the login and refresh views.
    Override to return a custom response such as including the
    serialized representation of the User.

    Example:

    def jwt_response_payload_handler(token, user=None, request=None):
        return {
            'token': token,
            'user': UserSerializer(user).data
        }

    """
    return {
        'token': token
    }

def get_user_from_token(token):
    """
    Utility function to get the user object from the token
    :type token: str
    :rtype: User
    """
    username = jwt_get_username_from_payload_handler(jwt_decode_handler(token))
    try:
        user = (User.objects.get_by_natural_key(username))
        return user
    except User.DoesNotExist:
        raise ValueError("User does not exist for the given token")

def get_token_for_user(user):
    """
    Utility to function to obtain a token for a user object, creates one if it does not exist
    :type user: User
    :rtype: str
    """
    payload = jwt_payload_handler(user)
    value = jwt_encode_handler(payload)
    models.UserJWToken.objects.create(user=user, token=value)
    return value
