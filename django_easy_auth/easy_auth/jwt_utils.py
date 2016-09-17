from rest_framework_jwt.settings import api_settings as jwt_api_settings
from django.conf import settings
import models
jwt_decode_handler = jwt_api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = jwt_api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER
jwt_encode_handler = jwt_api_settings.JWT_ENCODE_HANDLER
from rest_framework import authentication
from rest_framework import exceptions
from rest_framework_jwt.compat import get_username, get_username_field
import warnings
from calendar import timegm
from datetime import datetime
from django.contrib.auth.models import User


def custom_jwt_payload_handler(user):
    from .utils import get_jwt_version_for_user
    username_field = get_username_field()
    username = get_username(user)

    warnings.warn(
        'The following fields will be removed in the future: '
        '`email` and `user_id`. ',
        DeprecationWarning
    )

    payload = {
        'user_id': user.pk,
        'email': user.email,
        'username': username,
        'version': get_jwt_version_for_user(user),
        'exp': datetime.utcnow() + jwt_api_settings.JWT_EXPIRATION_DELTA
    }

    payload[username_field] = username

    # Include original issued at time for a brand new token,
    # to allow token refresh
    if jwt_api_settings.JWT_ALLOW_REFRESH:
        payload['orig_iat'] = timegm(
            datetime.utcnow().utctimetuple()
        )

    return payload


jwt_payload_handler = custom_jwt_payload_handler


def get_user_from_jwt(token):
    """
    Utility function to get the user object from the token
    :type token: str
    :rtype: User
    """
    from .utils import get_jwt_version_for_user
    payload = jwt_decode_handler(token)
    username = jwt_get_username_from_payload(payload)
    try:
        user = (User.objects.get_by_natural_key(username))
        user_version = get_jwt_version_for_user(user)
        if not payload.get("version"):
            raise ValueError("Version required in Payload")
        if payload.get('version') != user_version:
            raise ValueError("Incorrect JWT version")
        return user
    except User.DoesNotExist:
        raise ValueError("User does not exist for the given token")


def get_jwt_for_user(user):
    """
    Utility to function to obtain a token for a user object, creates one if it does not exist
    :type user: User
    :rtype: str
    """
    payload = jwt_payload_handler(user)
    value = jwt_encode_handler(payload)
    models.UserJWToken.objects.create(user=user, token=value)
    return value


class JWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        JWToken = request.META.get(settings.EASY_AUTH_JWT_HEADER)
        if not JWToken:
            return None
        try:
            user = get_user_from_jwt(JWToken)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('No such user')
        if not user.is_active:
            raise exceptions.AuthenticationFailed('User Blocked')
        return user, None



