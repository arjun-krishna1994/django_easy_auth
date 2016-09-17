from rest_framework_jwt.settings import api_settings as jwt_api_settings
from django.conf import settings
import models
User = getattr(settings, "AUTH_USER_MODEL", "auth.User")
jwt_decode_handler = jwt_api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = jwt_api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER
jwt_payload_handler = jwt_api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = jwt_api_settings.JWT_ENCODE_HANDLER


def get_user_from_jwt(token):
    """
    Utility function to get the user object from the token
    :type token: str
    :rtype: User
    """
    username = jwt_get_username_from_payload(jwt_decode_handler(token))
    try:
        user = (User.objects.get_by_natural_key(username))
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
