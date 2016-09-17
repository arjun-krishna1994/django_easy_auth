from rest_framework.decorators import api_view
from rest_framework import status
from django.contrib.auth import authenticate, login
from rest_framework.response import Response
from django.conf import settings
import utils
from .import jwt_utils


@api_view(["POST"])
def obtain_jwt_for_user(request):
    login_field = utils.get_value_or_404(request.data, "login_field")
    password = utils.get_value_or_404(request.data, 'password')
    user = utils.get_user_from_login_field(login_field)
    user = authenticate(username=utils.get_username_for_user(user), password=password)
    if user is None:
        return Response({"message": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
    if settings.EASY_AUTH_AUTHENTICATE_TO_DJANGO_SESSIONS:
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, user)
    return Response({"token": jwt_utils.get_jwt_for_user(user)})


def refresh_token(request):
    pass


def verify_token(request):
    pass


def change_password(request):
    pass


def reset_password(request):
    pass


def invalidate_all_tokens(request):
    pass


def facebook_login(request):
    pass


def google_login(request):
    pass