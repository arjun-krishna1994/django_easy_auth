from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework import status
from django.contrib.auth import authenticate, login
from rest_framework.response import Response
from django.conf import settings
import urllib2, json, random
from .utils import get_value_or_404
import utils, models
from .import jwt_utils
from rest_framework_jwt.views import JSONWebTokenAPIView
from .serializers import RefreshJWTSerializer, VerifyJWTSerializer
from django.contrib.auth.models import User


#TODO: Convert this function into a class based view
@api_view(["POST"])
def obtain_jwt_for_user(request):
    login_field = get_value_or_404(request.data, "login_field")
    password = get_value_or_404(request.data, 'password')
    user = utils.get_user_from_login_field(login_field)
    user = authenticate(username=utils.get_username_for_user(user), password=password)
    if user is None:
        return Response({"message": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
    if settings.EASY_AUTH_AUTHENTICATE_TO_DJANGO_SESSIONS:
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, user)
    return Response({"token": jwt_utils.get_jwt_for_user(user)})


class RefreshTokenAPIView(JSONWebTokenAPIView):
    serializer_class = RefreshJWTSerializer


class VerifyTokenAPIView(JSONWebTokenAPIView):
    serializer_class = VerifyJWTSerializer


@api_view(["POST"])
def change_password(request):
    old_password = get_value_or_404(request.data, 'old_password')
    new_password1 = get_value_or_404(request.data, 'new_password1')
    new_password2 = get_value_or_404(request.data, 'new_password2')
    user = request.user
    success = user.check_password(old_password)
    if not success:
        return Response({"message": "Old password incorrect"}, status=status.HTTP_400_BAD_REQUEST)
    if new_password1 != new_password2:
        return Response({"message": "New passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)
    else:
        user.set_password(new_password1)
        user.save()
        utils.invalidate_user_jwt_version(user)
        token = jwt_utils.get_jwt_for_user(user)
        return Response({'message': 'Password successfully reset', 'token': token}, status=status.HTTP_200_OK)


class ResetPasswordToken(APIView):

    def get(self, request, format=None):
        login_field = get_value_or_404(request.GET, 'login_field')
        user = utils.get_user_from_login_field(login_field)
        token = utils.get_reset_token_for_password(user)
        return Response({"token": token}, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        token = get_value_or_404(request.data, "reset_token")
        password = get_value_or_404(request.data, "password")
        user = utils.verify_reset_token(token)
        user.set_password(password)
        user.save()
        utils.invalidate_user_jwt_version(user)
        token = jwt_utils.get_jwt_for_user(user)
        return Response({'message': 'Password successfully reset', 'token': token}, status=status.HTTP_200_OK)


@api_view(["POST"])
def invalidate_all_tokens(request):
    utils.invalidate_all_tokens()
    return Response({"message": "All tokens successfully invalidated"}, status=status.HTTP_200_OK)


@api_view(["POST"])
def facebook_auth(request):
    access_token = get_value_or_404(request.data, 'access_token')
    file_ = urllib2.urlopen("https://graph.facebook.com/me?access_token="+access_token+'&fields=email,first_name,last_name')
    ret = json.loads(file_.read())
    uid = ret['id']
    signup = False
    try:
        row = models.UserSocialAccount.objects.get(uid=uid, provider="fb")
        user = row.user
    except models.UserSocialAccount.DoesNotExist:
        email = ret["email"]
        user = utils.get_user_from_login_field(email, raise_error=False)
        if not user:
            username = ret["first_name"].replace(" ", "").lower() + str(random.randint(0, 10000000000000000))
            first_name = ret["first_name"]
            last_name = ret["last_name"]
            user = utils.create_user(username, email, first_name, last_name)
            signup = True
        row = models.UserSocialAccount.objects.create(uid=uid, user=user, extra_data=json.dumps(ret))
    token = jwt_utils.get_jwt_for_user(user)
    return Response({"token": token, "sign_up": signup}, status=status.HTTP_200_OK)



refresh_jwt_token = RefreshTokenAPIView.as_view()
verify_jwt_token = VerifyTokenAPIView.as_view()
password_reset_token = ResetPasswordToken.as_view()