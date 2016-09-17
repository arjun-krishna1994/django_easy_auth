from django.http import Http404
import models


class UserDoesNotExistForLoginField(BaseException):
    pass


class InvalidCredentials(BaseException):
    pass


class InvalidResetToken(BaseException):
    pass

class ExpiredResetToken(BaseException):
    pass


def get_value_or_404(dict_, key):
    try:
        return dict_[key]
    except Exception as e:
        raise Http404(str(e))


def get_user_from_login_field(login_field, raise_error=True):
    from django.conf import settings
    from django.contrib.auth.models import User
    user = None
    try:
        user = User.objects.get(email=login_field)
    except User.DoesNotExist:
        pass
    try:
        user = User.objects.get(username=login_field)
    except User.DoesNotExist:
        pass
    if user is not None:
        return user
    if raise_error:
        raise UserDoesNotExistForLoginField("User does not exist for {login_field}".format(login_field=login_field))
    else:
        return None


def get_username_for_user(user):
    return user.username


def get_jwt_version_for_user(user):
    try:
        return models.TokenVersionForUser.objects.get(user=user).version
    except models.TokenVersionForUser.DoesNotExist:
        return models.TokenVersionForUser.objects.create(user=user).version


def invalidate_user_jwt_version(user):
    row = models.TokenVersionForUser.objects.get(user=user)
    row.version += 1
    row.save()
    return row.version


def get_reset_token_for_password(user):
    import hashlib
    import datetime
    import random
    salt = hashlib.sha1(str(random.random())).hexdigest()[:5]
    token = hashlib.sha1(salt+user.email).hexdigest()
    token_expires = datetime.datetime.today() + datetime.timedelta(9)
    models.ResetPasswordToken.objects.create(expires_at=token_expires, token=token, user=user)
    return token


def verify_reset_token(token):
    from django.utils import timezone
    try:
        row = models.ResetPasswordToken.objects.get(token=token)
        if row.expires_at < timezone.now():
            raise ExpiredResetToken("The reset token has expired")
        else:
            return row.user
    except models.ResetPasswordToken.DoesNotExist:
        raise InvalidResetToken("No valid reset token was provided")


def invalidate_all_tokens():
    from django.db.models import F
    models.TokenVersionForUser.objects.all().update(version = F('version') + 1)


def create_user(username, email, first_name="", last_name=""):
    from django.contrib.auth.models import User
    return User.objects.create(username=username, email=email, first_name=first_name, last_name=last_name)




