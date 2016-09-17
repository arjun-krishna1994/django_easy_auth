from django.http import Http404

def get_value_or_404(dict_, key):
    try:
        return dict_[key]
    except Exception as e:
        raise Http404(str(e))


class UserDoesNotExistForLoginField(BaseException):
    pass

class InvalidCredentials(BaseException):
    pass


def get_user_from_login_field(login_field):
    from django.conf import settings
    AUTH_USER_MODEL = getattr(settings, "AUTH_USER_MODEL", "auth.User")
    user = None
    try:
        user = AUTH_USER_MODEL.objects.get(email=login_field)
    except AUTH_USER_MODEL.DoesNotExist:
        pass
    try:
        user = AUTH_USER_MODEL.objects.get(username=login_field)
    except AUTH_USER_MODEL.DoesNotExist:
        pass
    if user is not None:
        return user
    raise UserDoesNotExistForLoginField("User does not exist for {login_field}".format(login_field=login_field))


def get_username_for_user(user):
    return user.username