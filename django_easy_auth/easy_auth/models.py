from django.db import models
from django.conf import settings
AUTH_USER_MODEL = getattr(settings, "AUTH_USER_MODEL", "auth.User")


class UserJWToken(models.Model):
    created = models.DateTimeField(auto_created=True, auto_now_add=True)
    user = models.ForeignKey(AUTH_USER_MODEL)
    token = models.TextField()