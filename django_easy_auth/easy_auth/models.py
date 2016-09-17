from django.db import models
from django.conf import settings
AUTH_USER_MODEL = getattr(settings, "AUTH_USER_MODEL", "auth.User")


class UserJWToken(models.Model):
    created = models.DateTimeField(auto_created=True, auto_now_add=True)
    user = models.ForeignKey(AUTH_USER_MODEL)
    token = models.TextField()


class TokenVersionForUser(models.Model):
    user = models.OneToOneField(AUTH_USER_MODEL)
    version = models.IntegerField(default=1)


class ResetPasswordToken(models.Model):
    user = models.ForeignKey(AUTH_USER_MODEL)
    token = models.TextField(unique=True)
    expires_at = models.DateTimeField()


class UserSocialAccount(models.Model):
    class Meta:
        unique_together = (('uid', 'provider'),)
    user = models.ForeignKey(AUTH_USER_MODEL)
    uid = models.TextField()
    extra_data = models.TextField()
    provider = models.CharField(max_length=20, choices=(('fb', 'Facebook'),('twt', 'Twitter') ))