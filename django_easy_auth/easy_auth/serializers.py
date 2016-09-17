import models
from rest_framework import serializers


class JWTSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.UserJWToken
        fields = ['token']

