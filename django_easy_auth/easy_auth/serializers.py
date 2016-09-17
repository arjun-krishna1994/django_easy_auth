import models
from rest_framework import serializers
from rest_framework_jwt.serializers import RefreshJSONWebTokenSerializer, VerificationBaseSerializer
import utils

class JWTSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.UserJWToken
        fields = ['token']


class RefreshJWTSerializer(RefreshJSONWebTokenSerializer):
    def validate(self, attrs):
        rval = super(RefreshJSONWebTokenSerializer, self).validate(attrs)
        token = attrs['token']
        payload = self._check_payload(token=token)
        user_version = utils.get_jwt_version_for_user(rval["user"])
        if not payload.get('version'):
            raise serializers.ValidationError("Version is missing in JWT payload")
        if payload.get("version") != user_version:
            raise serializers.ValidationError("Incorrect token version. Please Re-Authenticate")
        return rval


class VerifyJWTSerializer(VerificationBaseSerializer):
    def validate(self, attrs):
        token = attrs['token']
        payload = self._check_payload(token=token)
        user = self._check_user(payload=payload)
        user_version = utils.get_jwt_version_for_user(user)
        if not payload.get('version'):
            raise serializers.ValidationError("Version is missing in JWT payload")
        if payload.get("version") != user_version:
            raise serializers.ValidationError("Incorrect token version. Please Re-Authenticate")
        return {
            'token': token,
            'user': user
        }



