from rest_framework import serializers
from rest_framework_jwt.serializers import RefreshJSONWebTokenSerializer, VerificationBaseSerializer
import utils
from rest_framework_jwt.settings import api_settings as jwt_api_settings
import models
jwt_decode_handler = jwt_api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = jwt_api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER
jwt_encode_handler = jwt_api_settings.JWT_ENCODE_HANDLER
jwt_payload_handler = jwt_api_settings.JWT_PAYLOAD_HANDLER
from calendar import timegm
from datetime import datetime, timedelta

class JWTSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.UserJWToken
        fields = ['token']


class RefreshJWTSerializer(RefreshJSONWebTokenSerializer):
    def validate(self, attrs):
        token = attrs['token']
        payload = self._check_payload(token=token)
        user = self._check_user(payload=payload)
        # Get and check 'orig_iat'
        orig_iat = payload.get('orig_iat')

        if orig_iat:
            # Verify expiration
            refresh_limit = jwt_api_settings.JWT_REFRESH_EXPIRATION_DELTA

            if isinstance(refresh_limit, timedelta):
                refresh_limit = (refresh_limit.days * 24 * 3600 +
                                 refresh_limit.seconds)

            expiration_timestamp = orig_iat + int(refresh_limit)
            now_timestamp = timegm(datetime.utcnow().utctimetuple())

            if now_timestamp > expiration_timestamp:
                msg = _('Refresh has expired.')
                raise serializers.ValidationError(msg)
        else:
            msg = _('orig_iat field is required.')
            raise serializers.ValidationError(msg)

        payload = self._check_payload(token=token)
        user_version = utils.get_jwt_version_for_user(user)
        if not payload.get('version'):
            raise serializers.ValidationError("Version is missing in JWT payload")
        if payload.get("version") != user_version:
            raise serializers.ValidationError("Incorrect token version. Please Re-Authenticate")
        new_payload = jwt_payload_handler(user)
        new_payload['orig_iat'] = orig_iat
        return {
            'token': jwt_encode_handler(new_payload),
            'user': user
        }


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



