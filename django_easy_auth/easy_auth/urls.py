from django.conf.urls import url
import views
from rest_framework_jwt.views import refresh_jwt_token, verify_jwt_token


urlpatterns = [
    url(r'^api-token-auth/', views.obtain_jwt_for_user),
    url(r'^api-token-refresh/', refresh_jwt_token),
    url(r'^api-token-verify/', verify_jwt_token),
]