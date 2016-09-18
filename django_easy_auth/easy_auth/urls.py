from django.conf.urls import url
import views


urlpatterns = [
    url(r'^api-token-auth/', views.obtain_jwt_for_user),
    url(r'^api-token-refresh/', views.refresh_jwt_token),
    url(r'^api-token-verify/', views.verify_jwt_token),
    url(r'^password-reset-token/', views.password_reset_token),
    url(r'^change-password/', views.change_password),
    url(r'^invalidate-all-tokens/', views.invalidate_all_tokens),
    url(r'^api-facebook-auth/', views.facebook_auth),
    url(r'^login-page/', views.view_login_page),
]