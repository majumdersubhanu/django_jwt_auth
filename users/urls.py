# users/urls.py

from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView,
)

from users.views import CustomTokenObtainPairView, RegisterView, LogoutView, ProtectedView

urlpatterns = [
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('create/', RegisterView.as_view(), name='user_create'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('logout/', LogoutView.as_view(), name='auth_logout'),
    path('protected/', ProtectedView.as_view(), name='protected'),
]
