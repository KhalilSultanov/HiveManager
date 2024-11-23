from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import (
    RegisterView, VerifyEmailView, UserDetailView, UserListView,
    UserDetailAdminView, login_view, register_view, home_view, logout_view, email_confirmation_view,
)

urlpatterns = [
    # API Endpoints
    path('register-api/', RegisterView.as_view(), name='api_register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify_email'),
    path('users/me/', UserDetailView.as_view(), name='user_detail'),
    path('users/', UserListView.as_view(), name='user_list'),
    path('users/<int:user_id>/', UserDetailAdminView.as_view(), name='user_detail_admin'),
    path('email-confirmation/', email_confirmation_view, name='email_confirmation'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify_email'),

    # JWT Endpoints
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('accounts/', include('allauth.urls')),  # Все URL от django-allauth

    # Web Views
    path('register/', register_view, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('', home_view, name='home'),
]
