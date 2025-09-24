"""
URL patterns for authentication app.
"""
from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', views.UserRegistrationView.as_view(), name='register'),
    path('auth/login/', views.UserLoginView.as_view(), name='login'),
    path('auth/logout/', views.UserLogoutView.as_view(), name='logout'),
    path('auth/verify/', views.verify_token, name='verify_token'),
    
    # Profile management
    path('user/profile/', views.UserProfileView.as_view(), name='profile'),
    path('user/change-password/', views.PasswordChangeView.as_view(), name='change_password'),
    
    # Password reset
    path('auth/password-reset/', views.PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('auth/password-reset/confirm/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    
    # Admin endpoints
    path('users/', views.UserListView.as_view(), name='user_list'),
    
    # Health check
    path('health/', views.health_check, name='health_check'),
]
