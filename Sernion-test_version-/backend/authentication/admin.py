"""
Admin configuration for authentication app.
"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import LoginHistory, PasswordResetToken, User, UserProfile


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin configuration for User model."""
    list_display = ['username', 'email', 'full_name', 'is_active', 'is_verified', 'created_at', 'last_login']
    list_filter = ['is_active', 'is_verified', 'is_staff', 'is_superuser', 'created_at', 'last_login']
    search_fields = ['username', 'email', 'first_name', 'last_name']
    ordering = ['-created_at']
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Sernion Mark Profile', {
            'fields': ('phone_number', 'bio', 'avatar', 'date_of_birth', 'is_verified', 'email_verified_at')
        }),
        ('Security', {
            'fields': ('failed_login_attempts', 'account_locked_until')
        }),
    )
    
    readonly_fields = ['created_at', 'updated_at', 'last_login', 'failed_login_attempts', 'account_locked_until']


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin configuration for UserProfile model."""
    list_display = ['user', 'company', 'job_title', 'preferred_language', 'profile_visibility', 'created_at']
    list_filter = ['profile_visibility', 'email_notifications', 'push_notifications', 'created_at']
    search_fields = ['user__username', 'user__email', 'company', 'job_title']
    ordering = ['-created_at']
    
    fieldsets = (
        ('User Information', {
            'fields': ('user',)
        }),
        ('Professional Information', {
            'fields': ('company', 'job_title', 'website')
        }),
        ('Preferences', {
            'fields': ('preferred_language', 'timezone')
        }),
        ('Notifications', {
            'fields': ('email_notifications', 'push_notifications')
        }),
        ('Privacy', {
            'fields': ('profile_visibility',)
        }),
    )
    
    readonly_fields = ['created_at', 'updated_at']


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    """Admin configuration for PasswordResetToken model."""
    list_display = ['user', 'token', 'created_at', 'expires_at', 'is_used', 'is_expired']
    list_filter = ['is_used', 'created_at', 'expires_at']
    search_fields = ['user__username', 'user__email', 'token']
    ordering = ['-created_at']
    
    readonly_fields = ['created_at', 'is_expired']
    
    def is_expired(self, obj):
        """Display if token is expired."""
        return obj.is_expired()
    is_expired.boolean = True
    is_expired.short_description = 'Expired'


@admin.register(LoginHistory)
class LoginHistoryAdmin(admin.ModelAdmin):
    """Admin configuration for LoginHistory model."""
    list_display = ['user', 'ip_address', 'login_successful', 'created_at']
    list_filter = ['login_successful', 'created_at']
    search_fields = ['user__username', 'user__email', 'ip_address']
    ordering = ['-created_at']
    
    readonly_fields = ['user', 'ip_address', 'user_agent', 'login_successful', 'created_at']
    
    def has_add_permission(self, request):
        """Disable adding login history manually."""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Disable editing login history."""
        return False
