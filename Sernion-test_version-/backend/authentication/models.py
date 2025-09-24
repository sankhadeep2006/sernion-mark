"""
Authentication models for Sernion Mark.
"""
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    """
    Custom User model with extended fields for Sernion Mark.
    """
    # Override email to be unique and required
    email = models.EmailField(unique=True, blank=False)
    
    # Additional fields
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    phone_number = models.CharField(validators=[phone_regex], max_length=17, blank=True)
    
    # Profile fields
    bio = models.TextField(max_length=500, blank=True)
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    
    # Account status
    is_verified = models.BooleanField(default=False)
    email_verified_at = models.DateTimeField(blank=True, null=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(blank=True, null=True)
    
    # Failed login attempts tracking
    failed_login_attempts = models.PositiveIntegerField(default=0)
    account_locked_until = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        db_table = 'auth_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return self.username
    
    @property
    def full_name(self):
        """Return the user's full name."""
        return f"{self.first_name} {self.last_name}".strip() or self.username
    
    def is_account_locked(self):
        """Check if the account is currently locked."""
        if self.account_locked_until and self.account_locked_until > timezone.now():
            return True
        return False
    
    def increment_failed_attempts(self):
        """Increment failed login attempts."""
        self.failed_login_attempts += 1
        self.save(update_fields=['failed_login_attempts'])
    
    def reset_failed_attempts(self):
        """Reset failed login attempts."""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save(update_fields=['failed_login_attempts', 'account_locked_until'])
    
    def lock_account(self, duration_minutes=15):
        """Lock the account for a specified duration."""
        from datetime import timedelta
        self.account_locked_until = timezone.now() + timedelta(minutes=duration_minutes)
        self.save(update_fields=['account_locked_until'])


class UserProfile(models.Model):
    """
    Extended user profile information.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # Professional information
    company = models.CharField(max_length=100, blank=True)
    job_title = models.CharField(max_length=100, blank=True)
    website = models.URLField(blank=True)
    
    # Preferences
    preferred_language = models.CharField(max_length=10, default='en')
    timezone = models.CharField(max_length=50, default='UTC')
    
    # Notification preferences
    email_notifications = models.BooleanField(default=True)
    push_notifications = models.BooleanField(default=True)
    
    # Privacy settings
    profile_visibility = models.CharField(
        max_length=20,
        choices=[
            ('public', 'Public'),
            ('private', 'Private'),
            ('friends', 'Friends Only'),
        ],
        default='public'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_profile'
    
    def __str__(self):
        return f"{self.user.username}'s Profile"


class PasswordResetToken(models.Model):
    """
    Model for password reset tokens.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'password_reset_token'
    
    def __str__(self):
        return f"Reset token for {self.user.username}"
    
    def is_expired(self):
        """Check if the token has expired."""
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Check if the token is valid and not used."""
        return not self.is_used and not self.is_expired()


class LoginHistory(models.Model):
    """
    Model to track user login history.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='login_history')
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    login_successful = models.BooleanField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'login_history'
        verbose_name = 'Login History'
        verbose_name_plural = 'Login Histories'
        ordering = ['-created_at']
    
    def __str__(self):
        status = "Success" if self.login_successful else "Failed"
        return f"{self.user.username} - {status} - {self.created_at}"
