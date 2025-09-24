"""
Serializers for authentication app.
"""
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework import serializers

from .models import User, UserProfile


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.
    """
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    full_name = serializers.CharField(max_length=150, required=False)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'full_name', 'phone_number']
        extra_kwargs = {
            'username': {'min_length': 3},
            'email': {'required': True},
        }
    
    def validate(self, attrs):
        """Validate registration data."""
        # Check if passwords match
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        
        # Validate password strength
        try:
            validate_password(attrs['password'])
        except ValidationError as e:
            raise serializers.ValidationError({'password': e.messages})
        
        # Check if username or email already exists
        username = attrs.get('username')
        email = attrs.get('email')
        
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError({'username': 'Username already exists.'})
        
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({'email': 'Email already exists.'})
        
        return attrs
    
    def create(self, validated_data):
        """Create a new user."""
        # Extract full_name and split into first_name and last_name
        full_name = validated_data.pop('full_name', '')
        password_confirm = validated_data.pop('password_confirm', '')
        
        # Split full name into first and last name
        name_parts = full_name.split(' ', 1)
        if len(name_parts) > 1:
            validated_data['first_name'] = name_parts[0]
            validated_data['last_name'] = name_parts[1]
        elif full_name:
            validated_data['first_name'] = full_name
        
        # Create user
        user = User.objects.create_user(**validated_data)
        
        # Create user profile
        UserProfile.objects.create(user=user)
        
        return user


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login.
    """
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128, write_only=True)
    
    def validate(self, attrs):
        """Validate login credentials."""
        username = attrs.get('username')
        password = attrs.get('password')
        
        if username and password:
            # Try to authenticate with username or email
            user = authenticate(username=username, password=password)
            
            if not user:
                # Try with email
                try:
                    user_obj = User.objects.get(email=username)
                    user = authenticate(username=user_obj.username, password=password)
                except User.DoesNotExist:
                    pass
            
            if not user:
                raise serializers.ValidationError('Invalid credentials.')
            
            if not user.is_active:
                raise serializers.ValidationError('Account is disabled.')
            
            if user.is_account_locked():
                raise serializers.ValidationError('Account is temporarily locked due to too many failed attempts.')
            
            attrs['user'] = user
        else:
            raise serializers.ValidationError('Must include username and password.')
        
        return attrs


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile.
    """
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    full_name = serializers.CharField(source='user.full_name', read_only=True)
    avatar = serializers.ImageField(source='user.avatar', read_only=True)
    bio = serializers.CharField(source='user.bio', read_only=True)
    
    class Meta:
        model = UserProfile
        fields = [
            'username', 'email', 'full_name', 'avatar', 'bio',
            'company', 'job_title', 'website', 'preferred_language',
            'timezone', 'email_notifications', 'push_notifications',
            'profile_visibility'
        ]


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user information.
    """
    first_name = serializers.CharField(max_length=150, required=False)
    last_name = serializers.CharField(max_length=150, required=False)
    email = serializers.EmailField(required=False)
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'bio', 'avatar']
    
    def validate_email(self, value):
        """Validate email uniqueness."""
        user = self.context['request'].user
        if User.objects.exclude(pk=user.pk).filter(email=value).exists():
            raise serializers.ValidationError('Email already exists.')
        return value
    
    def update(self, instance, validated_data):
        """Update user instance."""
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for password change.
    """
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8)
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Validate password change data."""
        user = self.context['request'].user
        current_password = attrs.get('current_password')
        new_password = attrs.get('new_password')
        new_password_confirm = attrs.get('new_password_confirm')
        
        # Check current password
        if not user.check_password(current_password):
            raise serializers.ValidationError({'current_password': 'Current password is incorrect.'})
        
        # Check if new passwords match
        if new_password != new_password_confirm:
            raise serializers.ValidationError({'new_password_confirm': 'New passwords don\'t match.'})
        
        # Validate new password strength
        try:
            validate_password(new_password)
        except ValidationError as e:
            raise serializers.ValidationError({'new_password': e.messages})
        
        return attrs


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for password reset request.
    """
    email = serializers.EmailField()
    
    def validate_email(self, value):
        """Validate email exists."""
        if not User.objects.filter(email=value, is_active=True).exists():
            raise serializers.ValidationError('No active user found with this email address.')
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for password reset confirmation.
    """
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, min_length=8)
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Validate password reset data."""
        new_password = attrs.get('new_password')
        new_password_confirm = attrs.get('new_password_confirm')
        
        # Check if passwords match
        if new_password != new_password_confirm:
            raise serializers.ValidationError({'new_password_confirm': 'Passwords don\'t match.'})
        
        # Validate password strength
        try:
            validate_password(new_password)
        except ValidationError as e:
            raise serializers.ValidationError({'new_password': e.messages})
        
        return attrs


class UserListSerializer(serializers.ModelSerializer):
    """
    Serializer for listing users (limited information).
    """
    full_name = serializers.CharField(source='full_name', read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'full_name', 'email', 'is_active', 'created_at']
        read_only_fields = ['id', 'created_at']
