"""
Views for authentication app.
"""
import secrets
import string

from django.conf import settings
from django.contrib.auth import login, logout
from django.core.mail import send_mail
from django.utils import timezone
from rest_framework import generics, permissions, status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import LoginHistory, PasswordResetToken, User, UserProfile
from .serializers import (PasswordChangeSerializer,
                          PasswordResetConfirmSerializer,
                          PasswordResetRequestSerializer, UserListSerializer,
                          UserLoginSerializer, UserProfileSerializer,
                          UserRegistrationSerializer, UserUpdateSerializer)


class UserRegistrationView(APIView):
    """
    User registration endpoint.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Register a new user."""
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Generate token
            token, created = Token.objects.get_or_create(user=user)
            
            # Create login history entry
            LoginHistory.objects.create(
                user=user,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                login_successful=True
            )
            
            return Response({
                'success': True,
                'message': 'User registered successfully',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'full_name': user.full_name,
                },
                'token': token.key
            }, status=status.HTTP_201_CREATED)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserLoginView(APIView):
    """
    User login endpoint.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Authenticate and login user."""
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Reset failed login attempts
            user.reset_failed_attempts()
            
            # Update last login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            # Generate token
            token, created = Token.objects.get_or_create(user=user)
            
            # Create login history entry
            LoginHistory.objects.create(
                user=user,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                login_successful=True
            )
            
            return Response({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'full_name': user.full_name,
                    'is_verified': user.is_verified,
                },
                'token': token.key
            }, status=status.HTTP_200_OK)
        
        # Handle failed login
        username = request.data.get('username')
        if username:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                try:
                    user = User.objects.get(email=username)
                except User.DoesNotExist:
                    user = None
            
            if user:
                # Increment failed login attempts
                user.increment_failed_attempts()
                
                # Lock account if too many failed attempts
                if user.failed_login_attempts >= 5:
                    user.lock_account()
                
                # Create failed login history entry
                LoginHistory.objects.create(
                    user=user,
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    login_successful=False
                )
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_401_UNAUTHORIZED)
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserLogoutView(APIView):
    """
    User logout endpoint.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Logout user and delete token."""
        try:
            # Delete the user's token
            Token.objects.filter(user=request.user).delete()
            
            return Response({
                'success': True,
                'message': 'Logout successful'
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Logout failed'
            }, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    """
    User profile management.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get user profile."""
        try:
            profile = request.user.profile
            serializer = UserProfileSerializer(profile)
            return Response({
                'success': True,
                'profile': serializer.data
            }, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            # Create profile if it doesn't exist
            profile = UserProfile.objects.create(user=request.user)
            serializer = UserProfileSerializer(profile)
            return Response({
                'success': True,
                'profile': serializer.data
            }, status=status.HTTP_200_OK)
    
    def put(self, request):
        """Update user profile."""
        try:
            profile = request.user.profile
        except UserProfile.DoesNotExist:
            profile = UserProfile.objects.create(user=request.user)
        
        # Update user fields
        user_serializer = UserUpdateSerializer(request.user, data=request.data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()
        
        # Update profile fields
        profile_serializer = UserProfileSerializer(profile, data=request.data, partial=True)
        if profile_serializer.is_valid():
            profile_serializer.save()
        
        if user_serializer.is_valid() and profile_serializer.is_valid():
            return Response({
                'success': True,
                'message': 'Profile updated successfully',
                'profile': profile_serializer.data
            }, status=status.HTTP_200_OK)
        
        errors = {}
        if not user_serializer.is_valid():
            errors.update(user_serializer.errors)
        if not profile_serializer.is_valid():
            errors.update(profile_serializer.errors)
        
        return Response({
            'success': False,
            'errors': errors
        }, status=status.HTTP_400_BAD_REQUEST)


class PasswordChangeView(APIView):
    """
    Password change endpoint.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Change user password."""
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            new_password = serializer.validated_data['new_password']
            
            # Change password
            user.set_password(new_password)
            user.save()
            
            return Response({
                'success': True,
                'message': 'Password changed successfully'
            }, status=status.HTTP_200_OK)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):
    """
    Password reset request endpoint.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Request password reset."""
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            
            # Generate reset token
            token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
            
            # Create or update reset token
            reset_token, created = PasswordResetToken.objects.get_or_create(
                user=user,
                defaults={
                    'token': token,
                    'expires_at': timezone.now() + timezone.timedelta(hours=24)
                }
            )
            
            if not created:
                reset_token.token = token
                reset_token.expires_at = timezone.now() + timezone.timedelta(hours=24)
                reset_token.is_used = False
                reset_token.save()
            
            # Send email (in production, use proper email templates)
            try:
                reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
                send_mail(
                    'Password Reset Request',
                    f'Click the following link to reset your password: {reset_url}',
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )
                
                return Response({
                    'success': True,
                    'message': 'Password reset email sent successfully'
                }, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({
                    'success': False,
                    'message': 'Failed to send password reset email'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    """
    Password reset confirmation endpoint.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Confirm password reset."""
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']
            
            try:
                reset_token = PasswordResetToken.objects.get(token=token)
                
                if not reset_token.is_valid():
                    return Response({
                        'success': False,
                        'message': 'Invalid or expired reset token'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Change password
                user = reset_token.user
                user.set_password(new_password)
                user.save()
                
                # Mark token as used
                reset_token.is_used = True
                reset_token.save()
                
                return Response({
                    'success': True,
                    'message': 'Password reset successfully'
                }, status=status.HTTP_200_OK)
                
            except PasswordResetToken.DoesNotExist:
                return Response({
                    'success': False,
                    'message': 'Invalid reset token'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class UserListView(generics.ListAPIView):
    """
    List users (admin only).
    """
    queryset = User.objects.filter(is_active=True)
    serializer_class = UserListSerializer
    permission_classes = [permissions.IsAdminUser]


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def verify_token(request):
    """Verify token."""
    return Response({
        'success': True,
        'message': 'Token is valid',
        'user': {
            'id': request.user.id,
            'username': request.user.username,
            'email': request.user.email,
            'full_name': request.user.full_name,
            'is_verified': request.user.is_verified,
        }
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def health_check(request):
    """Health check endpoint."""
    return Response({
        'status': 'healthy',
        'service': 'Sernion Mark Authentication API',
        'timestamp': timezone.now().isoformat()
    }, status=status.HTTP_200_OK)
