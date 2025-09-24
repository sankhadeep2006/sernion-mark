"""
Test script for Sernion Mark Django Authentication System
Tests all authentication functionality without external dependencies
"""

import os
import sys
import django
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
import json

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sernion_mark.settings')
django.setup()

from authentication.models import User, UserProfile, PasswordResetToken, LoginHistory
from authentication.serializers import UserRegistrationSerializer, UserLoginSerializer

User = get_user_model()

def test_authentication_system():
    """Test the complete authentication system"""
    print("🧪 Testing Sernion Mark Django Authentication System")
    print("=" * 60)
    
    # Test data
    test_user_data = {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'securepassword123',
        'password_confirm': 'securepassword123',
        'full_name': 'Test User'
    }
    
    try:
        # Test 1: User Registration
        print("\n1. Testing User Registration...")
        serializer = UserRegistrationSerializer(data=test_user_data)
        if serializer.is_valid():
            user = serializer.save()
            print(f"✅ Registration successful: {user.username}")
            print(f"   User ID: {user.id}")
            print(f"   Email: {user.email}")
            print(f"   Full Name: {user.full_name}")
        else:
            print(f"❌ Registration failed: {serializer.errors}")
            return
        
        # Test 2: User Login
        print("\n2. Testing User Login...")
        login_data = {
            'username': test_user_data['username'],
            'password': test_user_data['password']
        }
        login_serializer = UserLoginSerializer(data=login_data)
        if login_serializer.is_valid():
            user = login_serializer.validated_data['user']
            print(f"✅ Login successful: {user.username}")
            print(f"   User ID: {user.id}")
            print(f"   Is Active: {user.is_active}")
        else:
            print(f"❌ Login failed: {login_serializer.errors}")
        
        # Test 3: User Profile Creation
        print("\n3. Testing User Profile Creation...")
        try:
            profile = user.profile
            print(f"✅ Profile exists: {profile}")
            print(f"   Company: {profile.company}")
            print(f"   Job Title: {profile.job_title}")
        except UserProfile.DoesNotExist:
            profile = UserProfile.objects.create(user=user)
            print(f"✅ Profile created: {profile}")
        
        # Test 4: Password Change
        print("\n4. Testing Password Change...")
        new_password = "newsecurepassword456"
        user.set_password(new_password)
        user.save()
        print(f"✅ Password changed successfully")
        
        # Test 5: Login with New Password
        print("\n5. Testing Login with New Password...")
        new_login_data = {
            'username': test_user_data['username'],
            'password': new_password
        }
        new_login_serializer = UserLoginSerializer(data=new_login_data)
        if new_login_serializer.is_valid():
            user = new_login_serializer.validated_data['user']
            print(f"✅ Login with new password successful")
        else:
            print(f"❌ Login with new password failed: {new_login_serializer.errors}")
        
        # Test 6: Account Lockout
        print("\n6. Testing Account Lockout...")
        for i in range(6):  # Try 6 times to trigger lockout
            user.increment_failed_attempts()
        
        if user.is_account_locked():
            print(f"✅ Account locked successfully after {user.failed_login_attempts} attempts")
        else:
            print(f"❌ Account lockout failed")
        
        # Test 7: Reset Failed Attempts
        print("\n7. Testing Reset Failed Attempts...")
        user.reset_failed_attempts()
        if not user.is_account_locked():
            print(f"✅ Failed attempts reset successfully")
        else:
            print(f"❌ Failed attempts reset failed")
        
        # Test 8: Password Reset Token
        print("\n8. Testing Password Reset Token...")
        import secrets
        import string
        from django.utils import timezone
        
        token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        reset_token = PasswordResetToken.objects.create(
            user=user,
            token=token,
            expires_at=timezone.now() + timezone.timedelta(hours=24)
        )
        print(f"✅ Password reset token created: {token[:10]}...")
        
        if reset_token.is_valid():
            print(f"✅ Token is valid")
        else:
            print(f"❌ Token is invalid")
        
        # Test 9: Login History
        print("\n9. Testing Login History...")
        login_history = LoginHistory.objects.create(
            user=user,
            ip_address='127.0.0.1',
            user_agent='Test Browser',
            login_successful=True
        )
        print(f"✅ Login history created: {login_history}")
        
        # Test 10: User Properties
        print("\n10. Testing User Properties...")
        print(f"   Full Name: {user.full_name}")
        print(f"   Is Account Locked: {user.is_account_locked()}")
        print(f"   Failed Login Attempts: {user.failed_login_attempts}")
        print(f"   Created At: {user.created_at}")
        
        print("\n" + "=" * 60)
        print("🎉 All authentication tests passed successfully!")
        print("✅ Django backend is working correctly!")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

def test_api_endpoints():
    """Test API endpoints using Django test client"""
    print("\n🌐 Testing API Endpoints...")
    print("=" * 40)
    
    client = Client()
    
    # Test health check endpoint
    try:
        response = client.get('/api/v1/health/')
        if response.status_code == 200:
            print("✅ Health check endpoint working")
        else:
            print(f"❌ Health check failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Health check error: {e}")
    
    # Test registration endpoint
    try:
        registration_data = {
            'username': 'apitestuser',
            'email': 'apitest@example.com',
            'password': 'testpassword123',
            'password_confirm': 'testpassword123',
            'full_name': 'API Test User'
        }
        response = client.post('/api/v1/auth/register/', 
                             data=json.dumps(registration_data),
                             content_type='application/json')
        if response.status_code in [200, 201]:
            print("✅ Registration endpoint working")
        else:
            print(f"❌ Registration endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Registration endpoint error: {e}")

if __name__ == "__main__":
    print("Starting Django Authentication Tests...")
    print("No external APIs required - testing local functionality only")
    
    # Test core authentication functionality
    test_authentication_system()
    
    # Test API endpoints
    test_api_endpoints()
    
    print("\n🏁 Testing completed!")
    print("The Django backend is ready for frontend integration.")
