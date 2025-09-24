"""
Simple API test script for Sernion Mark backend
"""
import json

import requests

# API base URL
BASE_URL = "http://localhost:8000/api/v1"

def test_health_check():
    """Test health check endpoint"""
    print("🏥 Testing Health Check...")
    try:
        response = requests.get(f"{BASE_URL}/health/")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health check successful: {data}")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_user_registration():
    """Test user registration endpoint"""
    print("\n👤 Testing User Registration...")
    try:
        user_data = {
            "username": "apitestuser",
            "email": "apitest@example.com",
            "password": "testpassword123",
            "password_confirm": "testpassword123",
            "full_name": "API Test User"
        }
        
        response = requests.post(
            f"{BASE_URL}/auth/register/",
            json=user_data,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code in [200, 201]:
            data = response.json()
            print(f"✅ Registration successful: {data['message']}")
            print(f"   User: {data['user']['username']}")
            print(f"   Token: {data['token'][:20]}...")
            return data['token']
        else:
            print(f"❌ Registration failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return None

def test_user_login():
    """Test user login endpoint"""
    print("\n🔐 Testing User Login...")
    try:
        login_data = {
            "username": "apitestuser",
            "password": "testpassword123"
        }
        
        response = requests.post(
            f"{BASE_URL}/auth/login/",
            json=login_data,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Login successful: {data['message']}")
            print(f"   User: {data['user']['username']}")
            print(f"   Token: {data['token'][:20]}...")
            return data['token']
        else:
            print(f"❌ Login failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
    except Exception as e:
        print(f"❌ Login error: {e}")
        return None

def test_protected_endpoint(token):
    """Test a protected endpoint"""
    print("\n🔒 Testing Protected Endpoint...")
    try:
        headers = {
            'Authorization': f'Token {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(
            f"{BASE_URL}/auth/verify/",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Token verification successful: {data['message']}")
            print(f"   User: {data['user']['username']}")
            return True
        else:
            print(f"❌ Token verification failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Token verification error: {e}")
        return False

def test_user_profile(token):
    """Test user profile endpoint"""
    print("\n👤 Testing User Profile...")
    try:
        headers = {
            'Authorization': f'Token {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(
            f"{BASE_URL}/user/profile/",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Profile retrieval successful")
            print(f"   Username: {data['profile']['username']}")
            print(f"   Email: {data['profile']['email']}")
            return True
        else:
            print(f"❌ Profile retrieval failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Profile retrieval error: {e}")
        return False

def test_logout(token):
    """Test logout endpoint"""
    print("\n🚪 Testing Logout...")
    try:
        headers = {
            'Authorization': f'Token {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            f"{BASE_URL}/auth/logout/",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Logout successful: {data['message']}")
            return True
        else:
            print(f"❌ Logout failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Logout error: {e}")
        return False

def main():
    """Run all API tests"""
    print("🚀 Testing Sernion Mark Django API")
    print("=" * 50)
    print("No Google API required - testing local functionality only")
    print()
    
    # Test health check
    if not test_health_check():
        print("❌ Health check failed. Is the server running?")
        return
    
    # Test registration
    token = test_user_registration()
    if not token:
        print("❌ Registration failed")
        return
    
    # Test login
    login_token = test_user_login()
    if not login_token:
        print("❌ Login failed")
        return
    
    # Test protected endpoint
    if not test_protected_endpoint(login_token):
        print("❌ Protected endpoint test failed")
        return
    
    # Test user profile
    if not test_user_profile(login_token):
        print("❌ Profile test failed")
        return
    
    # Test logout
    if not test_logout(login_token):
        print("❌ Logout test failed")
        return
    
    print("\n" + "=" * 50)
    print("🎉 All API tests passed successfully!")
    print("✅ Django backend is working perfectly!")
    print("✅ No external APIs required!")
    print("✅ Ready for frontend integration!")

if __name__ == "__main__":
    main()
