import pytest
import json
import jwt
from datetime import datetime, timedelta
from flask import Flask
from flask.testing import FlaskClient
from unittest.mock import patch, mock_open, MagicMock
import os

# Assuming your main application file is named 'app.py'
# Update this import statement to match your actual file name
from routes import app, UserService, USERS_FILE

# Get SECRET_KEY from environment or set a test key
SECRET_KEY = os.getenv('SECRET_KEY', 'test-secret-key')

@pytest.fixture
def client():
    """Create a test client for the Flask application"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_users():
    """Mock user data for testing"""
    return {
        "test-uuid": {
            "id": "test-uuid",
            "name": "Test User",
            "email": "test@example.com",
            "password": UserService.hash_password("password123"),
            "role": "User",
            "created_at": datetime.utcnow().isoformat()
        }
    }

@pytest.fixture
def mock_file_operations(mock_users):
    """Mock file operations for users.json"""
    with patch("builtins.open", mock_open(read_data=json.dumps(mock_users))):
        yield

class TestUserService:
    def test_validate_email_valid(self):
        """Test email validation with valid email"""
        assert UserService.validate_email("test@example.com") is True

    def test_validate_email_invalid(self):
        """Test email validation with invalid email"""
        assert UserService.validate_email("invalid-email") is False

    def test_hash_password(self):
        """Test password hashing"""
        password = "password123"
        hashed = UserService.hash_password(password)
        assert isinstance(hashed, str)
        assert len(hashed) == 64  # SHA-256 produces 64 character hex string

    def test_generate_token(self):
        """Test JWT token generation"""
        user_id = "test-uuid"
        role = "User"
        token = UserService.generate_token(user_id, role)
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        assert decoded['user_id'] == user_id
        assert decoded['role'] == role

    def test_validate_token_valid(self):
        """Test token validation with valid token"""
        token = UserService.generate_token("test-uuid", "User")
        payload = UserService.validate_token(token)
        assert payload is not None
        assert payload['user_id'] == "test-uuid"

    def test_validate_token_expired(self):
        """Test token validation with expired token"""
        payload = {
            'user_id': 'test-uuid',
            'role': 'User',
            'exp': datetime.utcnow() - timedelta(hours=1)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        assert UserService.validate_token(token) is None

class TestRegistrationEndpoint:
    def test_register_success(self, client, mock_file_operations):
        """Test successful user registration"""
        data = {
            "name": "New User",
            "email": "new@example.com",
            "password": "password123"
        }
        response = client.post('/register', 
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 201
        assert 'id' in response.json
        assert response.json['message'] == "User registered successfully"

    def test_register_invalid_email(self, client):
        """Test registration with invalid email"""
        data = {
            "name": "New User",
            "email": "invalid-email",
            "password": "password123"
        }
        response = client.post('/register',
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 400
        assert response.json['error'] == "Invalid email format"

    def test_register_missing_fields(self, client):
        """Test registration with missing fields"""
        data = {
            "name": "New User"
        }
        response = client.post('/register',
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 400
        assert response.json['error'] == "All fields are required"

class TestLoginEndpoint:
    def test_login_success(self, client, mock_file_operations, mock_users):
        """Test successful login"""
        data = {
            "email": "test@example.com",
            "password": "password123"
        }
        response = client.post('/login',
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 200
        assert 'token' in response.json
        assert response.json['email'] == data['email']

    def test_login_invalid_credentials(self, client, mock_file_operations):
        """Test login with invalid credentials"""
        data = {
            "email": "test@example.com",
            "password": "wrongpassword"
        }
        response = client.post('/login',
                             json=data,
                             content_type='application/json')
        
        assert response.status_code == 401
        assert response.json['error'] == "Invalid credentials"

class TestProfileEndpoint:
    def test_get_profile_success(self, client, mock_file_operations, mock_users):
        """Test successful profile retrieval"""
        # Generate valid token
        token = UserService.generate_token("test-uuid", "User")
        
        response = client.get('/profile?user_id=test-uuid',
                            headers={'Authorization': f'Bearer {token}'})
        
        assert response.status_code == 200
        assert response.json['email'] == "test@example.com"
        assert 'password' not in response.json

    def test_get_profile_unauthorized(self, client, mock_file_operations):
        """Test profile retrieval with invalid token"""
        response = client.get('/profile?user_id=test-uuid',
                            headers={'Authorization': 'Bearer invalid-token'})
        
        assert response.status_code == 401
        assert response.json['error'] == "Invalid or expired token"

    def test_get_profile_wrong_user(self, client, mock_file_operations):
        """Test profile retrieval for wrong user"""
        # Generate token for different user
        token = UserService.generate_token("other-uuid", "User")
        
        response = client.get('/profile?user_id=test-uuid',
                            headers={'Authorization': f'Bearer {token}'})
        
        assert response.status_code == 403
        assert response.json['error'] == "Unauthorized to access this profile"

if __name__ == '__main__':
    pytest.main(['-v'])