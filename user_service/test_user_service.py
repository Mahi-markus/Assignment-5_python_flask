from typing import Generator, Dict, Any
import pytest
import json
import jwt
from datetime import datetime, timedelta
from flask import Flask
from unittest.mock import patch, mock_open, MagicMock
from flask.testing import FlaskClient
from _pytest.fixtures import FixtureRequest

# Import the main application code
from routes import app, UserService, SECRET_KEY

@pytest.fixture
def client(request: FixtureRequest) -> Generator[FlaskClient, None, None]:
    """Create a test client fixture"""
    app.config['TESTING'] = True
    with app.test_client() as test_client:
        yield test_client

@pytest.fixture
def mock_users() -> Dict[str, Any]:
    """Fixture for mock user data"""
    return {
        "test-uuid": {
            "id": "test-uuid",
            "name": "Test User",
            "email": "test@example.com",
            "password": UserService.hash_password("password123"),
            "role": "User",
            "created_at": datetime.utcnow().isoformat()
        },
        "admin-uuid": {
            "id": "admin-uuid",
            "name": "Admin User",
            "email": "admin@example.com",
            "password": UserService.hash_password("admin123"),
            "role": "Admin",
            "created_at": datetime.utcnow().isoformat()
        }
    }

@pytest.fixture
def mock_json_file(mock_users: Dict[str, Any]) -> Generator[None, None, None]:
    """Mock the JSON file operations"""
    with patch("builtins.open", mock_open(read_data=json.dumps(mock_users))):
        yield

class TestUserService:
    """Test cases for UserService class"""

    def test_validate_email(self) -> None:
        """Test email validation"""
        assert UserService.validate_email("valid@example.com") == True
        assert UserService.validate_email("invalid-email") == False
        assert UserService.validate_email("") == False

    def test_hash_password(self) -> None:
        """Test password hashing"""
        password = "test123"
        hashed = UserService.hash_password(password)
        assert isinstance(hashed, str)
        assert len(hashed) == 64  # SHA-256 produces 64 character hex string
        assert hashed == UserService.hash_password(password)  # Consistent hashing

    def test_generate_token(self) -> None:
        """Test JWT token generation"""
        user_id = "test-id"
        role = "User"
        token = UserService.generate_token(user_id, role)
        
        # Decode and verify token
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        assert payload['user_id'] == user_id
        assert payload['role'] == role
        assert 'exp' in payload

class TestAuthEndpoints:
    """Test cases for authentication endpoints"""

    def test_register_success(self, client: FlaskClient, mock_json_file: None) -> None:
        """Test successful user registration"""
        with patch('uuid.uuid4', return_value="new-test-uuid"):
            response = client.post('/register', json={
                "name": "New User",
                "email": "new@example.com",
                "password": "password123"
            })
            
            assert response.status_code == 201
            data = json.loads(response.data)
            assert data["id"] == "new-test-uuid"
            assert "message" in data

    def test_register_invalid_data(self, client: FlaskClient) -> None:
        """Test registration with invalid data"""
        # Test missing fields
        response = client.post('/register', json={})
        assert response.status_code == 400

        # Test invalid email
        response = client.post('/register', json={
            "name": "Test User",
            "email": "invalid-email",
            "password": "password123"
        })
        assert response.status_code == 400

        # Test short password
        response = client.post('/register', json={
            "name": "Test User",
            "email": "test@example.com",
            "password": "short"
        })
        assert response.status_code == 400

    def test_login_success(self, client: FlaskClient, mock_json_file: None) -> None:
        """Test successful login"""
        response = client.post('/login', json={
            "email": "test@example.com",
            "password": "password123"
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "token" in data
        assert data["email"] == "test@example.com"
        assert data["role"] == "User"

    def test_login_failure(self, client: FlaskClient, mock_json_file: None) -> None:
        """Test login failures"""
        # Test wrong password
        response = client.post('/login', json={
            "email": "test@example.com",
            "password": "wrongpassword"
        })
        assert response.status_code == 401

        # Test non-existent user
        response = client.post('/login', json={
            "email": "nonexistent@example.com",
            "password": "password123"
        })
        assert response.status_code == 401

class TestProtectedEndpoints:
    """Test cases for protected endpoints"""

    def test_get_profile_authorized(self, client: FlaskClient, mock_json_file: None) -> None:
        """Test profile access with valid token"""
        token = UserService.generate_token("test-uuid", "User")
        response = client.get('/profile', headers={
            'Authorization': f'Bearer {token}'
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["email"] == "test@example.com"
        assert data["role"] == "User"

    def test_get_profile_unauthorized(self, client: FlaskClient) -> None:
        """Test profile access with invalid token"""
        # Test missing token
        response = client.get('/profile')
        assert response.status_code == 401

        # Test invalid token
        response = client.get('/profile', headers={
            'Authorization': 'Bearer invalid-token'
        })
        assert response.status_code == 401

    def test_get_users_admin(self, client: FlaskClient, mock_json_file: None) -> None:
        """Test admin access to users list"""
        token = UserService.generate_token("admin-uuid", "Admin")
        response = client.get('/users', headers={
            'Authorization': f'Bearer {token}'
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "users" in data
        assert len(data["users"]) > 0

    def test_get_users_non_admin(self, client: FlaskClient, mock_json_file: None) -> None:
        """Test non-admin access to users list"""
        token = UserService.generate_token("test-uuid", "User")
        response = client.get('/users', headers={
            'Authorization': f'Bearer {token}'
        })
        
        assert response.status_code == 403

    def test_expired_token(self, client: FlaskClient) -> None:
        """Test access with expired token"""
        # Create an expired token
        payload = {
            'user_id': 'test-uuid',
            'role': 'User',
            'exp': datetime.utcnow() - timedelta(hours=1)
        }
        expired_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        
        response = client.get('/profile', headers={
            'Authorization': f'Bearer {expired_token}'
        })
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data["error"] == "Token has expired"