import pytest
from flask import session
import jwt
from datetime import datetime, timedelta
import json
from unittest.mock import patch, MagicMock
from routes import app, AuthService, SECRET_KEY
import requests

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_valid_token():
    payload = {
        'user_id': 'test123',
        'role': 'Admin',
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

@pytest.fixture
def mock_expired_token():
    payload = {
        'user_id': 'test123',
        'role': 'Admin',
        'exp': datetime.utcnow() - timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def test_login_success(client, mock_valid_token):
    """Test successful login with valid token"""
    response = client.post(
        '/login',
        headers={'Authorization': f'Bearer {mock_valid_token}'}
    )
    assert response.status_code == 200
    assert b'Login successful' in response.data
    with client.session_transaction() as sess:
        assert 'token' in sess
        assert 'user' in sess

def test_login_missing_token(client):
    """Test login attempt without token"""
    response = client.post('/login')
    assert response.status_code == 401
    assert b'No authorization token provided' in response.data

def test_login_expired_token(client, mock_expired_token):
    """Test login attempt with expired token"""
    response = client.post(
        '/login',
        headers={'Authorization': f'Bearer {mock_expired_token}'}
    )
    assert response.status_code == 401
    assert b'Invalid token' in response.data

def test_validate_token_success(client, mock_valid_token):
    """Test successful token validation"""
    with client.session_transaction() as sess:
        payload = jwt.decode(mock_valid_token, SECRET_KEY, algorithms=['HS256'])
        sess['token'] = mock_valid_token
        sess['user'] = payload

    response = client.get('/validate')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'Token is valid'
    assert data['user_id'] == 'test123'
    assert data['role'] == 'Admin'
    assert 'permissions' in data
    assert 'token_validity' in data

def test_validate_token_no_session(client):
    """Test token validation without active session"""
    response = client.get('/validate')
    assert response.status_code == 401
    assert b'Not authenticated' in response.data

def test_logout(client, mock_valid_token):
    """Test logout functionality"""
    # First login
    with client.session_transaction() as sess:
        payload = jwt.decode(mock_valid_token, SECRET_KEY, algorithms=['HS256'])
        sess['token'] = mock_valid_token
        sess['user'] = payload

    # Then logout
    response = client.post('/logout')
    assert response.status_code == 200
    assert b'Logout successful' in response.data
    
    # Verify session is cleared
    with client.session_transaction() as sess:
        assert 'token' not in sess
        assert 'user' not in sess

@patch('app.AuthService.get_user_info')
def test_token_info_success(mock_get_user_info, client, mock_valid_token):
    """Test retrieving detailed token information"""
    mock_user_info = {
        'name': 'Test User',
        'email': 'test@example.com'
    }
    mock_get_user_info.return_value = mock_user_info

    with client.session_transaction() as sess:
        payload = jwt.decode(mock_valid_token, SECRET_KEY, algorithms=['HS256'])
        sess['token'] = mock_valid_token
        sess['user'] = payload

    response = client.get('/token/info')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'token_info' in data
    assert 'user_info' in data
    assert data['user_info'] == mock_user_info
    assert data['token_info']['user_id'] == 'test123'
    assert data['token_info']['role'] == 'Admin'

@patch('app.AuthService.get_user_info')
def test_token_info_user_service_error(mock_get_user_info, client, mock_valid_token):
    """Test token info when user service is unavailable"""
    mock_get_user_info.return_value = None

    with client.session_transaction() as sess:
        payload = jwt.decode(mock_valid_token, SECRET_KEY, algorithms=['HS256'])
        sess['token'] = mock_valid_token
        sess['user'] = payload

    response = client.get('/token/info')
    assert response.status_code == 404
    assert b'Could not fetch user information' in response.data

def test_auth_service_decode_token():
    """Test AuthService token decoding"""
    # Test valid token
    payload = {
        'user_id': 'test123',
        'role': 'Admin',
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    decoded_payload, error = AuthService.decode_token(token)
    assert error is None
    assert decoded_payload['user_id'] == payload['user_id']
    assert decoded_payload['role'] == payload['role']

    # Test expired token
    expired_payload = {
        'user_id': 'test123',
        'exp': datetime.utcnow() - timedelta(hours=1)
    }
    expired_token = jwt.encode(expired_payload, SECRET_KEY, algorithm='HS256')
    decoded_payload, error = AuthService.decode_token(expired_token)
    assert decoded_payload is None
    assert "Token has expired" in error

def test_auth_service_format_expiration_time():
    """Test expiration time formatting"""
    exp_time = datetime.utcnow() + timedelta(hours=2)
    formatted_time = AuthService.format_expiration_time(exp_time.timestamp())
    
    assert 'expiration' in formatted_time
    assert 'valid_for' in formatted_time
    assert 'hours' in formatted_time['valid_for']
    assert 'minutes' in formatted_time['valid_for']

@patch('requests.get')
def test_auth_service_get_user_info_success(mock_get):
    """Test successful user info retrieval"""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {'name': 'Test User'}
    mock_get.return_value = mock_response

    result = AuthService.get_user_info('test123', 'valid_token')
    assert result == {'name': 'Test User'}
    mock_get.assert_called_once()

@patch('requests.get')
def test_auth_service_get_user_info_failure(mock_get):
    """Test failed user info retrieval"""
    mock_get.side_effect = requests.RequestException()
    result = AuthService.get_user_info('test123', 'valid_token')
    assert result is None