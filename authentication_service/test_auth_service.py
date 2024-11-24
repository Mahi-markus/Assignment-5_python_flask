import pytest
from flask import Flask, session
import jwt
from datetime import datetime, timedelta
import json
from unittest.mock import patch, MagicMock
from routes import app, AuthService, require_auth
import os
import requests

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    with app.test_client() as client:
        yield client

@pytest.fixture
def valid_token():
    payload = {
        'user_id': '12345',
        'role': 'Admin',
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

@pytest.fixture
def expired_token():
    payload = {
        'user_id': '12345',
        'role': 'Admin',
        'exp': datetime.utcnow() - timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

class TestAuthService:
    def test_decode_valid_token(self, valid_token):
        payload, error = AuthService.decode_token(valid_token)
        assert error is None
        assert payload['user_id'] == '12345'
        assert payload['role'] == 'Admin'

    def test_decode_expired_token(self, expired_token):
        payload, error = AuthService.decode_token(expired_token)
        assert payload is None
        assert error == "Token has expired"

    def test_decode_invalid_token(self):
        payload, error = AuthService.decode_token("invalid.token.string")
        assert payload is None
        assert error == "Invalid token"

    @patch('requests.get')
    def test_get_user_info_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'user_id': '12345', 'name': 'Test User'}
        mock_get.return_value = mock_response

        result = AuthService.get_user_info('12345', 'test_token')
        assert result == {'user_id': '12345', 'name': 'Test User'}
        mock_get.assert_called_once()

    @patch('requests.get')
    def test_get_user_info_failure(self, mock_get):
        mock_get.side_effect = requests.RequestException()
        result = AuthService.get_user_info('12345', 'test_token')
        assert result is None

    def test_format_expiration_time(self):
        # Test with a timestamp 1 hour in the future
        future_timestamp = (datetime.utcnow() + timedelta(hours=1)).timestamp()
        result = AuthService.format_expiration_time(future_timestamp)
        
        assert 'expiration' in result
        assert 'valid_for' in result
        assert '0 hours, 59 minutes' in result['valid_for'] or '1 hours, 0 minutes' in result['valid_for']

class TestRoutes:
    def test_login_success(self, client, valid_token):
        response = client.post(
            '/login',
            headers={'Authorization': f'Bearer {valid_token}'}
        )
        assert response.status_code == 200
        assert b'Login successful' in response.data

    def test_login_no_token(self, client):
        response = client.post('/login')
        assert response.status_code == 401
        assert b'No authorization token provided' in response.data

    def test_login_invalid_token(self, client):
        response = client.post(
            '/login',
            headers={'Authorization': 'Bearer invalid.token.here'}
        )
        assert response.status_code == 401
        assert b'Invalid token' in response.data

    def test_logout(self, client):
        with client.session_transaction() as sess:
            sess['token'] = 'test_token'
            sess['user'] = {'user_id': '12345'}

        response = client.post('/logout')
        assert response.status_code == 200
        assert b'Logout successful' in response.data
        
        with client.session_transaction() as sess:
            assert 'token' not in sess
            assert 'user' not in sess

    def test_validate_token_success(self, client, valid_token):
        with client.session_transaction() as sess:
            sess['token'] = valid_token
            sess['user'] = {
                'user_id': '12345',
                'role': 'Admin',
                'exp': (datetime.utcnow() + timedelta(hours=1)).timestamp()
            }

        response = client.get('/validate')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'Token is valid'
        assert data['user_id'] == '12345'
        assert data['role'] == 'Admin'
        assert 'permissions' in data
        assert data['permissions']['access_level'] == 'full'

    def test_validate_token_no_session(self, client):
        response = client.get('/validate')
        assert response.status_code == 401
        assert b'Not authenticated' in response.data

    def test_validate_token_expired(self, client, expired_token):
        with client.session_transaction() as sess:
            sess['token'] = expired_token
            sess['user'] = {
                'user_id': '12345',
                'role': 'Admin',
                'exp': (datetime.utcnow() - timedelta(hours=1)).timestamp()
            }

        response = client.get('/validate')
        assert response.status_code == 401
        assert b'Token has expired' in response.data

@pytest.mark.parametrize("role,expected_access_level", [
    ('Admin', 'full'),
    ('User', 'limited'),
    ('Unknown', 'limited')
])
def test_role_based_permissions(client, valid_token, role, expected_access_level):
    with client.session_transaction() as sess:
        sess['token'] = valid_token
        sess['user'] = {
            'user_id': '12345',
            'role': role,
            'exp': (datetime.utcnow() + timedelta(hours=1)).timestamp()
        }

    response = client.get('/validate')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['permissions']['access_level'] == expected_access_level