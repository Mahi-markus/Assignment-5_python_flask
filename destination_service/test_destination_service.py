import pytest
from flask import Flask
from flask.testing import FlaskClient
import jwt
from datetime import datetime, timedelta
from typing import Dict, Any, Generator
import json
from _pytest.fixtures import FixtureRequest

# Import the application code
from routes import app, destinations, api

@pytest.fixture
def client(request: FixtureRequest) -> Generator[FlaskClient, None, None]:
    """Create a test client fixture"""
    app.config['TESTING'] = True
    with app.test_client() as test_client:
        yield test_client

@pytest.fixture
def admin_token() -> str:
    """Generate an admin token for testing"""
    payload = {
        'user_id': 'admin-test-id',
        'role': 'Admin',
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

@pytest.fixture
def user_token() -> str:
    """Generate a regular user token for testing"""
    payload = {
        'user_id': 'user-test-id',
        'role': 'User',
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

@pytest.fixture
def expired_token() -> str:
    """Generate an expired token for testing"""
    payload = {
        'user_id': 'user-test-id',
        'role': 'User',
        'exp': datetime.utcnow() - timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

class TestDestinationsAPI:
    """Test cases for Destinations API endpoints"""

    def test_get_destinations_authenticated(self, client: FlaskClient, user_token: str) -> None:
        """Test getting all destinations with valid user token"""
        response = client.get('/destinations/', headers={
            'Authorization': f'Bearer {user_token}'
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert len(data) > 0
        assert all(key in data[0] for key in ['id', 'name', 'description', 'location'])

    def test_get_destinations_unauthorized(self, client: FlaskClient) -> None:
        """Test getting destinations without token"""
        response = client.get('/destinations/')
        assert response.status_code == 401

    def test_get_destinations_expired_token(self, client: FlaskClient, expired_token: str) -> None:
        """Test getting destinations with expired token"""
        response = client.get('/destinations/', headers={
            'Authorization': f'Bearer {expired_token}'
        })
        assert response.status_code == 401

    def test_get_single_destination(self, client: FlaskClient, user_token: str) -> None:
        """Test getting a single destination"""
        response = client.get('/destinations/1', headers={
            'Authorization': f'Bearer {user_token}'
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['id'] == 1
        assert 'name' in data
        assert 'description' in data
        assert 'location' in data

    def test_get_nonexistent_destination(self, client: FlaskClient, user_token: str) -> None:
        """Test getting a destination that doesn't exist"""
        response = client.get('/destinations/999', headers={
            'Authorization': f'Bearer {user_token}'
        })
        assert response.status_code == 404

    def test_create_destination_admin(self, client: FlaskClient, admin_token: str) -> None:
        """Test creating a new destination as admin"""
        new_destination = {
            'name': 'Test City',
            'description': 'A test destination',
            'location': 'Test Location'
        }
        
        response = client.post('/destinations/', 
                             headers={
                                 'Authorization': f'Bearer {admin_token}',
                                 'Content-Type': 'application/json'
                             },
                             data=json.dumps(new_destination))
        
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['name'] == new_destination['name']
        assert data['description'] == new_destination['description']
        assert data['location'] == new_destination['location']
        assert 'id' in data

    def test_create_destination_user(self, client: FlaskClient, user_token: str) -> None:
        """Test creating a destination as regular user (should fail)"""
        new_destination = {
            'name': 'Test City',
            'description': 'A test destination',
            'location': 'Test Location'
        }
        
        response = client.post('/destinations/', 
                             headers={
                                 'Authorization': f'Bearer {user_token}',
                                 'Content-Type': 'application/json'
                             },
                             data=json.dumps(new_destination))
        
        assert response.status_code == 403

    def test_delete_destination_admin(self, client: FlaskClient, admin_token: str) -> None:
        """Test deleting a destination as admin"""
        # First create a destination to delete
        new_destination = {
            'name': 'To Delete',
            'description': 'Will be deleted',
            'location': 'Nowhere'
        }
        
        create_response = client.post('/destinations/', 
                                    headers={
                                        'Authorization': f'Bearer {admin_token}',
                                        'Content-Type': 'application/json'
                                    },
                                    data=json.dumps(new_destination))
        
        created_id = json.loads(create_response.data)['id']
        
        # Now delete it
        delete_response = client.delete(f'/destinations/{created_id}',
                                      headers={'Authorization': f'Bearer {admin_token}'})
        
        assert delete_response.status_code == 200
        
        # Verify it's deleted
        get_response = client.get(f'/destinations/{created_id}',
                                headers={'Authorization': f'Bearer {admin_token}'})
        assert get_response.status_code == 404

    def test_delete_destination_user(self, client: FlaskClient, user_token: str) -> None:
        """Test deleting a destination as regular user (should fail)"""
        response = client.delete('/destinations/1',
                               headers={'Authorization': f'Bearer {user_token}'})
        assert response.status_code == 403

    def test_invalid_token_format(self, client: FlaskClient) -> None:
        """Test invalid token format"""
        response = client.get('/destinations/',
                            headers={'Authorization': 'InvalidFormat token'})
        assert response.status_code == 401

    def test_malformed_json(self, client: FlaskClient, admin_token: str) -> None:
        """Test sending malformed JSON in POST request"""
        response = client.post('/destinations/',
                             headers={
                                 'Authorization': f'Bearer {admin_token}',
                                 'Content-Type': 'application/json'
                             },
                             data='invalid json')
        assert response.status_code == 400

class TestTokenValidation:
    """Test cases for token validation"""

    def test_missing_token(self, client: FlaskClient) -> None:
        """Test request without token"""
        response = client.get('/destinations/')
        assert response.status_code == 401

    def test_expired_token(self, client: FlaskClient, expired_token: str) -> None:
        """Test expired token handling"""
        response = client.get('/destinations/',
                            headers={'Authorization': f'Bearer {expired_token}'})
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'message' in data

    def test_invalid_token_signature(self, client: FlaskClient) -> None:
        """Test token with invalid signature"""
        invalid_token = jwt.encode(
            {'user_id': 'test', 'role': 'User', 'exp': datetime.utcnow() + timedelta(hours=1)},
            'wrong_secret',
            algorithm='HS256'
        )
        response = client.get('/destinations/',
                            headers={'Authorization': f'Bearer {invalid_token}'})
        assert response.status_code == 401