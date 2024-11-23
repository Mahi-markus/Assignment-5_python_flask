import pytest
from flask import Flask
from flask.testing import FlaskClient
import jwt
import json
from datetime import datetime, timedelta
from unittest.mock import patch
import os

# Import the application code - update the import to match your file name
from routes import app, api, destinations

# Test configurations
TEST_SECRET_KEY = 'test-secret-key'

@pytest.fixture
def client():
    """Create a test client for the Flask application"""
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = TEST_SECRET_KEY
    with app.test_client() as client:
        yield client

@pytest.fixture
def admin_token():
    """Generate a valid admin token"""
    payload = {
        'user_id': 'admin-id',
        'role': 'Admin',
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, TEST_SECRET_KEY, algorithm='HS256')

@pytest.fixture
def user_token():
    """Generate a valid user token"""
    payload = {
        'user_id': 'user-id',
        'role': 'User',
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, TEST_SECRET_KEY, algorithm='HS256')

@pytest.fixture
def expired_token():
    """Generate an expired token"""
    payload = {
        'user_id': 'user-id',
        'role': 'User',
        'exp': datetime.utcnow() - timedelta(hours=1)
    }
    return jwt.encode(payload, TEST_SECRET_KEY, algorithm='HS256')

@pytest.fixture
def reset_destinations():
    """Reset destinations to initial state before each test"""
    global destinations
    original_destinations = [
        {'id': 1, 'name': 'Paris', 'description': 'The city of light'},
        {'id': 2, 'name': 'Tokyo', 'description': 'A bustling metropolis in Japan'},
        {'id': 3, 'name': 'New York', 'description': 'The Big Apple'},
    ]
    destinations = original_destinations.copy()
    yield
    destinations = original_destinations.copy()

class TestAuthentication:
    def test_missing_token(self, client):
        """Test endpoint access without token"""
        response = client.get('/destinations/')
        assert response.status_code == 401

    def test_invalid_token_format(self, client):
        """Test endpoint access with invalid token format"""
        response = client.get('/destinations/',
                            headers={'Authorization': 'InvalidFormat token'})
        assert response.status_code == 401

    def test_expired_token(self, client, expired_token):
        """Test endpoint access with expired token"""
        response = client.get('/destinations/',
                            headers={'Authorization': f'Bearer {expired_token}'})
        assert response.status_code == 401

class TestDestinationList:
    def test_get_destinations_user(self, client, user_token, reset_destinations):
        """Test getting destinations list as regular user"""
        response = client.get('/destinations/',
                            headers={'Authorization': f'Bearer {user_token}'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert len(data) == 3
        assert data[0]['name'] == 'Paris'

    def test_get_destinations_admin(self, client, admin_token, reset_destinations):
        """Test getting destinations list as admin"""
        response = client.get('/destinations/',
                            headers={'Authorization': f'Bearer {admin_token}'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert len(data) == 3

    def test_create_destination_user(self, client, user_token):
        """Test creating destination as regular user (should fail)"""
        new_destination = {
            'name': 'London',
            'description': 'The capital of England'
        }
        response = client.post('/destinations/',
                             headers={'Authorization': f'Bearer {user_token}'},
                             json=new_destination)
        
        assert response.status_code == 403

    def test_create_destination_admin(self, client, admin_token, reset_destinations):
        """Test creating destination as admin"""
        new_destination = {
            'name': 'London',
            'description': 'The capital of England'
        }
        response = client.post('/destinations/',
                             headers={'Authorization': f'Bearer {admin_token}'},
                             json=new_destination)
        
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['name'] == 'London'
        assert data['description'] == 'The capital of England'
        assert 'id' in data

class TestDestination:
    def test_get_destination_user(self, client, user_token, reset_destinations):
        """Test getting specific destination as user"""
        response = client.get('/destinations/1',
                            headers={'Authorization': f'Bearer {user_token}'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['name'] == 'Paris'

    def test_get_nonexistent_destination(self, client, user_token):
        """Test getting non-existent destination"""
        response = client.get('/destinations/999',
                            headers={'Authorization': f'Bearer {user_token}'})
        
        assert response.status_code == 404

    def test_delete_destination_user(self, client, user_token):
        """Test deleting destination as regular user (should fail)"""
        response = client.delete('/destinations/1',
                               headers={'Authorization': f'Bearer {user_token}'})
        
        assert response.status_code == 403

    def test_delete_destination_admin(self, client, admin_token, reset_destinations):
        """Test deleting destination as admin"""
        response = client.delete('/destinations/1',
                               headers={'Authorization': f'Bearer {admin_token}'})
        
        assert response.status_code == 200
        # Verify destination is deleted
        get_response = client.get('/destinations/1',
                                headers={'Authorization': f'Bearer {admin_token}'})
        assert get_response.status_code == 404

    def test_delete_nonexistent_destination(self, client, admin_token):
        """Test deleting non-existent destination"""
        response = client.delete('/destinations/999',
                               headers={'Authorization': f'Bearer {admin_token}'})
        
        assert response.status_code == 404

class TestInputValidation:
    def test_create_destination_missing_fields(self, client, admin_token):
        """Test creating destination with missing required fields"""
        incomplete_destination = {
            'name': 'London'
            # missing description
        }
        response = client.post('/destinations/',
                             headers={'Authorization': f'Bearer {admin_token}'},
                             json=incomplete_destination)
        
        assert response.status_code == 400

    def test_create_destination_empty_fields(self, client, admin_token):
        """Test creating destination with empty fields"""
        empty_destination = {
            'name': '',
            'description': ''
        }
        response = client.post('/destinations/',
                             headers={'Authorization': f'Bearer {admin_token}'},
                             json=empty_destination)
        
        assert response.status_code == 400

if __name__ == '__main__':
    pytest.main(['-v'])