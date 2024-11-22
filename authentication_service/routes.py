from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flasgger import Swagger, swag_from
import jwt
import json
import os
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv
import requests
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
SECRET_KEY = os.getenv('SECRET_KEY')
USER_SERVICE_URL = 'http://localhost:5002'

if not SECRET_KEY:
    raise ValueError("SECRET_KEY is not set in the environment variables")

# Set Flask secret key for session management
app.secret_key = SECRET_KEY

# Configure session to use secure cookies and set timeout
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Swagger configuration remains the same
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec_1',
            "route": '/apispec_1.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/"
}

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Authentication Service API",
        "description": "API for token validation and user authentication with role-based access",
        "version": "1.0.0"
    },
    "basePath": "/",
    "schemes": ["http"],
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    }
}

swagger = Swagger(app, config=swagger_config, template=swagger_template)

class AuthService:
    @staticmethod
    def decode_token(token):
        """Decode and validate JWT token"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            return payload, None
        except jwt.ExpiredSignatureError:
            return None, "Token has expired"
        except jwt.InvalidTokenError:
            return None, "Invalid token"

    @staticmethod
    def get_user_info(user_id, token):
        """Fetch user information from user service"""
        try:
            response = requests.get(
                f"{USER_SERVICE_URL}/profile",
                params={"user_id": user_id},
                headers={"Authorization": f"Bearer {token}"}
            )
            return response.json() if response.status_code == 200 else None
        except requests.RequestException as e:
            logger.error(f"Error fetching user info: {e}")
            return None

    @staticmethod
    def format_expiration_time(exp_timestamp):
        """Format token expiration time"""
        exp_datetime = datetime.fromtimestamp(exp_timestamp)
        valid_for = (exp_datetime - datetime.utcnow()).total_seconds()
        hours = int(valid_for / 3600)
        minutes = int((valid_for % 3600) / 60)
        return {
            "expiration": exp_datetime.isoformat(),
            "valid_for": f"{hours} hours, {minutes} minutes"
        }

    @staticmethod
    def store_token_in_session(token):
        """Store token and user information in session"""
        try:
            payload, error = AuthService.decode_token(token)
            if error:
                return False
            
            session['token'] = token
            session['user'] = payload
            session.permanent = True
            return True
        except Exception as e:
            logger.error(f"Error storing token in session: {e}")
            return False

@app.route('/login', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Login and store token in session',
    'parameters': [
        {
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'description': 'JWT Token (Bearer token)'
        }
    ],
    'responses': {
        '200': {
            'description': 'Login successful'
        }
    }
})
def login():
    """Login endpoint to store token in session"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "No authorization token provided"}), 401

    try:
        token = auth_header.split(" ")[1]
        if AuthService.store_token_in_session(token):
            return jsonify({"message": "Login successful"}), 200
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 401

def require_auth(f):
    """Modified decorator to use session token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'token' not in session or 'user' not in session:
            return jsonify({"error": "Not authenticated"}), 401

        try:
            # Verify token is still valid
            payload, error = AuthService.decode_token(session['token'])
            if error:
                session.clear()
                return jsonify({"error": error}), 401
            
            request.user = session['user']
            return f(*args, **kwargs)
        except Exception as e:
            session.clear()
            return jsonify({"error": str(e)}), 401

    return decorated

@app.route('/logout', methods=['POST'])
def logout():
    """Logout endpoint to clear session"""
    session.clear()
    return jsonify({"message": "Logout successful"}), 200

@app.route('/validate', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Token Validation'],
    'summary': 'Validate session token and show user permissions',
    'description': 'Validates token and returns user role and permissions',
    'responses': {
        '200': {
            'description': 'Token validation successful',
            'schema': {
                'type': 'object',
                'properties': {
                    'status': {'type': 'string'},
                    'user_id': {'type': 'string'},
                    'role': {'type': 'string'},
                    'permissions': {'type': 'object'},
                    'token_validity': {'type': 'object'}
                }
            }
        }
    }
})
def validate_token():
    """Validate token and return role-based information"""
    user = request.user
    
    # Define role-based permissions
    permissions = {
        'Admin': {
            'can_create_users': True,
            'can_delete_users': True,
            'can_modify_roles': True,
            'can_view_all_profiles': True,
            'access_level': 'full'
        },
        'User': {
            'can_create_users': False,
            'can_delete_users': False,
            'can_modify_roles': False,
            'can_view_all_profiles': False,
            'access_level': 'limited'
        }
    }

    token_validity = AuthService.format_expiration_time(user['exp'])
    
    return jsonify({
        'status': 'Token is valid',
        'user_id': user['user_id'],
        'role': user['role'],
        'permissions': permissions.get(user['role'], permissions['User']),
        'token_validity': token_validity
    }), 200

@app.route('/token/info', methods=['GET'])
@require_auth
@swag_from({
    'tags': ['Token Information'],
    'summary': 'Get detailed token and user information',
    'description': 'Returns comprehensive information about token and associated user',
    'responses': {
        '200': {
            'description': 'Token information retrieved successfully'
        }
    }
})
def token_info():
    """Get detailed token and user information"""
    user = request.user
    token = session['token']
    
    # Get user details
    user_info = AuthService.get_user_info(user['user_id'], token)
    if not user_info:
        return jsonify({"error": "Could not fetch user information"}), 404

    # Get token validity
    token_validity = AuthService.format_expiration_time(user['exp'])
    
    # Get user activity status
    activity_status = {
        'last_seen': datetime.utcnow().isoformat(),
        'status': 'active',
        'session_valid': True
    }
    
    return jsonify({
        'token_info': {
            'user_id': user['user_id'],
            'role': user['role'],
            'validity': token_validity,
            'session': activity_status
        },
        'user_info': user_info,
        'access_level': {
            'role_type': user['role'],
            'permissions': {
                'api_access': True,
                'resource_access': user['role'] == 'Admin',
                'admin_privileges': user['role'] == 'Admin'
            }
        }
    }), 200

if __name__ == '__main__':
    logger.info("Enhanced Authentication Service starting...")
    logger.info("Listening on host 0.0.0.0, port 5003")
    app.run(host='0.0.0.0', port=5003, debug=True)