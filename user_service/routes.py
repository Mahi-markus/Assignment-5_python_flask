from flask import Flask, request, jsonify
from flask_cors import CORS
from flasgger import Swagger, swag_from
import uuid
import hashlib
import re
import logging
import jwt
import json
import os
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# Comprehensive Swagger configuration
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
    "specs_route": "/docs"
}

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "User Management API",
        "description": "API for user registration, authentication, and profile management",
        "version": "1.0.0"
    },
    "basePath": "/",
    "schemes": [
        "http"
    ],
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    }
}

swagger = Swagger(app, config=swagger_config, template=swagger_template)

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Secret key for JWT token generation
SECRET_KEY = 'your_super_secret_key_here_change_in_production'

# File path for storing users
USERS_FILE = 'users.json'

class UserService:
    @staticmethod
    def load_users():
        """
        Load users from JSON file
        """
        if not os.path.exists(USERS_FILE):
            return {}
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading users file: {e}")
            return {}

    @staticmethod
    def save_users(users):
        """
        Save users to JSON file
        """
        try:
            with open(USERS_FILE, 'w') as f:
                json.dump(users, f, indent=4)
        except IOError as e:
            logger.error(f"Error saving users file: {e}")

    @staticmethod
    def validate_email(email):
        """
        Validate email format
        """
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None

    @staticmethod
    def hash_password(password):
        """
        Hash password using SHA-256
        """
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def generate_token(user_id, role):
        """
        Generate JWT token
        """
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    @staticmethod
    def validate_token(token):
        """
        Validate JWT token
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    @staticmethod
    def register_user(name, email, password, role='User'):
        """
        Register a new user with file-based storage
        """
        logger.info(f"Attempting to register user: {email}")

        # Load existing users
        users = UserService.load_users()

        # Comprehensive input validation
        if not all([name, email, password]):
            logger.warning("Registration failed: Missing required fields")
            return None, "All fields are required"

        if not UserService.validate_email(email):
            logger.warning(f"Registration failed: Invalid email format - {email}")
            return None, "Invalid email format"

        if len(password) < 8:
            logger.warning("Registration failed: Password too short")
            return None, "Password must be at least 8 characters"

        # Check if email already exists
        if any(user['email'] == email for user in users.values()):
            logger.warning(f"Registration failed: Email already registered - {email}")
            return None, "Email already registered"

        # Create user
        user_id = str(uuid.uuid4())
        user = {
            'id': user_id,
            'name': name,
            'email': email,
            'password': UserService.hash_password(password),
            'role': role,
            'created_at': datetime.utcnow().isoformat()
        }
        users[user_id] = user

        # Save updated users
        UserService.save_users(users)
        
        logger.info(f"User registered successfully: {email}")
        return user_id, None

    @staticmethod
    def login_user(email, password):
        """
        Authenticate user and generate token
        """
        logger.info(f"Login attempt for: {email}")
        users = UserService.load_users()
        hashed_password = UserService.hash_password(password)
        
        for user in users.values():
            if user['email'] == email and user['password'] == hashed_password:
                # Generate JWT token
                token = UserService.generate_token(user['id'], user['role'])
                logger.info(f"Successful login: {email}")
                return {
                    'user_id': user['id'],
                    'name': user['name'],
                    'email': user['email'],
                    'role': user['role'],
                    'token': token
                }, None
        
        logger.warning(f"Login failed for: {email}")
        return None, "Invalid credentials"

    @staticmethod
    def get_user_profile(user_id):
        """
        Retrieve user profile (without sensitive information)
        """
        logger.info(f"Fetching profile for user ID: {user_id}")
        users = UserService.load_users()
        user = users.get(user_id)
        if user:
            # Remove sensitive information before returning
            profile = user.copy()
            del profile['password']
            return profile
        logger.warning(f"Profile not found for user ID: {user_id}")
        return None


@app.route('/register', methods=['POST'])
@swag_from({
    'tags': ['User Registration'],
    'summary': 'Register a new user',
    'description': 'Endpoint for user registration',
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'name': {'type': 'string', 'description': 'Full name of the user'},
                    'email': {'type': 'string', 'description': 'Email address'},
                    'password': {'type': 'string', 'description': 'Password (min 8 characters)'},
                    'role': {
                        'type': 'string', 
                        'enum': ['User', 'Admin'],
                        'default': 'User'
                    }
                },
                'required': ['name', 'email', 'password']
            }
        }
    ],
    'responses': {
        '201': {
            'description': 'User registered successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string'},
                    'message': {'type': 'string'}
                }
            }
        },
        '400': {
            'description': 'Registration failed',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def register():
    """Register a new user endpoint"""
    # Validate JSON content type
    if not request.is_json:
        logger.warning("Registration failed: Invalid content type")
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.json

    # Validate request data
    if not data:
        logger.warning("Registration failed: Empty request body")
        return jsonify({"error": "Empty request body"}), 400

    user_id, error = UserService.register_user(
        data.get('name'),
        data.get('email'),
        data.get('password'),
        data.get('role', 'User')
    )

    if user_id:
        return jsonify({
            "id": user_id,
            "message": "User registered successfully"
        }), 201
    return jsonify({"error": error}), 400


@app.route('/login', methods=['POST'])
@swag_from({
    'tags': ['User Authentication'],
    'summary': 'User login',
    'description': 'Endpoint for user login and token generation',
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string', 'description': 'User email'},
                    'password': {'type': 'string', 'description': 'User password'}
                },
                'required': ['email', 'password']
            }
        }
    ],
    'responses': {
        '200': {
            'description': 'Login successful',
            'schema': {
                'type': 'object',
                'properties': {
                    'user_id': {'type': 'string'},
                    'name': {'type': 'string'},
                    'email': {'type': 'string'},
                    'role': {'type': 'string'},
                    'token': {'type': 'string'}
                }
            }
        },
        '401': {
            'description': 'Authentication failed',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def login():
    """User login endpoint"""
    # Validate JSON content type
    if not request.is_json:
        logger.warning("Login failed: Invalid content type")
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.json

    # Validate request data
    if not data or not data.get('email') or not data.get('password'):
        logger.warning("Login failed: Missing credentials")
        return jsonify({"error": "Email and password are required"}), 400

    result, error = UserService.login_user(
        data.get('email'),
        data.get('password')
    )

    if result:
        return jsonify(result), 200
    return jsonify({"error": error}), 401
    
@app.route('/profile', methods=['GET'])
@swag_from({
    'tags': ['User Profile'],
    'summary': 'Get user profile',
    'description': 'Retrieve user profile by user ID',
    'parameters': [
        {
            'name': 'user_id',
            'in': 'query',
            'type': 'string',
            'required': True,
            'description': 'ID of the user'
        },
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
            'description': 'User profile retrieved successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string'},
                    'name': {'type': 'string'},
                    'email': {'type': 'string'},
                    'role': {'type': 'string'}
                }
            }
        },
        '401': {
            'description': 'Unauthorized access',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def get_profile():
    """Get user profile endpoint"""
    # Check for authorization token
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Authorization token required"}), 401

    # Validate token
    token = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else None
    if not token:
        return jsonify({"error": "Invalid token format"}), 401

    # Verify token
    payload = UserService.validate_token(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 401

    # Get user ID from query parameter
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    # Ensure the requester can only access their own profile
    if user_id != payload.get('user_id'):
        return jsonify({"error": "Unauthorized to access this profile"}), 403

    profile = UserService.get_user_profile(user_id)

    if profile:
        return jsonify(profile), 200
    return jsonify({"error": "Profile not found"}), 404


if __name__ == '__main__':
    # Seed an admin user
    UserService.register_user(
        "Admin User",
        "admin@travelapi.com",
        "AdminPass123!",
        "Admin"
    )

    # Add more detailed logging for startup
    logger.info("User Service starting...")
    logger.info("Listening on host 0.0.0.0, port 5002")

    # Dependencies for requirements
    # pip install flask flask-cors flasgger PyJWT

    app.run(host='0.0.0.0', port=5002, debug=True)