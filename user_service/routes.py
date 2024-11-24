from flask import Flask, request, jsonify
from flask_cors import CORS
from flasgger import Swagger, swag_from
from swagger_config import swagger_config, swagger_template, register, login, get_users, get_profile
import uuid
import hashlib
import re
import logging
import jwt
import json
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from functools import wraps

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app)

# Use the secret key from .env file
SECRET_KEY = os.getenv('SECRET_KEY')

# Ensure the secret key is set
if not SECRET_KEY:
    raise ValueError("SECRET_KEY is not set in the environment variables")

# Initialize Swagger
swagger = Swagger(app, config=swagger_config, template=swagger_template)

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# File path for storing users
USERS_FILE = 'users.json'

def admin_required(f):
    """Decorator to check if the user has admin privileges"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            logger.warning("Access denied: No authorization token provided")
            return jsonify({"error": "Authorization token required"}), 401

        try:
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            
            if payload.get('role') != 'Admin':
                logger.warning(f"Access denied: User {payload.get('user_id')} attempted admin action without privileges")
                return jsonify({"error": "Admin privileges required"}), 403
                
            request.user = payload
            return f(*args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            logger.warning("Access denied: Token expired")
            return jsonify({"error": "Token has expired"}), 401
        except (jwt.InvalidTokenError, IndexError) as e:
            logger.warning(f"Access denied: Invalid token - {str(e)}")
            return jsonify({"error": "Invalid token"}), 401

    return decorated

def auth_required(f):
    """Decorator to check if the user is authenticated"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            logger.warning("Access denied: No authorization token provided")
            return jsonify({"error": "Authorization token required"}), 401

        try:
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.user = payload
            return f(*args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            logger.warning("Access denied: Token expired")
            return jsonify({"error": "Token has expired"}), 401
        except (jwt.InvalidTokenError, IndexError) as e:
            logger.warning(f"Access denied: Invalid token - {str(e)}")
            return jsonify({"error": "Invalid token"}), 401

    return decorated

class UserService:
    @staticmethod
    def load_users():
        """Load users from JSON file"""
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
        """Save users to JSON file"""
        try:
            with open(USERS_FILE, 'w') as f:
                json.dump(users, f, indent=4)
        except IOError as e:
            logger.error(f"Error saving users file: {e}")

    @staticmethod
    def validate_email(email):
        """Validate email format"""
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None

    @staticmethod
    def hash_password(password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def generate_token(user_id, role):
        """Generate JWT token"""
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    @staticmethod
    def get_all_users():
        """Retrieve all users (admin only)"""
        users = UserService.load_users()
        return [
            {
                'id': user_id,
                'name': user['name'],
                'email': user['email'],
                'role': user['role'],
                'created_at': user['created_at']
            }
            for user_id, user in users.items()
        ]

    @staticmethod
    def get_user_profile(user_id):
        """Retrieve user profile information"""
        users = UserService.load_users()
        user = users.get(user_id)
        
        if not user:
            logger.warning(f"Profile not found for user ID: {user_id}")
            return None, "User not found"
            
        profile = {
            'id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'role': user['role'],
            'created_at': user['created_at']
        }
        logger.info(f"Profile retrieved successfully for user ID: {user_id}")
        return profile, None

    @staticmethod
    def register_user(name, email, password, role='User'):
        """Register a new user"""
        logger.info(f"Attempting to register user: {email}")

        if not all([name, email, password]):
            logger.warning("Registration failed: Missing required fields")
            return None, "All fields are required"

        if not UserService.validate_email(email):
            logger.warning(f"Registration failed: Invalid email format - {email}")
            return None, "Invalid email format"

        if len(password) < 8:
            logger.warning("Registration failed: Password too short")
            return None, "Password must be at least 8 characters"

        users = UserService.load_users()

        if any(user['email'] == email for user in users.values()):
            logger.warning(f"Registration failed: Email already registered - {email}")
            return None, "Email already registered"

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
        UserService.save_users(users)

        logger.info(f"User registered successfully: {email}")
        return user_id, None

    @staticmethod
    def login_user(email, password):
        """Authenticate user and generate token"""
        logger.info(f"Login attempt for: {email}")

        if not email or not password:
            logger.warning("Login failed: Missing credentials")
            return None, "Email and password are required"

        users = UserService.load_users()
        hashed_password = UserService.hash_password(password)

        user = next((user for user in users.values() if user['email'] == email), None)

        if user and user['password'] == hashed_password:
            token = UserService.generate_token(user['id'], user['role'])
            logger.info(f"Login successful: {email}")
            return {
                'user_id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'role': user['role'],
                'token': token
            }, None

        logger.warning(f"Login failed for: {email}")
        return None, "Invalid credentials"

# Register endpoint
@app.route('/register', methods=['POST'])
@swag_from(register)
def register():
    """Register a new user endpoint"""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.json
    if not data:
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

# Login endpoint
@app.route('/login', methods=['POST'])
@swag_from(login)
def login():
    """User login endpoint"""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.json
    if not data:
        return jsonify({"error": "Empty request body"}), 400

    result, error = UserService.login_user(
        data.get('email'),
        data.get('password')
    )

    if result:
        return jsonify(result), 200
    return jsonify({"error": error}), 401

# Admin-only endpoint to get all users
@app.route('/users', methods=['GET'])
@admin_required
@swag_from(get_users)
def get_all_users():
    """Admin endpoint to get all users"""
    logger.info(f"Admin user {request.user['user_id']} accessed all users list")
    users = UserService.get_all_users()
    return jsonify({'users': users}), 200

# Profile endpoint
@app.route('/profile', methods=['GET'])
@auth_required
@swag_from(get_profile)
def get_profile():
    """Get user profile endpoint"""
    logger.info(f"Profile access request for user {request.user['user_id']}")
    
    profile, error = UserService.get_user_profile(request.user['user_id'])
    
    if profile:
        return jsonify(profile), 200
    return jsonify({"error": error}), 404

if __name__ == '__main__':
    logger.info("User Service starting...")
    app.run(host='0.0.0.0', port=5002, debug=True)