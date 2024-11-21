from flask import Flask, request, jsonify,redirect
from flask_cors import CORS
from flasgger import Swagger
import uuid
import jwt
import datetime

app = Flask(__name__)
CORS(app)
swagger = Swagger(app)

# Secret key for JWT token generation
SECRET_KEY = 'your_secret_key_here'

# In-memory token storage (in production, use a more robust solution)
active_tokens = set()


@app.route('/')
def home():
    return redirect('/apidocs')


class AuthService:
    @staticmethod
    def generate_token(user_id, role):
        """
        Generate a JWT token for the user
        """
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        active_tokens.add(token)
        return token

    @staticmethod
    def validate_token(token, required_role=None):
        """
        Validate JWT token and optionally check role
        """
        try:
            if token not in active_tokens:
                return None, "Invalid or expired token"
            
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            
            # Check role if required
            if required_role and payload.get('role') != required_role:
                return None, "Insufficient privileges"
            
            return payload, None
        except jwt.ExpiredSignatureError:
            active_tokens.discard(token)
            return None, "Token expired"
        except jwt.InvalidTokenError:
            return None, "Invalid token"

    @staticmethod
    def revoke_token(token):
        """
        Revoke an active token
        """
        if token in active_tokens:
            active_tokens.remove(token)
            return True
        return False

@app.route('/token', methods=['POST'])
def create_token():
    """
    Create authentication token
    ---
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            user_id:
              type: string
            role:
              type: string
    responses:
      200:
        description: Token generated successfully
      400:
        description: Token generation failed
    """
    data = request.json
    user_id = data.get('user_id')
    role = data.get('role', 'User')
    
    if not user_id:
        return jsonify({"error": "User ID is required"}), 400
    
    token = AuthService.generate_token(user_id, role)
    return jsonify({"token": token}), 200

@app.route('/validate', methods=['POST'])
def validate_token():
    """
    Validate authentication token
    ---
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            token:
              type: string
            required_role:
              type: string
    responses:
      200:
        description: Token is valid
      401:
        description: Token validation failed
    """
    data = request.json
    token = data.get('token')
    required_role = data.get('required_role')
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    payload, error = AuthService.validate_token(token, required_role)
    
    if payload:
        return jsonify(payload), 200
    return jsonify({"error": error}), 401

@app.route('/revoke', methods=['POST'])
def revoke_token():
    """
    Revoke an authentication token
    ---
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            token:
              type: string
    responses:
      200:
        description: Token revoked successfully
      400:
        description: Token revocation failed
    """
    data = request.json
    token = data.get('token')
    
    if not token:
        return jsonify({"error": "Token is required"}), 400
    
    if AuthService.revoke_token(token):
        return jsonify({"message": "Token revoked successfully"}), 200
    return jsonify({"error": "Token not found"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=True)