from flask import Flask, request, jsonify
from flask_restx import Api, Resource, fields
from werkzeug.exceptions import Forbidden
from functools import wraps
import jwt
import os
from datetime import datetime
from dotenv import load_dotenv
from flask_cors import CORS

# Load environment variables
load_dotenv()

# Flask app and configuration
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  # Use the same secret key as user service

# Flask-RESTX API with proper security definitions
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': 'Type in the *\'Value\'* input box below: **\'Bearer &lt;JWT&gt;\'**, where JWT is the token'
    }
}

api = Api(app, 
         title="Travel API", 
         version="1.0", 
         description="API for managing destinations",
         authorizations=authorizations,
         security='Bearer')

ns = api.namespace('destinations', description="Destination management")

# In-memory storage with dummy destinations
destinations = [
    {'id': 1, 'name': 'Paris', 'description': 'The city of light'},
    {'id': 2, 'name': 'Tokyo', 'description': 'A bustling metropolis in Japan'},
    {'id': 3, 'name': 'New York', 'description': 'The Big Apple'},
]

# Models
destination_model = api.model('Destination', {
    'id': fields.Integer(readOnly=True, description='Unique ID of the destination'),
    'name': fields.String(required=True, description='Name of the destination'),
    'description': fields.String(required=True, description='Description of the destination'),
})

destination_input_model = api.model('DestinationInput', {
    'name': fields.String(required=True, description='Name of the destination'),
    'description': fields.String(required=True, description='Description of the destination'),
})

def validate_token(auth_header):
    """Validate JWT token using the same secret key as user service"""
    try:
        if not auth_header:
            return None
            
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return None
            
        token = parts[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, Exception) as e:
        print(f"Token validation error: {str(e)}")
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        payload = validate_token(auth_header)
        
        if not payload:
            api.abort(401, 'Invalid token or token format. Please provide token as "Bearer <token>"')

        return f(*args, **kwargs, current_user=payload)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        payload = validate_token(auth_header)
        
        if not payload:
            api.abort(401, 'Invalid token or token format. Please provide token as "Bearer <token>"')

        if payload.get('role') != 'Admin':
            api.abort(403, 'Admin privileges required')

        return f(*args, **kwargs, current_user=payload)
    return decorated

@ns.route('/')
class DestinationList(Resource):
    @ns.doc('list_destinations', security='Bearer')
    @ns.response(200, 'Success', [destination_model])
    @ns.response(401, 'Authentication failed')
    @token_required
    def get(self, current_user):
        """List all destinations"""
        return destinations

    @ns.doc('create_destination', security='Bearer')
    @ns.expect(destination_input_model)
    @ns.response(201, 'Destination created', destination_model)
    @ns.response(401, 'Authentication failed')
    @ns.response(403, 'Admin privileges required')
    @admin_required
    def post(self, current_user):
        """Create a new destination (Admin only)"""
        data = api.payload
        destination = {
            'id': max(d['id'] for d in destinations) + 1 if destinations else 1,
            'name': data['name'],
            'description': data['description'],
        }
        destinations.append(destination)
        return destination, 201

@ns.route('/<int:id>')
@ns.param('id', 'The destination identifier')
class Destination(Resource):
    @ns.doc('delete_destination', security='Bearer')
    @ns.response(200, 'Destination deleted')
    @ns.response(401, 'Authentication failed')
    @ns.response(403, 'Admin privileges required')
    @ns.response(404, 'Destination not found')
    @admin_required
    def delete(self, id, current_user):
        """Delete a destination (Admin only)"""
        global destinations
        destination = next((d for d in destinations if d['id'] == id), None)
        if not destination:
            api.abort(404, f'Destination {id} not found')
        
        destinations = [d for d in destinations if d['id'] != id]
        return {'message': 'Destination deleted successfully'}

    @ns.doc('get_destination', security='Bearer')
    @ns.response(200, 'Success', destination_model)
    @ns.response(401, 'Authentication failed')
    @ns.response(404, 'Destination not found')
    @token_required
    def get(self, id, current_user):
        """Get a specific destination"""
        destination = next((d for d in destinations if d['id'] == id), None)
        if not destination:
            api.abort(404, f'Destination {id} not found')
        return destination

# Error handlers
@api.errorhandler(jwt.ExpiredSignatureError)
def handle_expired_token(error):
    return {'message': 'Token has expired'}, 401

@api.errorhandler(jwt.InvalidTokenError)
def handle_invalid_token(error):
    return {'message': 'Invalid token'}, 401

@api.errorhandler(Forbidden)
def handle_forbidden(error):
    return {'message': 'Access forbidden'}, 403

if __name__ == '__main__':
    print("Starting Destinations API...")
    print("Make sure to include 'Bearer' before your token in the Authorization header")
    app.run(host='0.0.0.0', port=5001, debug=True)