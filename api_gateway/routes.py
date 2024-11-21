from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app)

# Service URLs
DESTINATION_SERVICE = 'http://localhost:5001/apidocs/'
USER_SERVICE = 'http://localhost:5002/apidocs/'
AUTH_SERVICE = 'http://localhost:5003/apidocs/'

class APIGateway:
    @staticmethod
    def validate_token(token, required_role=None):
        try:
            response = requests.post(f'{AUTH_SERVICE}/validate', json={
                'token': token, 
                'required_role': required_role
            })
            return response.json(), response.status_code
        except Exception as e:
            return {"error": str(e)}, 500

@app.route('/api/destinations', methods=['GET'])
def get_destinations():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    # Validate token
    auth_result, status_code = APIGateway.validate_token(token)
    if status_code != 200:
        return jsonify(auth_result), status_code
    
    # Fetch destinations from destination service
    response = requests.get(f'{DESTINATION_SERVICE}/destinations')
    return jsonify(response.json()), response.status_code

@app.route('/api/destinations', methods=['POST'])
def create_destination():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    # Validate admin token
    auth_result, status_code = APIGateway.validate_token(token, 'Admin')
    if status_code != 200:
        return jsonify(auth_result), status_code
    
    