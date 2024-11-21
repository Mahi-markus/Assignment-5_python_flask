from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import logging
import traceback

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Service URLs
DESTINATION_SERVICE = 'http://localhost:5001'  # Updated to match previous destination service port
USER_SERVICE = 'http://localhost:5002'
AUTH_SERVICE = 'http://localhost:5003'  # Assuming auth service is on same port as user service

class APIGateway:
    @staticmethod
    def validate_token(token, required_role=None):
        """
        Validate JWT token with optional role check
        """
        try:
            # Remove 'Bearer ' prefix if present
            token = token.replace('Bearer ', '')
            
            # Log the validation attempt
            logger.debug(f"Validating token. Required role: {required_role}")
            
            # Send token to profile endpoint for validation
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get(f'{USER_SERVICE}/profile', 
                                    headers=headers)
            
            # Log the response from profile endpoint
            logger.debug(f"Token validation response: {response.status_code}")
            logger.debug(f"Response content: {response.text}")
            
            # Check if token is valid
            if response.status_code != 200:
                return {"error": "Invalid or expired token", "details": response.text}, 401
            
            # Get user profile
            user_profile = response.json()
            
            # Check role if required
            if required_role and user_profile.get('role') != required_role:
                return {"error": "Insufficient permissions", "role": user_profile.get('role')}, 403
            
            return user_profile, 200
        
        except requests.RequestException as e:
            logger.error(f"Token validation error: {str(e)}")
            logger.error(traceback.format_exc())
            return {"error": "Authentication service unavailable", "details": str(e)}, 500
        except Exception as e:
            logger.error(f"Unexpected error in token validation: {str(e)}")
            logger.error(traceback.format_exc())
            return {"error": "Internal authentication error", "details": str(e)}, 500

@app.route('/http://127.0.0.1:5001/', methods=['GET'])
def get_destinations():
    """
    Get destinations endpoint (requires login)
    """
    try:
        # Extract token from Authorization header
        token = request.headers.get('Authorization', '')
        logger.debug(f"Received token: {token}")
        
        # Validate token (login required, no specific role)
        auth_result, status_code = APIGateway.validate_token(token)
        if status_code != 200:
            logger.warning(f"Token validation failed: {auth_result}")
            return jsonify(auth_result), status_code
        
        # Fetch destinations from destination service
        try:
            response = requests.get(
                f'{DESTINATION_SERVICE}/destinations', 
                headers={'Authorization': token}
            )
            
            # Log the response
            logger.debug(f"Destinations response status: {response.status_code}")
            logger.debug(f"Destinations response content: {response.text}")
            
            # Return destinations
            return jsonify(response.json()), response.status_code
        
        except requests.RequestException as e:
            logger.error(f"Error fetching destinations: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                "error": "Unable to fetch destinations", 
                "details": str(e)
            }), 500
    
    except Exception as e:
        logger.error(f"Unexpected error in get_destinations: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": "An unexpected error occurred", 
            "details": str(e)
        }), 500

@app.route('/http://127.0.0.1:5001/', methods=['POST'])
def create_destination():
    """
    Create destination endpoint (admin-only)
    """
    try:
        # Extract token from Authorization header
        token = request.headers.get('Authorization', '')
        logger.debug(f"Received token for destination creation: {token}")
        
        # Validate token (admin role required)
        auth_result, status_code = APIGateway.validate_token(token, 'Admin')
        if status_code != 200:
            logger.warning(f"Admin token validation failed: {auth_result}")
            return jsonify(auth_result), status_code
        
        # Forward destination creation request to destination service
        try:
            response = requests.post(
                f'{DESTINATION_SERVICE}/destinations', 
                json=request.json,
                headers={'Authorization': token}
            )
            
            # Log the response
            logger.debug(f"Create destination response status: {response.status_code}")
            logger.debug(f"Create destination response content: {response.text}")
            
            # Return response from destination service
            return jsonify(response.json()), response.status_code
        
        except requests.RequestException as e:
            logger.error(f"Error creating destination: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                "error": "Unable to create destination", 
                "details": str(e)
            }), 500
    
    except Exception as e:
        logger.error(f"Unexpected error in create_destination: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": "An unexpected error occurred", 
            "details": str(e)
        }), 500

@app.route('/http://127.0.0.1:5001/<destination_id>', methods=['DELETE'])
def delete_destination(destination_id):
    """
    Delete destination endpoint (admin-only)
    """
    try:
        # Extract token from Authorization header
        token = request.headers.get('Authorization', '')
        logger.debug(f"Received token for destination deletion: {token}")
        
        # Validate token (admin role required)
        auth_result, status_code = APIGateway.validate_token(token, 'Admin')
        if status_code != 200:
            logger.warning(f"Admin token validation failed: {auth_result}")
            return jsonify(auth_result), status_code
        
        # Forward destination deletion request to destination service
        try:
            response = requests.delete(
                f'{DESTINATION_SERVICE}/destinations/{destination_id}', 
                headers={'Authorization': token}
            )
            
            # Log the response
            logger.debug(f"Delete destination response status: {response.status_code}")
            logger.debug(f"Delete destination response content: {response.text}")
            
            # Return response from destination service
            return jsonify(response.json()), response.status_code
        
        except requests.RequestException as e:
            logger.error(f"Error deleting destination: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                "error": "Unable to delete destination", 
                "details": str(e)
            }), 500
    
    except Exception as e:
        logger.error(f"Unexpected error in delete_destination: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": "An unexpected error occurred", 
            "details": str(e)
        }), 500

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    """
    Global error handler for unexpected exceptions
    """
    logger.error(f"Unhandled exception: {str(error)}")
    logger.error(traceback.format_exc())
    return jsonify({
        "error": "An unexpected error occurred", 
        "details": str(error)
    }), 500

if __name__ == '__main__':
    # Logging service startup
    logger.info("API Gateway starting...")
    logger.info("Listening on host 0.0.0.0, port 5000")
    
    # Run the application
    app.run(host='0.0.0.0', port=5000, debug=True)