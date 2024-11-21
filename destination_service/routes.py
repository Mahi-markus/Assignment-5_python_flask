from flask import Flask, request, jsonify
from flask_cors import CORS
from flasgger import Swagger
import uuid

app = Flask(__name__)
CORS(app)
swagger = Swagger(app)

# In-memory storage for destinations
destinations = {}

class DestinationService:
    @staticmethod
    def add_destination(name, description, location, price):
        destination_id = str(uuid.uuid4())
        destinations[destination_id] = {
            'id': destination_id,
            'name': name,
            'description': description,
            'location': location,
            'price_per_night': price
        }
        return destination_id

    @staticmethod
    def get_destinations():
        return list(destinations.values())

    @staticmethod
    def delete_destination(destination_id):
        if destination_id in destinations:
            del destinations[destination_id]
            return True
        return False

@app.route('/destinations', methods=['GET'])
def list_destinations():
    """
    List all destinations
    ---
    responses:
      200:
        description: List of all destinations
    """
    return jsonify(DestinationService.get_destinations()), 200

@app.route('/destinations', methods=['POST'])
def create_destination():
    """
    Create a new destination
    ---
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
            description:
              type: string
            location:
              type: string
            price:
              type: number
    responses:
      201:
        description: Destination created successfully
      400:
        description: Invalid input
    """
    data = request.json
    if not all(key in data for key in ['name', 'description', 'location', 'price']):
        return jsonify({"error": "Missing required fields"}), 400
    
    destination_id = DestinationService.add_destination(
        data['name'], 
        data['description'], 
        data['location'], 
        data['price']
    )
    return jsonify({"id": destination_id, "message": "Destination created"}), 201

@app.route('/destinations/<destination_id>', methods=['DELETE'])
def remove_destination(destination_id):
    """
    Delete a destination
    ---
    parameters:
      - name: destination_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Destination deleted successfully
      404:
        description: Destination not found
    """
    if DestinationService.delete_destination(destination_id):
        return jsonify({"message": "Destination deleted"}), 200
    return jsonify({"error": "Destination not found"}), 404

if __name__ == '__main__':
    # Seed some initial destinations
    DestinationService.add_destination(
        "Paris", 
        "Romantic city of lights", 
        "France", 
        250.50
    )
    DestinationService.add_destination(
        "Tokyo", 
        "Vibrant modern metropolis", 
        "Japan", 
        300.75
    )
    
    app.run(host='0.0.0.0', port=5001, debug=True)