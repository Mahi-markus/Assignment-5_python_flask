from flask_restx import fields

def create_api_models(api):
    """Create and return the API models for Flask-RESTX"""
    
    # Full destination model including ID
    destination_model = api.model('Destination', {
        'id': fields.Integer(
            readOnly=True, 
            description='Unique ID of the destination'
        ),
        'name': fields.String(
            required=True, 
            description='Name of the destination',
            example='Paris'
        ),
        'description': fields.String(
            required=True, 
            description='Description of the destination',
            example='The city of light'
        ),
          'location': fields.String(
            required=True, 
            location='location of the destination',
            example='Dhaka'
        ),
    })

    # Input model without ID (for POST requests)
    destination_input_model = api.model('DestinationInput', {
        'name': fields.String(
            required=True, 
            description='Name of the destination',
            example='Paris'
        ),
        'description': fields.String(
            required=True, 
            description='Description of the destination',
            example='The city of light'
        ),
          'location': fields.String(
            required=True, 
            location='location of the destination',
            example='japan'
        ),
    })

    return destination_model, destination_input_model