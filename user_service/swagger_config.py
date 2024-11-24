# Swagger configuration dictionary
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

# Swagger template dictionary
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

# Endpoint specifications
register = {
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
                    'name': {'type': 'string'},
                    'email': {'type': 'string'},
                    'password': {'type': 'string'},
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
            'description': 'User registered successfully'
        },
        '400': {
            'description': 'Registration failed'
        }
    }
}

login = {
    'tags': ['User Authentication'],
    'summary': 'User login',
    'description': 'Endpoint for user login',
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['email', 'password']
            }
        }
    ],
    'responses': {
        '200': {
            'description': 'Login successful'
        },
        '401': {
            'description': 'Authentication failed'
        }
    }
}

get_users = {
    'tags': ['Admin'],
    'summary': 'Get all users',
    'description': 'Admin endpoint to retrieve all registered users',
    'responses': {
        '200': {
            'description': 'List of all users'
        },
        '401': {
            'description': 'Unauthorized access'
        },
        '403': {
            'description': 'Forbidden - Admin access required'
        }
    },
    'security': [{'Bearer': []}]
}


get_profile = {
    'tags': ['User Specific Profile'],
    'summary': 'Get user profile',
    'description': 'Endpoint for users to view their own profile information',
    'responses': {
        '200': {
            'description': 'User profile retrieved successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string'},
                    'name': {'type': 'string'},
                    'email': {'type': 'string'},
                    'role': {'type': 'string'},
                    'created_at': {'type': 'string', 'format': 'date-time'}
                }
            }
        },
        '401': {
            'description': 'Unauthorized - Invalid or missing token'
        },
        '404': {
            'description': 'User not found'
        }
    },
    'security': [{'Bearer': []}]
}