from flasgger import Swagger

# Swagger Configuration
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

# Initialize Swagger instance
swagger = Swagger(template=swagger_template, config=swagger_config)

# Route Documentation Specifications
login_spec = {
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
        },
        '401': {
            'description': 'Authentication failed'
        }
    }
}

validate_token_spec = {
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
                    'permissions': {
                        'type': 'object',
                        'properties': {
                            'can_create_users': {'type': 'boolean'},
                            'can_delete_users': {'type': 'boolean'},
                            'can_modify_roles': {'type': 'boolean'},
                            'can_view_all_profiles': {'type': 'boolean'},
                            'access_level': {'type': 'string'}
                        }
                    },
                    'token_validity': {
                        'type': 'object',
                        'properties': {
                            'expiration': {'type': 'string'},
                            'valid_for': {'type': 'string'}
                        }
                    }
                }
            }
        },
        '401': {
            'description': 'Authentication failed'
        }
    }
}

token_info_spec = {
    'tags': ['Token Information'],
    'summary': 'Get detailed token and user information',
    'description': 'Returns comprehensive information about token and associated user',
    'responses': {
        '200': {
            'description': 'Token information retrieved successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'token_info': {
                        'type': 'object',
                        'properties': {
                            'user_id': {'type': 'string'},
                            'role': {'type': 'string'},
                            'validity': {'type': 'object'},
                            'session': {'type': 'object'}
                        }
                    },
                    'user_info': {'type': 'object'},
                    'access_level': {
                        'type': 'object',
                        'properties': {
                            'role_type': {'type': 'string'},
                            'permissions': {'type': 'object'}
                        }
                    }
                }
            }
        },
        '401': {
            'description': 'Authentication failed'
        },
        '404': {
            'description': 'User information not found'
        }
    }
}