from flask import Flask
from destination_service.routes import destination_routes  # Import your
from flask_restx import Api
from flask_swagger_ui import get_swaggerui_blueprint

# Initialize Flask app
app = Flask(__name__)

# Set up Flask-RESTX API
api = Api(
    app,
    version='1.0',
    title='Travel API',
    description='A simple travel API for destinations management'
)

# Swagger UI configuration
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL, API_URL, config={'app_name': "Travel API"}
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Register the blueprint from the destination_service
app.register_blueprint(destination_routes, url_prefix='/destinations')  # Mak

# Main entry point to run the app
if __name__ == "__main__":
    app.run(port=5001, debug=True)
