from flask import Flask
from flask_cors import CORS
import os
import sys

# Ensure backend directory is in the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from backend.flask_api.config import config_by_name
# Import routes (will be created later)
# from backend.flask_api.routes.health_routes import health_bp
# from backend.flask_api.routes.prediction_routes import prediction_bp
# from backend.flask_api.routes.alert_routes import alert_bp
# from backend.flask_api.routes.dashboard_routes import dashboard_bp
# from backend.flask_api.routes.log_routes import log_bp

def create_app(config_name: str = 'development') -> Flask:
    """
    Application factory for Flask app
    
    Args:
        config_name: 'development', 'testing', or 'production'
        
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    
    # Load config
    app.config.from_object(config_by_name[config_name])
    
    # Enable CORS
    CORS(app)
    
    # Register blueprints
    from backend.flask_api.routes.health_routes import health_bp
    from backend.flask_api.routes.prediction_routes import prediction_bp
    from backend.flask_api.routes.alert_routes import alert_bp
    from backend.flask_api.routes.dashboard_routes import dashboard_bp
    from backend.flask_api.routes.log_routes import log_bp
    from backend.flask_api.routes.live_routes import live_bp
    from backend.flask_api.routes.device_routes import device_bp
    
    app.register_blueprint(health_bp)
    app.register_blueprint(prediction_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(log_bp)
    app.register_blueprint(live_bp)
    app.register_blueprint(device_bp)
    
    from backend.database.db_init import init_db
    init_db(app)

    return app
