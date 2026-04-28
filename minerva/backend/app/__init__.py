"""
AEGIS - Agentic AI Security Testing Platform
Enterprise-grade penetration testing framework for AI systems
"""

from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()
celery = None

def create_app(config_name='development'):
    """Application factory pattern for Flask app creation"""
    global celery
    
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(f'app.config.{config_name.capitalize()}Config')
    
    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Initialize Celery
    from app.celery_app import init_celery
    celery = init_celery(app)
    
    # Register blueprints
    from app.api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    
    # Create tables and initialize data
    with app.app_context():
        try:
            db.create_all()
            from app.services.init_service import initialize_default_data
            initialize_default_data()
        except Exception as e:
            print(f"Warning: Failed to initialize default data: {e}")
            # Don't fail startup completely, database structure is created
    
    # Add error handlers
    @app.errorhandler(404)
    def not_found(error):
        from flask import jsonify
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        from flask import jsonify
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500
    
    return app
