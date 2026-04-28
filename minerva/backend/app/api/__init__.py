"""
API Blueprint initialization
All routes are registered on the main api_bp blueprint
"""
from flask import Blueprint

api_bp = Blueprint('api', __name__)

# Import all route modules - they register routes on api_bp
from app.api import health
from app.api import auth
from app.api import users
from app.api import categories
from app.api import attacks
from app.api import payloads
from app.api import techniques
from app.api import connections
from app.api import targets
from app.api import campaigns
from app.api import executions
from app.api import reports
from app.api import scans
from app.api import scanners
from app.api import callbacks
from app.api import notifications
from app.api import settings
from app.api import dashboard
