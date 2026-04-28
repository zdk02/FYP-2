"""
Configuration settings for AEGIS Platform
"""
import os
from datetime import timedelta

class BaseConfig:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'aegis-super-secret-key-change-in-production')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Upload settings
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads')
    SCRIPTS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scripts')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    
    # Execution settings
    SCRIPT_TIMEOUT = 3600  # 1 hour max execution time
    MAX_CONCURRENT_ATTACKS = 10
    
    # Report settings
    REPORTS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports')

    # Plugin settings (YAML-backed scanner plugins)
    PLUGINS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'plugins')
    SCANNERS_PLUGINS_FOLDER = os.path.join(PLUGINS_FOLDER, 'scanners')
    SCANNER_MAX_EXEC_SECONDS = 180
    SCANNER_BACKUP_KEEP = 20


class DevelopmentConfig(BaseConfig):
    """Development configuration"""
    DEBUG = True
    # Use instance folder for database (created automatically by Flask)
    _basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _dbpath = os.path.join(_basedir, 'instance', 'aegis_dev.db')
    # Create instance directory if it doesn't exist
    os.makedirs(os.path.dirname(_dbpath), exist_ok=True)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f'sqlite:///{_dbpath}')


class ProductionConfig(BaseConfig):
    """Production configuration"""
    DEBUG = False
    _basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _dbpath = os.path.join(_basedir, 'instance', 'aegis_prod.db')
    os.makedirs(os.path.dirname(_dbpath), exist_ok=True)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f'sqlite:///{_dbpath}')


class TestingConfig(BaseConfig):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
