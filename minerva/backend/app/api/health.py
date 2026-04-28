"""
Health check API route
"""
from flask import jsonify
from app.api import api_bp
from app import db
import os


@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Docker and monitoring"""
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        db_status = 'healthy'
    except Exception as e:
        db_status = f'unhealthy: {str(e)}'
    
    return jsonify({
        'status': 'healthy' if db_status == 'healthy' else 'degraded',
        'database': db_status,
        'service': 'aegis-backend'
    }), 200 if db_status == 'healthy' else 503


@api_bp.route('/health/ready', methods=['GET'])
def readiness_check():
    """Readiness check - more lenient than health check"""
    return jsonify({
        'status': 'ready',
        'service': 'aegis-backend'
    }), 200
