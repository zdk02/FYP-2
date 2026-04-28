"""
Celery configuration for async task execution
"""
from celery import Celery
from flask import Flask
import os

celery = Celery(__name__)


def init_celery(app: Flask):
    """Initialize Celery with Flask app context"""
    
    celery.conf.update(
        broker_url=os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/1'),
        result_backend=os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2'),
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        task_track_started=True,
        task_time_limit=30 * 60,  # 30 minutes hard limit
    )
    
    class ContextTask(celery.Task):
        """Celery task that runs within Flask app context"""
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    return celery
