"""
Celery application configuration for the security scanner service.
This module sets up the Celery app with Redis as broker and result backend.
"""

import os
from celery import Celery
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Celery configuration
celery_app = Celery(
    'security_scanner',
    broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
    include=['services.tasks.security_tasks']
)

# Celery settings
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone=os.getenv('CELERY_TIMEZONE', 'UTC'),
    enable_utc=os.getenv('CELERY_ENABLE_UTC', 'True').lower() == 'true',
    result_expires=3600,  # Results expire after 1 hour
    task_default_queue='security_scans',
    task_routes={
        'services.tasks.security_tasks.perform_security_scan': {'queue': 'security_scans'},
    },
    # Worker settings
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)

# Configure Redis connection pool
celery_app.conf.broker_connection_retry_on_startup = True
celery_app.conf.redis_max_connections = 20

if __name__ == '__main__':
    celery_app.start()