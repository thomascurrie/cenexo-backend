"""
Services package for modular FastAPI application.
This package contains all service modules that can be loaded dynamically.
"""

from fastapi import APIRouter
import importlib
import os
import logging
from typing import List

logger = logging.getLogger(__name__)

def load_services() -> APIRouter:
    """
    Dynamically load all service modules and return a combined router.

    Returns:
        APIRouter: Combined router with all service endpoints
    """
    main_router = APIRouter()

    # List of service modules to load
    service_modules = [
        "security_scanner"
    ]

    loaded_services = []

    for service_name in service_modules:
        try:
            # Import the service module
            service_module = importlib.import_module(f".{service_name}", package="services")

            # Get the router from the service module
            if hasattr(service_module, 'router'):
                main_router.include_router(
                    service_module.router,
                    prefix=f"/api/v1/{service_name.replace('_', '-')}",
                    tags=[service_name]
                )
                loaded_services.append(service_name)
                logger.info(f"Loaded service: {service_name}")
            else:
                logger.warning(f"Service {service_name} does not have a router attribute")

        except ImportError as e:
            logger.error(f"Failed to load service {service_name}: {e}")
        except Exception as e:
            logger.error(f"Error loading service {service_name}: {e}")

    logger.info(f"Successfully loaded {len(loaded_services)} services: {loaded_services}")
    return main_router