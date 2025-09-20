"""
Services package for Cenexo Unified Platform.
This package contains all service modules that can be loaded dynamically with multi-tenant support.
"""

from fastapi import APIRouter
import importlib
import os
import logging
from typing import List
from .database import get_db
from .database_models import Tenant
from .service_registry import service_registry
from .tenant_manager import get_current_tenant

logger = logging.getLogger(__name__)

def load_services() -> APIRouter:
    """
    Dynamically load all service modules and return a combined router.

    Returns:
        APIRouter: Combined router with all service endpoints
    """
    main_router = APIRouter()

    # List of service modules to load (legacy services)
    legacy_service_modules = [
        "security_scanner"  # Keep for backward compatibility
    ]

    # List of new infrastructure services
    infrastructure_services = [
        "infrastructure.cenexo_scanner"
    ]

    loaded_services = []

    # Load legacy services
    for service_name in legacy_service_modules:
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
                logger.info(f"Loaded legacy service: {service_name}")
            else:
                logger.warning(f"Service {service_name} does not have a router attribute")

        except ImportError as e:
            logger.error(f"Failed to load legacy service {service_name}: {e}")
        except Exception as e:
            logger.error(f"Error loading legacy service {service_name}: {e}")

    # Load new infrastructure services
    for service_path in infrastructure_services:
        try:
            # Import the service module
            service_module = importlib.import_module(f".{service_path}", package="services")

            # Get the service class
            if hasattr(service_module, 'CenexoScannerService'):
                service_class = service_module.CenexoScannerService

                # Register the service class
                service_name = service_path.split('.')[-1]
                service_registry.register_service_class(service_class, service_name)

                # Create service instance for default tenant
                # This will be handled by the service registry when needed
                loaded_services.append(service_name)
                logger.info(f"Registered infrastructure service: {service_name}")

        except ImportError as e:
            logger.error(f"Failed to load infrastructure service {service_path}: {e}")
        except Exception as e:
            logger.error(f"Error loading infrastructure service {service_path}: {e}")

    logger.info(f"Successfully loaded {len(loaded_services)} services: {loaded_services}")
    return main_router

def get_service_router(service_name: str, tenant: Tenant) -> APIRouter:
    """
    Get router for a specific service and tenant.

    Args:
        service_name: Name of the service
        tenant: Tenant instance

    Returns:
        APIRouter: Service router for the tenant
    """
    return service_registry.get_service_router(service_name, tenant)

def list_available_services() -> List[str]:
    """
    List all available services.

    Returns:
        List[str]: List of available service names
    """
    return service_registry.list_registered_services()