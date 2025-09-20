"""
Service registry and configuration management system.
Provides dynamic service loading, configuration management, and service discovery.
"""

import logging
import importlib
import inspect
from typing import Dict, List, Optional, Type, Any
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from .database import get_db
from .database_models import Service, ServiceConfiguration, Tenant
from .tenant_manager import get_current_tenant
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class ServiceRegistry:
    """Manages service registration and configuration"""

    def __init__(self):
        self.registered_services: Dict[str, Type] = {}
        self.service_instances: Dict[str, Any] = {}
        self.service_configs: Dict[str, Dict] = {}
        self.main_router = APIRouter()

    def register_service_class(self, service_class: Type, service_name: str):
        """Register a service class"""
        if service_name in self.registered_services:
            logger.warning(f"Service {service_name} is already registered")

        self.registered_services[service_name] = service_class
        logger.info(f"Registered service class: {service_name}")

    def get_service_class(self, service_name: str) -> Optional[Type]:
        """Get registered service class"""
        return self.registered_services.get(service_name)

    def create_service_instance(self, service_name: str, tenant: Tenant, **kwargs) -> Any:
        """Create service instance for tenant"""
        service_class = self.get_service_class(service_name)
        if not service_class:
            raise HTTPException(
                status_code=404,
                detail=f"Service {service_name} not found"
            )

        # Create instance key
        instance_key = f"{tenant.uuid}:{service_name}"

        if instance_key not in self.service_instances:
            # Get service configuration
            config = self.get_service_config(service_name, tenant.uuid)

            # Create service instance
            service_instance = service_class(tenant=tenant, config=config, **kwargs)
            self.service_instances[instance_key] = service_instance

            logger.info(f"Created service instance: {instance_key}")

        return self.service_instances[instance_key]

    def get_service_config(self, service_name: str, tenant_id: str) -> Dict:
        """Get service configuration for tenant"""
        config_key = f"{tenant_id}:{service_name}"

        if config_key not in self.service_configs:
            # Load configuration from database or defaults
            self.service_configs[config_key] = self._load_service_config(service_name, tenant_id)

        return self.service_configs[config_key]

    def _load_service_config(self, service_name: str, tenant_id: str) -> Dict:
        """Load service configuration from database"""
        # This would typically load from the database
        # For now, return default configuration
        return {
            "enabled": True,
            "version": "1.0.0",
            "timeout": 30,
            "max_concurrent_requests": 10
        }

    def update_service_config(self, service_name: str, tenant_id: str, config: Dict):
        """Update service configuration"""
        config_key = f"{tenant_id}:{service_name}"
        self.service_configs[config_key] = config

        # In a real implementation, this would save to database
        logger.info(f"Updated configuration for {config_key}")

    def get_service_router(self, service_name: str, tenant: Tenant) -> APIRouter:
        """Get router for service instance"""
        service_instance = self.create_service_instance(service_name, tenant)
        return service_instance.router

    def load_services_from_database(self, db: Session, tenant: Tenant):
        """Load services from database for tenant"""
        services = db.query(Service).filter(
            Service.tenant_id == tenant.id,
            Service.is_active == True
        ).all()

        for service in services:
            try:
                # Create service instance
                service_instance = self.create_service_instance(service.service_type, tenant)

                # Add to main router
                self.main_router.include_router(
                    service_instance.router,
                    prefix=f"/api/v1/{service.name}",
                    tags=[service.name]
                )

                logger.info(f"Loaded service from database: {service.name}")

            except Exception as e:
                logger.error(f"Failed to load service {service.name}: {e}")

    def get_service_info(self, service_name: str) -> Dict:
        """Get service information"""
        service_class = self.get_service_class(service_name)
        if not service_class:
            return {}

        # Get service metadata
        info = {
            "name": service_name,
            "class": service_class.__name__,
            "module": service_class.__module__,
            "doc": inspect.getdoc(service_class),
            "methods": []
        }

        # Get service methods
        for name, method in inspect.getmembers(service_class, predicate=inspect.isfunction):
            if not name.startswith('_'):
                info["methods"].append({
                    "name": name,
                    "doc": inspect.getdoc(method)
                })

        return info

    def list_registered_services(self) -> List[str]:
        """List all registered services"""
        return list(self.registered_services.keys())

    def list_service_instances(self) -> List[str]:
        """List all service instances"""
        return list(self.service_instances.keys())

# Global service registry
service_registry = ServiceRegistry()

class BaseService:
    """Enhanced base service class with tenant support"""

    def __init__(self, service_name: str, service_type: str, tenant: Tenant,
                 config: Optional[Dict] = None):
        self.service_name = service_name
        self.service_type = service_type
        self.tenant = tenant
        self.config = config or {}
        self.router = APIRouter()
        self.logger = logging.getLogger(f"{__name__}.{service_name}")

        # Register common endpoints
        self._register_common_endpoints()

    def _register_common_endpoints(self):
        """Register common service endpoints"""

        @self.router.get("/health")
        async def service_health():
            """Service-specific health check"""
            return {
                "service": self.service_name,
                "type": self.service_type,
                "tenant": self.tenant.name,
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "config": {
                    "enabled": self.config.get("enabled", True),
                    "version": self.config.get("version", "1.0.0")
                }
            }

        @self.router.get("/info")
        async def service_info():
            """Service information endpoint"""
            return {
                "service": self.service_name,
                "type": self.service_type,
                "tenant": self.tenant.name,
                "description": self.get_service_description(),
                "version": self.config.get("version", "1.0.0"),
                "endpoints": self._get_service_endpoints(),
                "config": self.config
            }

        @self.router.get("/config")
        async def get_config():
            """Get service configuration"""
            return {
                "service": self.service_name,
                "tenant": self.tenant.name,
                "config": self.config
            }

    def _get_service_endpoints(self) -> Dict[str, str]:
        """Get service endpoints"""
        return {
            "health": f"/api/v1/{self.service_name}/health",
            "info": f"/api/v1/{self.service_name}/info",
            "config": f"/api/v1/{self.service_name}/config"
        }

    def get_service_description(self) -> str:
        """Get service description - override in subclasses"""
        return f"{self.service_name} service for tenant {self.tenant.name}"

    def setup_routes(self):
        """Setup service-specific routes - must be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement setup_routes()")

# Service discovery endpoints
def create_service_discovery_router():
    """Create service discovery router"""
    router = APIRouter(prefix="/api/v1/services", tags=["services"])

    @router.get("/")
    async def list_services():
        """List all registered services"""
        return {
            "services": service_registry.list_registered_services(),
            "instances": service_registry.list_service_instances()
        }

    @router.get("/{service_name}/info")
    async def get_service_info(service_name: str):
        """Get service information"""
        info = service_registry.get_service_info(service_name)
        if not info:
            raise HTTPException(status_code=404, detail="Service not found")
        return info

    @router.get("/health")
    async def services_health():
        """Get health status of all services"""
        # This would check all service instances
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    return router

# Service registry endpoints
def create_service_registry_router():
    """Create service registry management router"""
    router = APIRouter(prefix="/api/v1/registry", tags=["registry"])

    @router.post("/services/{service_name}/config")
    async def update_service_config(
        service_name: str,
        config: Dict,
        tenant: Tenant = Depends(get_current_tenant)
    ):
        """Update service configuration"""
        service_registry.update_service_config(service_name, tenant.uuid, config)
        return {"message": "Configuration updated"}

    @router.get("/services/{service_name}/config")
    async def get_service_config(
        service_name: str,
        tenant: Tenant = Depends(get_current_tenant)
    ):
        """Get service configuration"""
        config = service_registry.get_service_config(service_name, tenant.uuid)
        return {"service": service_name, "config": config}

    return router