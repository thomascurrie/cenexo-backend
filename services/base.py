"""
Base service interface for all services in the modular FastAPI application.
This provides a common structure and interface for all services.
"""

from abc import ABC, abstractmethod
from fastapi import APIRouter
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class BaseService(ABC):
    """
    Abstract base class for all services.
    Provides common functionality and enforces interface consistency.
    """

    def __init__(self, service_name: str, description: str):
        """
        Initialize the base service.

        Args:
            service_name: Name of the service
            description: Description of the service
        """
        self.service_name = service_name
        self.description = description
        self.router = APIRouter()
        self.logger = logging.getLogger(f"{__name__}.{service_name}")

        # Register common endpoints
        self._register_common_endpoints()

    def _register_common_endpoints(self):
        """Register common endpoints for all services."""

        @self.router.get("/health")
        async def service_health():
            """Service-specific health check"""
            from datetime import datetime, timezone
            return {
                "service": self.service_name,
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        @self.router.get("/info")
        async def service_info():
            """Service information endpoint"""
            return {
                "service": self.service_name,
                "description": self.description,
                "version": "1.0.0",
                "endpoints": self._get_service_endpoints()
            }

    def _get_service_endpoints(self) -> Dict[str, str]:
        """
        Get all endpoints for this service.
        Override in subclasses to provide specific endpoints.
        """
        return {
            "health": f"/api/v1/{self.service_name.replace('_', '-')}/health",
            "info": f"/api/v1/{self.service_name.replace('_', '-')}/info"
        }

    @abstractmethod
    def setup_routes(self):
        """Setup the service-specific routes. Must be implemented by subclasses."""
        pass

    def get_service_status(self) -> Dict[str, Any]:
        """Get the current status of the service."""
        return {
            "service": self.service_name,
            "status": "active",
            "routes": len([route for route in self.router.routes if hasattr(route, 'path')])
        }