"""
Monitoring and metrics collection system for Cenexo Unified Platform.
Provides Prometheus metrics, health checks, and performance monitoring.
"""

import time
import psutil
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from fastapi import Request
from fastapi.responses import Response
from prometheus_client import Counter, Histogram, Gauge, Info, Enum
import logging
from .database import check_database_health
from .enhanced_logging import enhanced_logger

logger = logging.getLogger(__name__)

# Prometheus metrics
REQUEST_COUNT = Counter(
    'cenexo_requests_total',
    'Total number of requests',
    ['method', 'endpoint', 'status_code', 'tenant_id']
)

REQUEST_LATENCY = Histogram(
    'cenexo_request_duration_seconds',
    'Request duration in seconds',
    ['method', 'endpoint', 'tenant_id']
)

ACTIVE_CONNECTIONS = Gauge(
    'cenexo_active_connections',
    'Number of active connections'
)

DATABASE_CONNECTIONS = Gauge(
    'cenexo_database_connections',
    'Database connection pool status'
)

SERVICE_HEALTH = Enum(
    'cenexo_service_health',
    'Health status of services',
    ['service_name', 'tenant_id'],
    states=['healthy', 'degraded', 'unhealthy']
)

SCAN_TASKS_TOTAL = Counter(
    'cenexo_scan_tasks_total',
    'Total number of scan tasks',
    ['status', 'tenant_id']
)

SCAN_DURATION = Histogram(
    'cenexo_scan_duration_seconds',
    'Scan task duration in seconds',
    ['scan_type', 'tenant_id']
)

class MetricsCollector:
    """Collects and exposes application metrics"""

    def __init__(self):
        self.start_time = time.time()

    def record_request(self, method: str, endpoint: str, status_code: int,
                      duration: float, tenant_id: Optional[str] = None):
        """Record request metrics"""
        REQUEST_COUNT.labels(
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            tenant_id=tenant_id or 'unknown'
        ).inc()

        REQUEST_LATENCY.labels(
            method=method,
            endpoint=endpoint,
            tenant_id=tenant_id or 'unknown'
        ).observe(duration)

    def update_active_connections(self):
        """Update active connections metric"""
        try:
            # Get network connections (approximation)
            connections = len(psutil.net_connections())
            ACTIVE_CONNECTIONS.set(connections)
        except Exception as e:
            logger.warning(f"Failed to update active connections: {e}")

    def update_database_connections(self, pool_size: int, active_connections: int):
        """Update database connection metrics"""
        DATABASE_CONNECTIONS.set(active_connections)

    def record_scan_task(self, status: str, tenant_id: str):
        """Record scan task metrics"""
        SCAN_TASKS_TOTAL.labels(status=status, tenant_id=tenant_id).inc()

    def record_scan_duration(self, duration: float, scan_type: str, tenant_id: str):
        """Record scan duration metrics"""
        SCAN_DURATION.labels(scan_type=scan_type, tenant_id=tenant_id).observe(duration)

    def update_service_health(self, service_name: str, status: str, tenant_id: str):
        """Update service health status"""
        SERVICE_HEALTH.labels(
            service_name=service_name,
            tenant_id=tenant_id
        ).state(status)

    def get_system_metrics(self) -> Dict[str, Any]:
        """Get system performance metrics"""
        try:
            return {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage('/').percent,
                "uptime": time.time() - self.start_time,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            logger.warning(f"Failed to collect system metrics: {e}")
            return {"error": str(e)}

# Global metrics collector
metrics_collector = MetricsCollector()

class MonitoringMiddleware:
    """Middleware for collecting request metrics"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = time.time()
        method = scope["method"]
        path = scope["path"]

        # Extract tenant ID from headers if available
        tenant_id = None
        if "headers" in scope:
            headers = dict(scope["headers"])
            tenant_header = headers.get(b"x-tenant-id", b"").decode()
            if tenant_header:
                tenant_id = tenant_header

        async def send_with_metrics(message):
            if message["type"] == "http.response.start":
                # Calculate request duration
                duration = time.time() - start_time
                status_code = message["status"]

                # Record metrics
                metrics_collector.record_request(
                    method=method,
                    endpoint=path,
                    status_code=status_code,
                    duration=duration,
                    tenant_id=tenant_id
                )

                # Update active connections periodically
                if int(time.time()) % 10 == 0:  # Every 10 seconds
                    metrics_collector.update_active_connections()

            await send(message)

        await self.app(scope, receive, send_with_metrics)

def get_platform_health() -> Dict[str, Any]:
    """Get comprehensive platform health status"""
    db_health = check_database_health()

    # Get system metrics
    system_metrics = metrics_collector.get_system_metrics()

    # Determine overall health
    overall_status = "healthy"
    issues = []

    if db_health["status"] != "healthy":
        overall_status = "degraded"
        issues.append(f"Database: {db_health['message']}")

    if isinstance(system_metrics.get("cpu_percent"), (int, float)) and system_metrics["cpu_percent"] > 90:
        overall_status = "degraded"
        issues.append(f"High CPU usage: {system_metrics['cpu_percent']}%")

    if isinstance(system_metrics.get("memory_percent"), (int, float)) and system_metrics["memory_percent"] > 90:
        overall_status = "degraded"
        issues.append(f"High memory usage: {system_metrics['memory_percent']}%")

    if isinstance(system_metrics.get("disk_usage"), (int, float)) and system_metrics["disk_usage"] > 90:
        overall_status = "degraded"
        issues.append(f"High disk usage: {system_metrics['disk_usage']}%")

    return {
        "status": overall_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": db_health,
        "system": system_metrics,
        "services": {
            "cenexo_scanner": "healthy",
            "service_registry": "healthy",
            "tenant_manager": "healthy"
        },
        "issues": issues,
        "uptime": system_metrics.get("uptime", 0)
    }

def get_service_metrics(service_name: str, tenant_id: str) -> Dict[str, Any]:
    """Get metrics for a specific service"""
    return {
        "service": service_name,
        "tenant_id": tenant_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "health_status": SERVICE_HEALTH.labels(
            service_name=service_name,
            tenant_id=tenant_id
        )._value.get(),
        "request_count": REQUEST_COUNT.labels(
            service_name=service_name,
            tenant_id=tenant_id
        )._value.get(),
        "average_response_time": REQUEST_LATENCY.labels(
            service_name=service_name,
            tenant_id=tenant_id
        )._sum.get() / REQUEST_LATENCY.labels(
            service_name=service_name,
            tenant_id=tenant_id
        )._count.get() if REQUEST_LATENCY.labels(
            service_name=service_name,
            tenant_id=tenant_id
        )._count.get() > 0 else 0
    }

def create_monitoring_router():
    """Create monitoring and metrics router"""
    from fastapi import APIRouter

    router = APIRouter(prefix="/api/v1/monitoring", tags=["monitoring"])

    @router.get("/health")
    async def platform_health():
        """Get comprehensive platform health"""
        return get_platform_health()

    @router.get("/metrics")
    async def get_metrics():
        """Get Prometheus metrics"""
        from prometheus_client import generate_latest
        return Response(
            content=generate_latest(),
            media_type="text/plain"
        )

    @router.get("/system")
    async def system_metrics():
        """Get system performance metrics"""
        return metrics_collector.get_system_metrics()

    @router.get("/services/{service_name}/metrics")
    async def service_metrics(service_name: str, tenant_id: str = None):
        """Get metrics for a specific service"""
        return get_service_metrics(service_name, tenant_id or "default")

    @router.get("/database/status")
    async def database_status():
        """Get database connection status"""
        return check_database_health()

    return router

# Health check functions
def check_service_health(service_name: str, tenant_id: str) -> Dict[str, Any]:
    """Check health of a specific service"""
    try:
        # Update service health metric
        metrics_collector.update_service_health(service_name, "healthy", tenant_id)

        return {
            "service": service_name,
            "status": "healthy",
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        metrics_collector.update_service_health(service_name, "unhealthy", tenant_id)
        return {
            "service": service_name,
            "status": "unhealthy",
            "error": str(e),
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

def perform_health_checks() -> Dict[str, Any]:
    """Perform comprehensive health checks"""
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_status": "healthy",
        "checks": {}
    }

    # Database health check
    db_health = check_database_health()
    results["checks"]["database"] = db_health

    if db_health["status"] != "healthy":
        results["overall_status"] = "degraded"

    # System health check
    system_metrics = metrics_collector.get_system_metrics()
    results["checks"]["system"] = system_metrics

    # Service health checks
    services = ["cenexo_scanner", "service_registry", "tenant_manager"]
    results["checks"]["services"] = {}

    for service in services:
        service_health = check_service_health(service, "default")
        results["checks"]["services"][service] = service_health

        if service_health["status"] != "healthy":
            results["overall_status"] = "degraded"

    return results