from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import os
import uvicorn
import logging
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import enhanced services and components
from services import load_services
from services.auth import API_KEY_HEADER
from services.database import init_database, check_database_health
from services.tenant_manager import TenantMiddleware
from services.service_registry import create_service_discovery_router, create_service_registry_router
from services.infrastructure.cenexo_scanner import CenexoScannerService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Initialize FastAPI app
app = FastAPI(
    title="Cenexo Unified Platform",
    description="A unified, modular web platform for managing complex internet infrastructure and digital services with multi-tenant architecture",
    version="2.0.0"
)

# Security middleware
def validate_cors_origins():
    """Validate CORS origins to prevent credential leakage"""
    origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    # Clean up whitespace
    origins = [origin.strip() for origin in origins if origin.strip()]

    # Prevent wildcard with credentials
    if True and "*" in origins:  # allow_credentials is hardcoded to True
        raise ValueError("Cannot use wildcard origins (*) with allow_credentials=True")

    return origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=validate_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Accept",
        "Accept-Language",
        "Content-Language",
        "Content-Type",
        "Authorization",
        "X-API-Key",
        "X-Tenant-ID",
        "X-Requested-With"
    ],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
)

# Tenant middleware for multi-tenant support
app.add_middleware(TenantMiddleware)

# Enhanced logging middleware
from services.enhanced_logging import LoggingMiddleware

# Monitoring middleware
from services.monitoring import MonitoringMiddleware
app.add_middleware(MonitoringMiddleware)

# Custom middleware to extract API key from headers
@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    """Extract API key from X-API-Key header and add to request state."""
    api_key = request.headers.get(API_KEY_HEADER)
    request.state.api_key = api_key
    response = await call_next(request)
    return response

# Security headers middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    # Content Security Policy - allow Swagger UI resources for docs
    if request.url.path == "/docs":
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' https://fastapi.tiangolo.com data:; "
            "connect-src 'self'"
        )
    else:
        # Strict CSP for API endpoints
        response.headers["Content-Security-Policy"] = "default-src 'none'"

    # Remove server information
    if "Server" in response.headers:
        del response.headers["Server"]

    return response

# Custom error handler for better security
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with sanitized error responses."""
    # Log security-relevant errors
    if exc.status_code in [401, 403, 429]:
        logger.warning(f"Security event: {exc.status_code} - {exc.detail} - Path: {request.url.path}")

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "Request failed",
            "error_code": f"HTTP_{exc.status_code}"
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions with sanitized error responses."""
    logger.error(f"Unexpected error: {str(exc)} - Path: {request.url.path}")

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "error_code": "INTERNAL_ERROR",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )

# Load all services
services_router = load_services()
app.include_router(services_router)

# Add service discovery and registry routers
app.include_router(create_service_discovery_router())
app.include_router(create_service_registry_router())

# Add monitoring router
from services.monitoring import create_monitoring_router

# Add admin interface router
from services.admin_interface import create_admin_router
app.include_router(create_admin_router())

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database and services on startup"""
    init_database()
    logger.info("Database initialized successfully")

    # Initialize scanner service
    try:
        from services.infrastructure.cenexo_scanner import CenexoScannerService
        from services.database_models import Tenant
        from services.database import get_db
        from sqlalchemy.orm import Session

        # Use get_db generator properly to get a database session
        db_gen = get_db()
        db = next(db_gen)
        try:
            # Check if default tenant exists
            default_tenant = db.query(Tenant).filter(Tenant.name == "default").first()
            if not default_tenant:
                # Create default tenant
                default_tenant = Tenant(
                    name="default",
                    domain="localhost",
                    is_active=True,
                    max_users=10,
                    max_services=5
                )
                db.add(default_tenant)
                db.commit()
                db.refresh(default_tenant)
                logger.info(f"Created default tenant: {default_tenant.uuid}")

            # Create scanner service instance and add routes
            scanner_service = CenexoScannerService(tenant=default_tenant)
            app.include_router(
                scanner_service.router,
                prefix="/api/v1/cenexo-scanner",
                tags=["cenexo-scanner"]
            )
            logger.info("Cenexo Scanner service initialized successfully")

        except Exception as e:
            logger.error(f"Error initializing scanner service: {e}")
            raise
        finally:
            db.close()

    except Exception as e:
        logger.error(f"Failed to initialize scanner service: {e}")

# Initialize database when running as main script
if __name__ == "__main__":
    init_database()

@app.get("/")
async def root():
    """Root endpoint - platform information"""
    db_health = check_database_health()
    return {
        "message": "Cenexo Unified Platform",
        "description": "A unified, modular web platform for managing complex internet infrastructure and digital services",
        "status": "healthy" if db_health["status"] == "healthy" else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.0.0",
        "services": ["cenexo_scanner", "service_discovery", "service_registry"],
        "database": db_health,
        "features": [
            "Multi-tenant architecture",
            "Service registry and discovery",
            "Enhanced security controls",
            "Audit logging",
            "Configuration management"
        ]
    }

@app.get("/health")
async def health_check():
    """Enhanced health check endpoint"""
    db_health = check_database_health()
    return {
        "status": "healthy" if db_health["status"] == "healthy" else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": db_health,
        "services": {
            "cenexo_scanner": "available",
            "service_discovery": "available",
            "service_registry": "available"
        }
    }

@app.get("/platform/info")
async def platform_info():
    """Platform information endpoint"""
    return {
        "platform": "Cenexo Unified Platform",
        "version": "2.0.0",
        "description": "Unified platform for managing complex internet infrastructure and digital services",
        "architecture": "Multi-tenant, service-oriented architecture",
        "features": [
            "Multi-tenant isolation",
            "Dynamic service loading",
            "Service registry and discovery",
            "Enhanced security controls",
            "Audit logging and monitoring",
            "Configuration management",
            "API versioning support"
        ],
        "services": [
            {
                "name": "cenexo_scanner",
                "type": "security_scanner",
                "description": "Enhanced network security scanner with multi-tenant support",
                "version": "1.0.0"
            }
        ],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

if __name__ == "__main__":
    # Security: Only bind to localhost in production
    environment = os.getenv("ENVIRONMENT", "development")
    host = "127.0.0.1" if environment == "production" else "0.0.0.0"

    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=environment == "development"
    )