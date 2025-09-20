from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import os
import uvicorn
import logging
from datetime import datetime

# Import services
from services import load_services
from services.auth import API_KEY_HEADER

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Modular FastAPI Application",
    description="A modular FastAPI application with security best practices and pluggable services",
    version="1.0.0"
)

# Security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Accept",
        "Accept-Language",
        "Content-Language",
        "Content-Type",
        "Authorization",
        "X-API-Key",
        "X-Requested-With"
    ],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
)

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
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    # Remove server information
    response.headers.pop("Server", None)

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
            "error_code": f"HTTP_{exc.status_code}",
            "timestamp": datetime.utcnow().isoformat() + "Z"
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
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    )

# Load all services
services_router = load_services()
app.include_router(services_router)

@app.get("/")
async def root():
    """Root endpoint - health check"""
    return {
        "message": "Modular FastAPI Application",
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "services": ["security_scanner"]
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z"
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