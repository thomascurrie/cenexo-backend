"""
Enhanced logging and monitoring system for Cenexo Unified Platform.
Provides structured logging, audit trails, and monitoring capabilities.
"""

import logging
import structlog
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import json
import os
from sqlalchemy.orm import Session
from .database_models import AuditLog, Tenant, User

# Configure structlog
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

class EnhancedLogger:
    """Enhanced logging with structured output and audit capabilities"""

    def __init__(self):
        self.logger = structlog.get_logger()
        self.audit_logger = logging.getLogger("audit")

        # Configure audit logger
        audit_handler = logging.FileHandler("logs/audit.log")
        audit_handler.setLevel(logging.INFO)
        audit_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        audit_handler.setFormatter(audit_formatter)
        self.audit_logger.addHandler(audit_handler)

    def log_api_request(self, method: str, path: str, user_agent: str,
                      ip_address: str, tenant_id: Optional[str] = None,
                      user_id: Optional[str] = None):
        """Log API request"""
        self.logger.info(
            "API Request",
            method=method,
            path=path,
            user_agent=user_agent,
            ip_address=ip_address,
            tenant_id=tenant_id,
            user_id=user_id
        )

    def log_api_response(self, method: str, path: str, status_code: int,
                        response_time: float, tenant_id: Optional[str] = None):
        """Log API response"""
        self.logger.info(
            "API Response",
            method=method,
            path=path,
            status_code=status_code,
            response_time=response_time,
            tenant_id=tenant_id
        )

    def log_security_event(self, event_type: str, severity: str, details: Dict[str, Any],
                          tenant_id: Optional[str] = None, user_id: Optional[str] = None):
        """Log security event"""
        self.logger.warning(
            "Security Event",
            event_type=event_type,
            severity=severity,
            details=details,
            tenant_id=tenant_id,
            user_id=user_id
        )

    def log_scan_activity(self, action: str, targets: list, scan_type: str,
                         user_id: str, tenant_id: str, task_id: Optional[str] = None):
        """Log scan activity"""
        self.logger.info(
            "Scan Activity",
            action=action,
            targets=targets,
            scan_type=scan_type,
            user_id=user_id,
            tenant_id=tenant_id,
            task_id=task_id
        )

    def log_audit_event(self, db: Session, tenant: Optional[Tenant] = None,
                       user: Optional[User] = None, action: str = "UNKNOWN",
                       resource_type: str = "unknown", resource_id: str = "",
                       details: dict = None, ip_address: str = None,
                       user_agent: str = None):
        """Log audit event to database"""
        try:
            audit_log = AuditLog(
                tenant_id=tenant.id if tenant else None,
                user_id=user.id if user else None,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details or {},
                ip_address=ip_address,
                user_agent=user_agent,
                timestamp=datetime.now(timezone.utc)
            )

            db.add(audit_log)
            db.commit()

            # Also log to file
            self.audit_logger.info(
                f"AUDIT: {action} - {resource_type} - {resource_id}",
                extra={
                    "tenant_id": tenant.uuid if tenant else None,
                    "user_id": user.username if user else None,
                    "details": details or {}
                }
            )

        except Exception as e:
            self.logger.error("Failed to log audit event", error=str(e))

    def log_rate_limit_exceeded(self, user: User, endpoint: str, tenant_id: str):
        """Log rate limit violation"""
        self.log_security_event(
            event_type="RATE_LIMIT_EXCEEDED",
            severity="medium",
            details={
                "endpoint": endpoint,
                "user_id": user.username,
                "tenant_id": tenant_id
            },
            tenant_id=tenant_id,
            user_id=user.username
        )

    def log_scan_started(self, user: User, targets: list, scan_type: str, tenant_id: str):
        """Log scan start event"""
        self.log_scan_activity(
            action="STARTED",
            targets=targets,
            scan_type=scan_type,
            user_id=user.username,
            tenant_id=tenant_id
        )

    def log_scan_completed(self, user: User, targets: list, scan_type: str,
                          tenant_id: str, task_id: str, duration: float):
        """Log scan completion event"""
        self.log_scan_activity(
            action="COMPLETED",
            targets=targets,
            scan_type=scan_type,
            user_id=user.username,
            tenant_id=tenant_id,
            task_id=task_id
        )

        self.logger.info(
            "Scan completed",
            duration=duration,
            targets_count=len(targets),
            task_id=task_id
        )

    def log_scan_failed(self, user: User, targets: list, scan_type: str,
                       tenant_id: str, task_id: str, error: str):
        """Log scan failure event"""
        self.log_scan_activity(
            action="FAILED",
            targets=targets,
            scan_type=scan_type,
            user_id=user.username,
            tenant_id=tenant_id,
            task_id=task_id
        )

        self.logger.error(
            "Scan failed",
            error=error,
            targets_count=len(targets),
            task_id=task_id
        )

    def log_tenant_created(self, tenant: Tenant, created_by: User):
        """Log tenant creation"""
        self.log_audit_event(
            db=None,  # Will be set by caller
            tenant=tenant,
            user=created_by,
            action="CREATE",
            resource_type="tenant",
            resource_id=tenant.uuid,
            details={
                "tenant_name": tenant.name,
                "domain": tenant.domain
            }
        )

    def log_user_login(self, user: User, ip_address: str, user_agent: str):
        """Log user login"""
        self.log_audit_event(
            db=None,  # Will be set by caller
            tenant=user.tenant,
            user=user,
            action="LOGIN",
            resource_type="user",
            resource_id=user.uuid,
            details={
                "ip_address": ip_address,
                "user_agent": user_agent
            }
        )

    def log_service_error(self, service_name: str, error: str, tenant_id: str):
        """Log service error"""
        self.logger.error(
            "Service Error",
            service=service_name,
            error=error,
            tenant_id=tenant_id
        )

# Global enhanced logger instance
enhanced_logger = EnhancedLogger()

class LoggingMiddleware:
    """Middleware for request/response logging"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract request information
        request = Request(scope, receive)
        start_time = datetime.now(timezone.utc)

        # Get client information
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")

        # Log request
        enhanced_logger.log_api_request(
            method=scope["method"],
            path=scope["path"],
            user_agent=user_agent,
            ip_address=client_ip
        )

        # Process request
        start_time = datetime.now(timezone.utc)

        async def send_with_logging(message):
            if message["type"] == "http.response.start":
                # Calculate response time
                response_time = (datetime.now(timezone.utc) - start_time).total_seconds()

                # Log response
                enhanced_logger.log_api_response(
                    method=scope["method"],
                    path=scope["path"],
                    status_code=message["status"],
                    response_time=response_time
                )

            await send(message)

        await self.app(scope, receive, send_with_logging)

def get_logger(name: str = None) -> structlog.BoundLogger:
    """Get structured logger instance"""
    return structlog.get_logger(name)

def setup_logging():
    """Setup enhanced logging configuration"""
    # Create logs directory
    os.makedirs("logs", exist_ok=True)

    # Configure main logger
    main_handler = logging.FileHandler("logs/platform.log")
    main_handler.setLevel(logging.INFO)

    # Configure error logger
    error_handler = logging.FileHandler("logs/errors.log")
    error_handler.setLevel(logging.ERROR)

    # Configure security logger
    security_handler = logging.FileHandler("logs/security.log")
    security_handler.setLevel(logging.WARNING)

    # Create formatters
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    main_handler.setFormatter(formatter)
    error_handler.setFormatter(formatter)
    security_handler.setFormatter(formatter)

    # Get root logger and add handlers
    root_logger = logging.getLogger()
    root_logger.addHandler(main_handler)
    root_logger.addHandler(error_handler)

    # Security logger
    security_logger = logging.getLogger("security")
    security_logger.addHandler(security_handler)

    # Set log levels
    root_logger.setLevel(logging.INFO)
    security_logger.setLevel(logging.WARNING)

    # Prevent duplicate logs
    root_logger.handlers.clear()
    root_logger.addHandler(main_handler)
    root_logger.addHandler(error_handler)

    structlog.get_logger().info("Enhanced logging system initialized")