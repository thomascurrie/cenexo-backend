"""
Security logging service for comprehensive audit trails.
Provides structured logging for security events and compliance.
"""

import os
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)

class SecurityEventType(str, Enum):
    """Types of security events to log"""
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_FAILURE = "authorization_failure"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INVALID_INPUT = "invalid_input"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"

class SecurityLogger:
    """
    Comprehensive security logging service.
    """

    def __init__(self):
        """Initialize the security logger."""
        self.audit_enabled = os.getenv("SCAN_AUDIT_LOG_ENABLED", "true").lower() == "true"
        self.log_file = self._validate_log_file_path(
            os.getenv("SECURITY_LOG_FILE", "security_audit.log")
        )

        # Setup security logger
        self.security_logger = logging.getLogger("security_audit")
        self.security_logger.setLevel(logging.INFO)

        # File handler for security logs with rotation
        if self.audit_enabled:
            try:
                # Use RotatingFileHandler for log rotation
                handler = RotatingFileHandler(
                    self.log_file,
                    maxBytes=10 * 1024 * 1024,  # 10MB per file
                    backupCount=5  # Keep 5 backup files
                )
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                handler.setFormatter(formatter)
                self.security_logger.addHandler(handler)
                logger.info(f"Security logging enabled with rotation to {self.log_file}")
            except (OSError, IOError) as e:
                logger.error(f"Failed to setup security log file {self.log_file}: {e}")
                self.audit_enabled = False

    def _validate_log_file_path(self, log_file_path: str) -> str:
        """
        Validate and sanitize the log file path.

        Args:
            log_file_path: Path to the log file

        Returns:
            Validated log file path
        """
        if not log_file_path:
            return "security_audit.log"

        # Ensure the path is safe (no path traversal)
        log_file_path = os.path.basename(log_file_path)

        # Ensure it's in a writable location
        if not log_file_path.endswith('.log'):
            log_file_path += '.log'

        return log_file_path

    def log_security_event(
        self,
        event_type: SecurityEventType,
        user: Optional[Any] = None,
        resource: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """
        Log a security event.

        Args:
            event_type: Type of security event
            user: User object or identifier
            resource: Resource being accessed
            details: Additional event details
            ip_address: Client IP address
            user_agent: Client user agent
        """
        if not self.audit_enabled:
            return

        # Build log entry
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user": self._get_user_identifier(user),
            "resource": resource or "",
            "details": details or {},
            "ip_address": ip_address or "",
            "user_agent": user_agent or ""
        }

        # Log the event
        self.security_logger.info(json.dumps(log_entry))

        # Also log to main logger for monitoring
        logger.info(f"SECURITY_EVENT: {event_type} - User: {log_entry['user']} - Resource: {resource}")

    def _get_user_identifier(self, user) -> str:
        """Get user identifier for logging."""
        if not user:
            return "anonymous"

        if hasattr(user, 'username'):
            return user.username
        elif hasattr(user, 'id'):
            return str(user.id)
        else:
            return str(user)

    def log_authentication_success(self, user, ip_address: str = None, user_agent: str = None):
        """Log successful authentication."""
        self.log_security_event(
            SecurityEventType.AUTHENTICATION_SUCCESS,
            user=user,
            details={"auth_method": "api_key"},
            ip_address=ip_address,
            user_agent=user_agent
        )

    def log_authentication_failure(self, reason: str, ip_address: str = None, user_agent: str = None):
        """Log failed authentication."""
        self.log_security_event(
            SecurityEventType.AUTHENTICATION_FAILURE,
            details={"reason": reason},
            ip_address=ip_address,
            user_agent=user_agent
        )

    def log_scan_started(self, user, targets: list, scan_type: str, ip_address: str = None):
        """Log scan initiation."""
        self.log_security_event(
            SecurityEventType.SCAN_STARTED,
            user=user,
            resource="security_scan",
            details={
                "targets": targets,
                "scan_type": scan_type,
                "target_count": len(targets)
            },
            ip_address=ip_address
        )

    def log_scan_completed(self, user, scan_id: str, duration: float, ip_address: str = None):
        """Log scan completion."""
        self.log_security_event(
            SecurityEventType.SCAN_COMPLETED,
            user=user,
            resource=f"scan:{scan_id}",
            details={"duration_seconds": duration},
            ip_address=ip_address
        )

    def log_rate_limit_exceeded(self, user, endpoint: str, ip_address: str = None):
        """Log rate limit violation."""
        self.log_security_event(
            SecurityEventType.RATE_LIMIT_EXCEEDED,
            user=user,
            resource=endpoint,
            details={"violation": "rate_limit"},
            ip_address=ip_address
        )

    def log_suspicious_activity(self, activity: str, details: dict, ip_address: str = None):
        """Log suspicious activity."""
        self.log_security_event(
            SecurityEventType.SUSPICIOUS_ACTIVITY,
            details={"activity": activity, **details},
            ip_address=ip_address
        )

# Global security logger instance
security_logger = SecurityLogger()