"""
Security Scanner Service using NMAP with Celery.
Provides network scanning capabilities with asynchronous task processing.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from fastapi import HTTPException
import ipaddress
import os

from .base import BaseService
from .models import (
    ScanRequest, ScanResult, ScanTarget, PortInfo,
    ErrorResponse, ServiceHealthResponse
)
from .celery_app import celery_app
from .tasks.security_tasks import perform_security_scan
from .auth import get_current_user, require_user, require_admin, UserRole
from .rate_limiter import rate_limiter
from .security_logger import security_logger

logger = logging.getLogger(__name__)

class SecurityScannerService(BaseService):
    """
    Security scanner service that uses NMAP with Celery for asynchronous processing.
    """

    def __init__(self):
        """Initialize the security scanner service."""
        super().__init__(
            service_name="security_scanner",
            description="Network security scanner using NMAP with Celery task processing"
        )

        # Setup routes
        self.setup_routes()

    async def _check_authorization(self, user):
        """Check if the scan request is authorized"""
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Authentication required for scan operations"
            )

        # Check if authorization is required
        if os.getenv("SCAN_AUTHORIZATION_REQUIRED", "true").lower() == "true":
            # Log successful authorization
            logger.info(f"Authorization check passed for user: {user.username} (role: {user.role})")
        else:
            logger.info("Authorization check skipped (not required)")

    def _check_target_allowlist(self, targets: List[str]):
        """Check if targets are in the allowed networks"""
        allowed_networks = os.getenv("ALLOWED_SCAN_NETWORKS", "")
        if not allowed_networks:
            logger.warning("No network allowlist configured - allowing all targets")
            return

        allowed_nets = allowed_networks.split(",")
        for target in targets:
            target_allowed = False
            try:
                target_ip = ipaddress.ip_address(target)
                for net_str in allowed_nets:
                    try:
                        net = ipaddress.ip_network(net_str.strip(), strict=False)
                        if target_ip in net:
                            target_allowed = True
                            break
                    except ValueError:
                        logger.warning(f"Invalid network in allowlist: {net_str}")
            except ValueError:
                # Target is hostname, not IP - allow for now
                target_allowed = True

            if not target_allowed:
                raise HTTPException(
                    status_code=403,
                    detail=f"Target {target} not in allowed networks: {allowed_networks}"
                )

    async def _check_rate_limit(self, user):
        """Check rate limiting for scan requests"""
        # Check rate limit for scan endpoint
        allowed, remaining, reset_time = rate_limiter.check_rate_limit(
            user=user,
            endpoint="scan",
            limit=None,  # Use role-based limits
            window_minutes=1
        )

        if not allowed:
            # Log rate limit violation
            security_logger.log_rate_limit_exceeded(
                user=user,
                endpoint="scan"
            )

            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Rate limit exceeded",
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "details": {
                        "retry_after": reset_time,
                        "message": "Too many scan requests. Please try again later."
                    }
                }
            )

        logger.info(f"Rate limit check passed for user {user.username if user else 'anonymous'}. "
                   f"Remaining requests: {remaining if remaining is not None else 'unlimited'}")

    async def _log_scan_request(self, task_id: str, request: ScanRequest, user):
        """Log scan request for audit purposes"""
        # Use comprehensive security logging
        security_logger.log_scan_started(
            user=user,
            targets=request.targets,
            scan_type=request.scan_type
        )

        # Also log to regular logger for monitoring
        logger.info(
            f"Scan task {task_id} requested by user {user.username} (role: {user.role}) "
            f"for {len(request.targets)} targets"
        )

    def setup_routes(self):
        """Setup the security scanner routes."""

        @self.router.post("/scan")
        async def start_scan(
            request: ScanRequest,
            user = Depends(require_user)
        ):
            """
            Start a security scan task on the specified targets.

            Args:
                request: ScanRequest containing targets and scan parameters
                user: Authenticated user

            Returns:
                Dictionary with task_id and status
            """
            try:
                # Security checks
                await self._check_authorization(user)
                self._check_target_allowlist(request.targets)
                await self._check_rate_limit(user)

                # Validate targets
                validated_targets = await self._validate_targets(request.targets)

                logger.info(f"Starting scan task for targets: {request.targets} by user: {user.username}")

                # Prepare task data
                task_data = {
                    'targets': validated_targets,
                    'scan_type': request.scan_type,
                    'ports': request.ports,
                    'timeout': request.timeout,
                    'user_id': user.username,
                    'user_role': user.role
                }

                # Trigger Celery task
                celery_task = perform_security_scan.delay(task_data)

                # Audit logging with actual task ID
                await self._log_scan_request(celery_task.id, request, user)

                logger.info(f"Scan task {celery_task.id} started for targets: {request.targets} by user: {user.username}")
                return {
                    "task_id": celery_task.id,
                    "status": "PENDING",
                    "message": "Scan task started successfully"
                }

            except HTTPException:
                # Re-raise HTTP exceptions as-is
                raise
            except Exception as e:
                logger.error(f"Failed to start scan task: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=ErrorResponse(
                        error="Failed to start scan task",
                        error_code="TASK_START_ERROR",
                        details={"error": str(e)}
                    ).dict()
                )

        @self.router.get("/scan/{task_id}")
        async def get_scan_result(
            task_id: str,
            user = Depends(require_viewer)
        ):
            """
            Retrieve a scan result by task ID.

            Args:
                task_id: Unique identifier of the scan task
                user: Authenticated user

            Returns:
                ScanResult for the specified task
            """
            try:
                # Get task result from Celery
                task = celery_app.AsyncResult(task_id)

                if task.state == 'PENDING':
                    raise HTTPException(
                        status_code=404,
                        detail=ErrorResponse(
                            error="Task not found or still pending",
                            error_code="TASK_NOT_FOUND",
                            details={"task_id": task_id, "status": task.state}
                        ).dict()
                    )

                elif task.state == 'PROGRESS':
                    return {
                        "task_id": task_id,
                        "status": task.state,
                        "progress": task.info.get('status', 'Processing...') if task.info else 'Processing...'
                    }

                elif task.state == 'SUCCESS':
                    # Task completed successfully
                    result_data = task.result
                    if result_data:
                        # Convert result data back to ScanResult
                        results = {}
                        for target, target_data in result_data['results'].items():
                            results[target] = ScanTarget(**target_data)

                        scan_result = ScanResult(
                            scan_id=result_data['scan_id'],
                            targets=result_data['targets'],
                            results=results,
                            duration=result_data['duration'],
                            status=result_data['status']
                        )
                        return scan_result
                    else:
                        raise HTTPException(
                            status_code=404,
                            detail="Task result not found"
                        )

                else:
                    # Task failed
                    error_detail = task.info if task.info else "Unknown error"
                    raise HTTPException(
                        status_code=500,
                        detail=ErrorResponse(
                            error=f"Task failed: {error_detail}",
                            error_code="TASK_FAILED",
                            details={"task_id": task_id, "status": task.state}
                        ).dict()
                    )

            except Exception as e:
                logger.error(f"Error retrieving task {task_id}: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=ErrorResponse(
                        error="Failed to retrieve scan result",
                        error_code="RESULT_RETRIEVAL_ERROR",
                        details={"task_id": task_id, "error": str(e)}
                    ).dict()
                )

        @self.router.get("/tasks/{task_id}/status")
        async def get_task_status(
            task_id: str,
            user = Depends(require_viewer)
        ):
            """
            Get the status of a scan task.

            Args:
                task_id: Unique identifier of the scan task
                user: Authenticated user

            Returns:
                Dictionary with task status information
            """
            try:
                task = celery_app.AsyncResult(task_id)
                return {
                    "task_id": task_id,
                    "status": task.state,
                    "progress": task.info.get('status') if task.info and isinstance(task.info, dict) else None,
                    "result": task.result if task.state == 'SUCCESS' else None
                }
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=ErrorResponse(
                        error="Failed to get task status",
                        error_code="STATUS_CHECK_ERROR",
                        details={"task_id": task_id, "error": str(e)}
                    ).dict()
                )

        @self.router.get("/health", response_model=ServiceHealthResponse)
        async def health_check():
            """Service-specific health check."""
            return ServiceHealthResponse(
                service=self.service_name,
                status="healthy",
                timestamp=datetime.utcnow().isoformat() + "Z",
                version="1.0.0"
            )

    async def _validate_targets(self, targets: List[str]) -> List[str]:
        """
        Validate scan targets asynchronously.

        Args:
            targets: List of target strings

        Returns:
            List of validated targets

        Raises:
            HTTPException: If any target is invalid
        """
        validated = []

        for target in targets:
            try:
                # Check if it's a valid IP
                ipaddress.ip_address(target)
                validated.append(target)
            except ValueError:
                try:
                    # Check if it's valid CIDR
                    ipaddress.ip_network(target, strict=False)
                    validated.append(target)
                except ValueError:
                    # Check if it's a valid hostname asynchronously
                    try:
                        # Use asyncio.get_event_loop().getaddrinfo for async DNS resolution
                        loop = asyncio.get_event_loop()
                        await loop.getaddrinfo(target, None)
                        validated.append(target)
                    except Exception:
                        raise HTTPException(
                            status_code=400,
                            detail=f"Invalid target: {target}. Must be IP, CIDR, or resolvable hostname."
                        )

        return validated

# Create service instance
security_scanner_service = SecurityScannerService()

# Export router for loading
router = security_scanner_service.router