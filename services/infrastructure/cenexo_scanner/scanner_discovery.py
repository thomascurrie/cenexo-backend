"""
Security Scanner Service - Cenexo Scanner Discovery
Enhanced security scanner with multi-tenant support and improved architecture.
"""

import asyncio
import logging
import socket
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from fastapi import HTTPException, Depends
import ipaddress
import os
from sqlalchemy.orm import Session

from ...database import get_db
from ...database_models import Tenant, User
from ...tenant_manager import get_current_tenant
from ...service_registry import BaseService
from ...models import (
    ScanRequest, ScanResult, ScanTarget, PortInfo,
    ErrorResponse, ServiceHealthResponse
)
from ...celery_app import celery_app
from ...tasks.security_tasks import perform_security_scan
from ...auth import get_current_user, require_user, require_admin, UserRole
from ...rate_limiter import rate_limiter
from ...security_logger import security_logger

logger = logging.getLogger(__name__)

class CenexoScannerService(BaseService):
    """
    Enhanced security scanner service with multi-tenant support.
    Provides network scanning capabilities with tenant isolation.
    """

    def __init__(self, tenant: Tenant, config: Optional[Dict] = None):
        """Initialize the Cenexo scanner service."""
        super().__init__(
            service_name="cenexo_scanner",
            service_type="security_scanner",
            tenant=tenant
        )

        # Service-specific configuration
        self.config.update(config or {})
        self.config.setdefault("scan_timeout", 300)
        self.config.setdefault("max_concurrent_scans", 3)
        self.config.setdefault("allowed_networks", "")

        # Setup routes
        self.setup_routes()

    async def _check_tenant_authorization(self, user: User) -> None:
        """Check if the scan request is authorized for this tenant"""
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Authentication required for scan operations"
            )

        # Check if user belongs to this tenant
        if user.tenant_id != self.tenant.id:
            raise HTTPException(
                status_code=403,
                detail="User does not have access to this tenant"
            )

        # Check if authorization is required
        if os.getenv("SCAN_AUTHORIZATION_REQUIRED", "true").lower() == "true":
            # Log successful authorization
            logger.info(f"Authorization check passed for user: {user.username} (role: {user.role}) in tenant: {self.tenant.name}")
        else:
            logger.info("Authorization check skipped (not required)")

    async def _check_target_allowlist(self, targets: List[str]) -> None:
        """Check if targets are in the allowed networks for this tenant"""
        allowed_networks = self.config.get("allowed_networks", "")
        if not allowed_networks:
            logger.warning(f"No network allowlist configured for tenant {self.tenant.name} - allowing all targets")
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
                        logger.warning(f"Invalid network in allowlist for tenant {self.tenant.name}: {net_str}")
            except ValueError:
                # Target is hostname, resolve to IP and check asynchronously
                try:
                    # Use asyncio.get_event_loop().getaddrinfo for async DNS resolution
                    loop = asyncio.get_event_loop()
                    addr_info = await loop.getaddrinfo(target, None)
                    if addr_info:
                        # Get the first IP address from the resolved addresses
                        resolved_ip = addr_info[0][4][0]
                        resolved_ip_obj = ipaddress.ip_address(resolved_ip)
                        for net_str in allowed_nets:
                            try:
                                net = ipaddress.ip_network(net_str.strip(), strict=False)
                                if resolved_ip_obj in net:
                                    target_allowed = True
                                    break
                            except ValueError:
                                logger.warning(f"Invalid network in allowlist for tenant {self.tenant.name}: {net_str}")
                except Exception:
                    logger.warning(f"Could not resolve hostname: {target}")
                    # If hostname cannot be resolved, deny access
                    target_allowed = False

            if not target_allowed:
                raise HTTPException(
                    status_code=403,
                    detail=f"Target {target} not in allowed networks for tenant {self.tenant.name}: {allowed_networks}"
                )

    async def _check_rate_limit(self, user: User) -> None:
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
                endpoint="scan",
                tenant_id=self.tenant.uuid
            )

            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Rate limit exceeded",
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "details": {
                        "retry_after": reset_time,
                        "message": "Too many scan requests. Please try again later.",
                        "tenant": self.tenant.name
                    }
                }
            )

        logger.info(f"Rate limit check passed for user {user.username} in tenant {self.tenant.name}. "
                    f"Remaining requests: {remaining if remaining is not None else 'unlimited'}")

    async def _log_scan_request(self, task_id: str, request: ScanRequest, user: User) -> None:
        """Log scan request for audit purposes"""
        # Use comprehensive security logging
        security_logger.log_scan_started(
            user=user,
            targets=request.targets,
            scan_type=request.scan_type,
            tenant_id=self.tenant.uuid
        )

        # Also log to regular logger for monitoring
        logger.info(
            f"Scan task {task_id} requested by user {user.username} (role: {user.role}) "
            f"in tenant {self.tenant.name} for {len(request.targets)} targets"
        )

    def setup_routes(self):
        """Setup the security scanner routes."""

        @self.router.post("/scan")
        async def start_scan(
            request: ScanRequest,
            user: User = Depends(require_user),
            db: Session = Depends(get_db)
        ):
            """
            Start a security scan task on the specified targets.

            Args:
                request: ScanRequest containing targets and scan parameters
                user: Authenticated user
                db: Database session

            Returns:
                Dictionary with task_id and status
            """
            try:
                # Security checks
                await self._check_tenant_authorization(user)
                await self._check_target_allowlist(request.targets)
                await self._check_rate_limit(user)

                # Validate targets
                validated_targets = await self._validate_targets(request.targets)

                logger.info(f"Starting scan task for targets: {request.targets} by user: {user.username} in tenant: {self.tenant.name}")

                # Prepare task data with tenant context
                task_data = {
                    'targets': validated_targets,
                    'scan_type': request.scan_type,
                    'ports': request.ports,
                    'timeout': request.timeout,
                    'user_id': user.username,
                    'user_role': user.role,
                    'tenant_id': self.tenant.uuid,
                    'tenant_name': self.tenant.name
                }

                # Trigger Celery task
                celery_task = perform_security_scan.delay(task_data)

                # Audit logging with actual task ID
                await self._log_scan_request(celery_task.id, request, user)

                logger.info(f"Scan task {celery_task.id} started for targets: {request.targets} by user: {user.username} in tenant: {self.tenant.name}")
                return {
                    "task_id": celery_task.id,
                    "status": "PENDING",
                    "message": "Scan task started successfully",
                    "tenant": self.tenant.name
                }

            except HTTPException:
                # Re-raise HTTP exceptions as-is
                raise
            except Exception as e:
                logger.error(f"Failed to start scan task in tenant {self.tenant.name}: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=ErrorResponse(
                        error="Failed to start scan task",
                        error_code="TASK_START_ERROR",
                        details={"error": str(e), "tenant": self.tenant.name}
                    ).dict()
                )

        @self.router.get("/scan/{task_id}")
        async def get_scan_result(
            task_id: str,
            user: User = Depends(require_user),
            db: Session = Depends(get_db)
        ):
            """
            Retrieve a scan result by task ID.

            Args:
                task_id: Unique identifier of the scan task
                user: Authenticated user
                db: Database session

            Returns:
                ScanResult for the specified task
            """
            try:
                # Verify user belongs to this tenant
                if user.tenant_id != self.tenant.id:
                    raise HTTPException(
                        status_code=403,
                        detail="Access denied to scan results from different tenant"
                    )

                # Get task result from Celery
                task = celery_app.AsyncResult(task_id)

                if task.state == 'PENDING':
                    raise HTTPException(
                        status_code=404,
                        detail=ErrorResponse(
                            error="Task not found or still pending",
                            error_code="TASK_NOT_FOUND",
                            details={"task_id": task_id, "status": task.state, "tenant": self.tenant.name}
                        ).dict()
                    )

                elif task.state == 'PROGRESS':
                    return {
                        "task_id": task_id,
                        "status": task.state,
                        "progress": task.info.get('status', 'Processing...') if task.info else 'Processing...',
                        "tenant": self.tenant.name
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
                            details={"task_id": task_id, "status": task.state, "tenant": self.tenant.name}
                        ).dict()
                    )

            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error retrieving task {task_id} in tenant {self.tenant.name}: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=ErrorResponse(
                        error="Failed to retrieve scan result",
                        error_code="RESULT_RETRIEVAL_ERROR",
                        details={"task_id": task_id, "error": str(e), "tenant": self.tenant.name}
                    ).dict()
                )

        @self.router.get("/tasks/{task_id}/status")
        async def get_task_status(
            task_id: str,
            user: User = Depends(require_user),
            db: Session = Depends(get_db)
        ):
            """
            Get the status of a scan task.

            Args:
                task_id: Unique identifier of the scan task
                user: Authenticated user
                db: Database session

            Returns:
                Dictionary with task status information
            """
            try:
                # Verify user belongs to this tenant
                if user.tenant_id != self.tenant.id:
                    raise HTTPException(
                        status_code=403,
                        detail="Access denied to task status from different tenant"
                    )

                task = celery_app.AsyncResult(task_id)
                return {
                    "task_id": task_id,
                    "status": task.state,
                    "progress": task.info.get('status') if task.info and isinstance(task.info, dict) else None,
                    "result": task.result if task.state == 'SUCCESS' else None,
                    "tenant": self.tenant.name
                }
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=ErrorResponse(
                        error="Failed to get task status",
                        error_code="STATUS_CHECK_ERROR",
                        details={"task_id": task_id, "error": str(e), "tenant": self.tenant.name}
                    ).dict()
                )

        @self.router.get("/health", response_model=ServiceHealthResponse)
        async def health_check():
            """Service-specific health check."""
            return ServiceHealthResponse(
                service=self.service_name,
                status="healthy",
                timestamp=datetime.utcnow().isoformat() + "Z",
                version=self.config.get("version", "1.0.0"),
                details={
                    "tenant": self.tenant.name,
                    "tenant_id": self.tenant.uuid,
                    "config": {
                        "scan_timeout": self.config.get("scan_timeout"),
                        "max_concurrent_scans": self.config.get("max_concurrent_scans")
                    }
                }
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

    def get_service_description(self) -> str:
        """Get service description"""
        return f"Cenexo Security Scanner service for tenant {self.tenant.name} - Enhanced network security scanning with multi-tenant support"