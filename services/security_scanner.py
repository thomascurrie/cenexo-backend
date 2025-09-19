"""
Security Scanner Service using NMAP.
Provides network scanning capabilities with JSON output.
"""

import nmap
import asyncio
import uuid
import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from fastapi import HTTPException, Depends
import ipaddress
import socket
from collections import OrderedDict

from .base import BaseService
from .models import (
    ScanRequest, ScanResult, ScanTarget, PortInfo,
    ErrorResponse, ServiceHealthResponse
)

logger = logging.getLogger(__name__)

class SecurityScannerService(BaseService):
    """
    Security scanner service that uses NMAP for network scanning.
    """

    def __init__(self):
        """Initialize the security scanner service."""
        super().__init__(
            service_name="security_scanner",
            description="Network security scanner using NMAP with JSON output"
        )

        # Initialize NMAP scanner
        self.nmap_scanner = nmap.PortScanner()

        # Scan cache with LRU eviction
        self.max_cache_size = 100
        self.cache_ttl = 3600  # 1 hour
        self.scan_cache: OrderedDict = OrderedDict()

        # Setup routes
        self.setup_routes()

    def _clean_expired_cache_entries(self):
        """Remove expired entries from cache"""
        current_time = time.time()
        expired_keys = []

        for scan_id, cache_data in self.scan_cache.items():
            if current_time - cache_data['timestamp'] > self.cache_ttl:
                expired_keys.append(scan_id)

        for key in expired_keys:
            del self.scan_cache[key]

    def _add_to_cache(self, scan_id: str, result: Dict[str, Any]):
        """Add result to cache with LRU eviction"""
        # Clean expired entries first
        self._clean_expired_cache_entries()

        # Check if we need to evict LRU entry
        if len(self.scan_cache) >= self.max_cache_size:
            # Remove oldest entry (first in OrderedDict)
            oldest_scan_id, _ = self.scan_cache.popitem(last=False)
            logger.info(f"Evicted cache entry: {oldest_scan_id}")

        # Add new entry
        self.scan_cache[scan_id] = {
            'result': result,
            'timestamp': time.time()
        }
        self.scan_cache.move_to_end(scan_id)  # Mark as most recently used

    async def _check_authorization(self):
        """Check if the scan request is authorized"""
        # For now, check environment variable
        # In production, this should check JWT tokens, API keys, etc.
        if os.getenv("SCAN_AUTHORIZATION_REQUIRED", "false").lower() == "true":
            # TODO: Implement proper authentication
            # For now, just log the authorization check
            logger.info("Authorization check passed (environment-based)")
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

    async def _check_rate_limit(self):
        """Check rate limiting for scan requests"""
        # TODO: Implement proper rate limiting with Redis
        # For now, just log the check
        logger.info("Rate limit check passed (not implemented)")

    async def _log_scan_request(self, scan_id: str, request: ScanRequest):
        """Log scan request for audit purposes"""
        if os.getenv("SCAN_AUDIT_LOG_ENABLED", "false").lower() == "true":
            logger.info(f"AUDIT: Scan {scan_id} requested for targets: {request.targets}")
        else:
            logger.info(f"Scan {scan_id} requested for targets: {request.targets}")

    def setup_routes(self):
        """Setup the security scanner routes."""

        @self.router.post("/scan", response_model=ScanResult)
        async def perform_scan(request: ScanRequest):
            """
            Perform a security scan on the specified targets.

            Args:
                request: ScanRequest containing targets and scan parameters

            Returns:
                ScanResult with scan findings
            """
            scan_id = str(uuid.uuid4())

            try:
                # Security checks
                await self._check_authorization()
                self._check_target_allowlist(request.targets)
                await self._check_rate_limit()

                logger.info(f"Starting authorized scan {scan_id} for targets: {request.targets}")

                # Validate targets
                validated_targets = await self._validate_targets(request.targets)

                # Audit logging
                await self._log_scan_request(scan_id, request)

                # Perform the scan
                start_time = time.time()
                scan_results = await self._perform_nmap_scan(
                    targets=validated_targets,
                    scan_type=request.scan_type,
                    ports=request.ports,
                    timeout=request.timeout
                )
                duration = time.time() - start_time

                # Build response
                result = ScanResult(
                    scan_id=scan_id,
                    targets=request.targets,
                    results=scan_results,
                    duration=duration,
                    status="completed"
                )

                # Cache the result
                self._add_to_cache(scan_id, result.dict())

                logger.info(f"Scan {scan_id} completed in {duration:.2f} seconds")
                return result

            except Exception as e:
                logger.error(f"Scan {scan_id} failed: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=ErrorResponse(
                        error="Scan failed",
                        error_code="SCAN_ERROR",
                        details={"scan_id": scan_id, "error": str(e)}
                    ).dict()
                )

        @self.router.get("/scan/{scan_id}", response_model=ScanResult)
        async def get_scan_result(scan_id: str):
            """
            Retrieve a previously completed scan result.

            Args:
                scan_id: Unique identifier of the scan

            Returns:
                ScanResult for the specified scan
            """
            # Clean expired entries first
            self._clean_expired_cache_entries()

            if scan_id in self.scan_cache:
                # Mark as recently used
                self.scan_cache.move_to_end(scan_id)
                cached_result = self.scan_cache[scan_id]["result"]
                return ScanResult(**cached_result)
            else:
                raise HTTPException(
                    status_code=404,
                    detail=ErrorResponse(
                        error="Scan not found",
                        error_code="SCAN_NOT_FOUND",
                        details={"scan_id": scan_id}
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
                    except socket.gaierror:
                        raise HTTPException(
                            status_code=400,
                            detail=f"Invalid target: {target}. Must be IP, CIDR, or resolvable hostname."
                        )

        return validated

    async def _perform_nmap_scan(
        self,
        targets: List[str],
        scan_type: str,
        ports: str,
        timeout: int
    ) -> Dict[str, ScanTarget]:
        """
        Perform NMAP scan on targets.

        Args:
            targets: List of validated targets
            scan_type: Type of scan to perform
            ports: Port specification
            timeout: Scan timeout

        Returns:
            Dictionary mapping targets to ScanTarget objects
        """
        results = {}

        # Configure scan arguments based on type
        scan_args = self._get_scan_arguments(scan_type, ports, timeout)

        # Run scan in a separate thread to avoid blocking
        loop = asyncio.get_event_loop()
        scan_result = await loop.run_in_executor(
            None,
            self._run_nmap_scan,
            targets,
            scan_args
        )

        # Process results
        for target in targets:
            if target in scan_result['scan']:
                host_data = scan_result['scan'][target]
                scan_target = self._parse_nmap_results(host_data)
                results[target] = scan_target
            else:
                # Target not found or unreachable
                results[target] = ScanTarget(
                    target=target,
                    ports=[]
                )

        return results

    def _validate_ports(self, ports: str) -> str:
        """
        Validate and sanitize ports parameter to prevent command injection.

        Args:
            ports: Port specification string

        Returns:
            Sanitized ports string

        Raises:
            HTTPException: If ports specification is invalid
        """
        if not ports or not ports.strip():
            raise HTTPException(
                status_code=400,
                detail="Ports specification cannot be empty"
            )

        # Remove any potentially dangerous characters
        ports = ports.strip()

        # Check for shell metacharacters and other dangerous patterns
        dangerous_patterns = [';', '&', '|', '$', '(', ')', '`', '\n', '\r', '\t']
        for pattern in dangerous_patterns:
            if pattern in ports:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid character '{pattern}' in ports specification"
                )

        # Validate port ranges and individual ports
        if ports == "all":
            return ports

        # Split by comma for individual ports or ranges
        port_specs = ports.split(',')

        for spec in port_specs:
            spec = spec.strip()
            if not spec:
                continue

            # Check for range notation (e.g., "1-1024")
            if '-' in spec:
                try:
                    start, end = spec.split('-', 1)
                    start_port = int(start.strip())
                    end_port = int(end.strip())

                    if start_port < 1 or start_port > 65535:
                        raise ValueError(f"Invalid start port: {start_port}")
                    if end_port < 1 or end_port > 65535:
                        raise ValueError(f"Invalid end port: {end_port}")
                    if start_port > end_port:
                        raise ValueError(f"Start port {start_port} > end port {end_port}")
                except ValueError as e:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid port range '{spec}': {str(e)}"
                    )
            else:
                # Single port
                try:
                    port_num = int(spec)
                    if port_num < 1 or port_num > 65535:
                        raise ValueError(f"Port out of range: {port_num}")
                except ValueError:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid port number '{spec}'"
                    )

        return ports

    def _get_scan_arguments(self, scan_type: str, ports: str, timeout: int) -> str:
        """
        Get NMAP arguments based on scan type.

        Args:
            scan_type: Type of scan
            ports: Port specification
            timeout: Scan timeout

        Returns:
            NMAP arguments string
        """
        # Validate ports first
        validated_ports = self._validate_ports(ports)

        base_args = f"-T3 --host-timeout {timeout}s"

        if scan_type == "basic":
            return f"{base_args} -sS -p {validated_ports}"
        elif scan_type == "comprehensive":
            return f"{base_args} -sS -sV -p {validated_ports} --script banner"
        elif scan_type == "custom":
            return f"{base_args} -sS -sV -p {validated_ports}"

        return f"{base_args} -sS -p {validated_ports}"

    def _run_nmap_scan(self, targets: List[str], arguments: str) -> Dict[str, Any]:
        """
        Run NMAP scan synchronously.

        Args:
            targets: List of targets to scan
            arguments: NMAP arguments

        Returns:
            NMAP scan results
        """
        try:
            # Join targets with spaces for NMAP
            target_string = " ".join(targets)

            # Perform the scan
            self.nmap_scanner.scan(target_string, arguments=arguments)

            # Use public API instead of private attribute
            return dict(self.nmap_scanner.get_nmap_last_output())
        except Exception as e:
            logger.error(f"NMAP scan failed: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"NMAP scan failed: {str(e)}"
            )

    def _parse_nmap_results(self, host_data: Dict[str, Any]) -> ScanTarget:
        """
        Parse NMAP results into ScanTarget object.

        Args:
            host_data: NMAP host data

        Returns:
            ScanTarget object
        """
        ports = []

        if 'tcp' in host_data:
            for port, port_data in host_data['tcp'].items():
                if port_data['state'] == 'open':
                    ports.append(PortInfo(
                        port=int(port),
                        state=port_data['state'],
                        service=port_data.get('name', 'unknown'),
                        version=port_data.get('version', ''),
                        protocol='tcp'
                    ))

        return ScanTarget(
            target=host_data.get('addresses', {}).get('ipv4', 'unknown'),
            ports=ports
        )

# Create service instance
security_scanner_service = SecurityScannerService()

# Export router for loading
router = security_scanner_service.router