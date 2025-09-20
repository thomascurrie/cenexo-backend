"""
Pydantic models for the services.
Defines request and response schemas for all services.
"""

from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timezone
import ipaddress
import re

class PortInfo(BaseModel):
    """Information about a single port"""
    port: int = Field(..., description="Port number", ge=1, le=65535)
    state: str = Field(..., description="Port state (open, closed, filtered)")
    service: str = Field(..., description="Service name")
    version: Optional[str] = Field(None, description="Service version")
    protocol: str = Field(default="tcp", description="Protocol (tcp/udp)")

    @validator('state')
    def validate_state(cls, v):
        """Validate port state"""
        valid_states = ['open', 'closed', 'filtered', 'open|filtered', 'closed|filtered']
        if v not in valid_states:
            raise ValueError(f'Port state must be one of: {valid_states}')
        return v

    @validator('protocol')
    def validate_protocol(cls, v):
        """Validate protocol"""
        valid_protocols = ['tcp', 'udp']
        if v not in valid_protocols:
            raise ValueError(f'Protocol must be one of: {valid_protocols}')
        return v

class ScanTarget(BaseModel):
    """Target information for scanning"""
    target: str = Field(..., description="IP address, CIDR, or hostname")
    ports: List[PortInfo] = Field(default_factory=list, description="Open ports found")

    @validator('target')
    def validate_target(cls, v):
        """Validate IP address, CIDR notation, or hostname"""
        # Check if it's a valid IP address
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass

        # Check if it's valid CIDR notation
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError:
            pass

        # Check if it's a valid hostname
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', v):
            return v

        raise ValueError('Target must be a valid IP address, CIDR notation, or hostname')

class ScanResult(BaseModel):
    """Result of a scan operation"""
    scan_id: str = Field(..., description="Unique scan identifier")
    targets: List[str] = Field(..., description="List of scan targets")
    results: Dict[str, ScanTarget] = Field(..., description="Scan results per target")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Scan completion time")
    duration: float = Field(..., description="Scan duration in seconds")
    status: str = Field(..., description="Scan status (completed, failed, partial)")

    @validator('status')
    def validate_status(cls, v):
        """Validate scan status"""
        valid_statuses = ['completed', 'failed', 'partial']
        if v not in valid_statuses:
            raise ValueError(f'Scan status must be one of: {valid_statuses}')
        return v

class ScanRequest(BaseModel):
    """Request for a security scan"""
    targets: List[str] = Field(..., min_items=1, description="List of targets to scan (IPs, CIDRs, or hostnames)")
    scan_type: str = Field(
        default="comprehensive",
        description="Type of scan to perform",
        pattern="^(basic|comprehensive|custom)$"
    )
    ports: str = Field(
        default="1-1024",
        description="Port range to scan (e.g., '1-1024', '80,443', 'all')"
    )
    timeout: int = Field(
        default=300,
        description="Scan timeout in seconds",
        ge=30,
        le=3600
    )
    intensity: int = Field(
        default=3,
        description="Scan intensity (1-5)",
        ge=1,
        le=5
    )

    @validator('targets')
    def validate_targets_list(cls, v):
        """Validate all targets in the list"""
        if not v:
            raise ValueError('At least one target is required')

        for target in v:
            # Use the same validation as ScanTarget
            try:
                ScanTarget(target=target)
            except ValueError as e:
                raise ValueError(f'Invalid target "{target}": {str(e)}')

        return v

class ErrorResponse(BaseModel):
    """Error response model"""
    error: str = Field(..., description="Error message")
    error_code: str = Field(..., description="Error code")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Error timestamp")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")

class ServiceHealthResponse(BaseModel):
    """Service health check response"""
    service: str = Field(..., description="Service name")
    status: str = Field(..., description="Service status")
    timestamp: str = Field(..., description="Health check timestamp")
    version: str = Field(default="1.0.0", description="Service version")