"""
Configuration management for Cenexo Scanner Service.
Handles service-specific configuration and validation.
"""

import os
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, validator
import logging

logger = logging.getLogger(__name__)

class ScannerConfig(BaseModel):
    """Configuration model for Cenexo Scanner Service"""

    # Scan configuration
    scan_timeout: int = Field(default=300, description="Scan timeout in seconds", ge=30, le=3600)
    max_concurrent_scans: int = Field(default=3, description="Maximum concurrent scans", ge=1, le=10)
    allowed_networks: str = Field(default="", description="Allowed network ranges (comma-separated)")

    # NMAP configuration
    nmap_timeout: int = Field(default=300, description="NMAP scan timeout in seconds", ge=30, le=3600)
    nmap_scan_intensity: int = Field(default=1, description="Scan intensity (1-5)", ge=1, le=5)
    nmap_max_targets: int = Field(default=10, description="Maximum targets per scan", ge=1, le=100)

    # Redis configuration
    redis_url: str = Field(default="redis://localhost:6379/0", description="Redis URL for caching")
    scan_cache_ttl: int = Field(default=3600, description="Cache TTL in seconds", ge=60, le=86400)

    # Security controls
    scan_authorization_required: bool = Field(default=True, description="Require authorization for scanning")
    scan_audit_log_enabled: bool = Field(default=True, description="Enable audit logging for scans")
    scan_max_concurrent_scans: int = Field(default=3, description="Maximum concurrent scans allowed", ge=1, le=20)
    scan_max_duration: int = Field(default=600, description="Maximum scan duration in seconds", ge=60, le=3600)

    # Service configuration
    service_version: str = Field(default="1.0.0", description="Service version")
    service_enabled: bool = Field(default=True, description="Whether service is enabled")

    @validator('allowed_networks')
    def validate_allowed_networks(cls, v):
        """Validate allowed networks format"""
        if not v:
            return v

        networks = v.split(',')
        for network in networks:
            network = network.strip()
            if network:
                try:
                    # Validate CIDR notation
                    import ipaddress
                    ipaddress.ip_network(network, strict=False)
                except ValueError:
                    raise ValueError(f"Invalid network format: {network}")

        return v

class ConfigManager:
    """Manages configuration for Cenexo Scanner Service"""

    def __init__(self):
        self.config: ScannerConfig = ScannerConfig()
        self._load_from_environment()

    def _load_from_environment(self):
        """Load configuration from environment variables"""
        # Scan configuration
        if os.getenv("NMAP_TIMEOUT"):
            self.config.scan_timeout = int(os.getenv("NMAP_TIMEOUT"))
        if os.getenv("NMAP_SCAN_INTENSITY"):
            self.config.nmap_scan_intensity = int(os.getenv("NMAP_SCAN_INTENSITY"))
        if os.getenv("NMAP_MAX_TARGETS"):
            self.config.nmap_max_targets = int(os.getenv("NMAP_MAX_TARGETS"))

        # Redis configuration
        if os.getenv("REDIS_URL"):
            self.config.redis_url = os.getenv("REDIS_URL")
        if os.getenv("SCAN_CACHE_TTL"):
            self.config.scan_cache_ttl = int(os.getenv("SCAN_CACHE_TTL"))

        # Security controls
        if os.getenv("ALLOWED_SCAN_NETWORKS"):
            self.config.allowed_networks = os.getenv("ALLOWED_SCAN_NETWORKS")
        if os.getenv("SCAN_AUTHORIZATION_REQUIRED"):
            self.config.scan_authorization_required = os.getenv("SCAN_AUTHORIZATION_REQUIRED").lower() == "true"
        if os.getenv("SCAN_AUDIT_LOG_ENABLED"):
            self.config.scan_audit_log_enabled = os.getenv("SCAN_AUDIT_LOG_ENABLED").lower() == "true"
        if os.getenv("SCAN_MAX_CONCURRENT_SCANS"):
            self.config.scan_max_concurrent_scans = int(os.getenv("SCAN_MAX_CONCURRENT_SCANS"))
        if os.getenv("SCAN_MAX_DURATION"):
            self.config.scan_max_duration = int(os.getenv("SCAN_MAX_DURATION"))

        # Service configuration
        if os.getenv("CENEXO_SCANNER_VERSION"):
            self.config.service_version = os.getenv("CENEXO_SCANNER_VERSION")
        if os.getenv("CENEXO_SCANNER_ENABLED"):
            self.config.service_enabled = os.getenv("CENEXO_SCANNER_ENABLED").lower() == "true"

        logger.info("Loaded Cenexo Scanner configuration from environment")

    def get_config(self) -> ScannerConfig:
        """Get current configuration"""
        return self.config

    def get_config_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary"""
        return self.config.dict()

    def update_config(self, updates: Dict[str, Any]):
        """Update configuration with new values"""
        for key, value in updates.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)

        logger.info(f"Updated Cenexo Scanner configuration: {updates}")

    def validate_config(self) -> List[str]:
        """Validate current configuration and return list of issues"""
        issues = []

        # Validate scan timeout
        if self.config.scan_timeout < 30:
            issues.append("Scan timeout must be at least 30 seconds")
        if self.config.scan_timeout > 3600:
            issues.append("Scan timeout cannot exceed 3600 seconds")

        # Validate max concurrent scans
        if self.config.max_concurrent_scans < 1:
            issues.append("Max concurrent scans must be at least 1")
        if self.config.max_concurrent_scans > 10:
            issues.append("Max concurrent scans cannot exceed 10")

        # Validate allowed networks format
        if self.config.allowed_networks:
            try:
                networks = self.config.allowed_networks.split(',')
                for network in networks:
                    network = network.strip()
                    if network:
                        import ipaddress
                        ipaddress.ip_network(network, strict=False)
            except ValueError as e:
                issues.append(f"Invalid network format in allowed_networks: {e}")

        return issues

    def is_healthy(self) -> bool:
        """Check if configuration is healthy"""
        issues = self.validate_config()
        return len(issues) == 0

# Global configuration manager
config_manager = ConfigManager()

def get_scanner_config() -> ScannerConfig:
    """Get scanner configuration"""
    return config_manager.get_config()

def get_scanner_config_dict() -> Dict[str, Any]:
    """Get scanner configuration as dictionary"""
    return config_manager.get_config_dict()

def update_scanner_config(updates: Dict[str, Any]):
    """Update scanner configuration"""
    config_manager.update_config(updates)

def validate_scanner_config() -> List[str]:
    """Validate scanner configuration"""
    return config_manager.validate_config()

def is_scanner_config_healthy() -> bool:
    """Check if scanner configuration is healthy"""
    return config_manager.is_healthy()