"""
Tenant management system for multi-tenant architecture.
Provides tenant isolation, context management, and tenant-specific operations.
"""

import logging
from typing import Optional, List
from fastapi import Request, HTTPException, Depends
from sqlalchemy.orm import Session
from .database import get_db, get_tenant_context, TenantContext
from .database_models import Tenant, User, AuditLog
import os

logger = logging.getLogger(__name__)

class TenantManager:
    """Manages tenant operations and isolation"""

    def __init__(self):
        self.default_tenant_domain = os.getenv("DEFAULT_TENANT_DOMAIN", "localhost")
        self.require_tenant_header = os.getenv("REQUIRE_TENANT_HEADER", "true").lower() == "true"
        self.tenant_header_name = os.getenv("TENANT_HEADER_NAME", "X-Tenant-ID")

    def extract_tenant_from_request(self, request: Request) -> Optional[str]:
        """Extract tenant identifier from request headers or subdomain"""
        # Try header first
        tenant_id = request.headers.get(self.tenant_header_name)

        if tenant_id:
            logger.info(f"Extracted tenant ID from header: {tenant_id}")
            return tenant_id

        # Try subdomain
        host = request.headers.get("host", "")
        if "." in host:
            subdomain = host.split(".")[0]
            if subdomain and subdomain != "www":
                logger.info(f"Extracted tenant from subdomain: {subdomain}")
                return subdomain

        return None

    def get_tenant_for_request(self, db: Session, request: Request) -> Optional[Tenant]:
        """Get tenant for the current request"""
        tenant_id = self.extract_tenant_from_request(request)

        if not tenant_id:
            if self.require_tenant_header:
                logger.warning("No tenant identifier found in request")
                return None
            else:
                # Use default tenant
                tenant_id = "default"

        # Look up tenant in database
        tenant = db.query(Tenant).filter(
            (Tenant.uuid == tenant_id) |
            (Tenant.domain == tenant_id) |
            (Tenant.name == tenant_id)
        ).first()

        if tenant and tenant.is_active:
            logger.info(f"Found active tenant: {tenant.name} (ID: {tenant.uuid})")
            return tenant
        else:
            logger.warning(f"Tenant not found or inactive: {tenant_id}")
            return None

    def validate_tenant_access(self, tenant: Tenant, user: Optional[User] = None) -> bool:
        """Validate if user has access to tenant"""
        if not tenant.is_active:
            return False

        # Additional validation logic can be added here
        # For example, checking user permissions, tenant limits, etc.

        return True

    def create_tenant(self, db: Session, name: str, domain: Optional[str] = None,
                     description: Optional[str] = None) -> Tenant:
        """Create a new tenant"""
        # Check if tenant name already exists
        existing_tenant = db.query(Tenant).filter(Tenant.name == name).first()
        if existing_tenant:
            raise HTTPException(
                status_code=400,
                detail=f"Tenant with name '{name}' already exists"
            )

        # Check domain uniqueness if provided
        if domain:
            existing_domain = db.query(Tenant).filter(Tenant.domain == domain).first()
            if existing_domain:
                raise HTTPException(
                    status_code=400,
                    detail=f"Tenant with domain '{domain}' already exists"
                )

        tenant = Tenant(
            name=name,
            domain=domain,
            description=description,
            is_active=True
        )

        db.add(tenant)
        db.commit()
        db.refresh(tenant)

        # Log tenant creation
        self._log_audit_event(
            db=db,
            tenant=tenant,
            action="CREATE",
            resource_type="tenant",
            resource_id=tenant.uuid,
            details={"name": name, "domain": domain}
        )

        logger.info(f"Created new tenant: {tenant.name} (ID: {tenant.uuid})")
        return tenant

    def update_tenant(self, db: Session, tenant_id: str, updates: dict) -> Tenant:
        """Update tenant information"""
        tenant = db.query(Tenant).filter(Tenant.uuid == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        # Validate updates
        if "name" in updates:
            existing = db.query(Tenant).filter(
                Tenant.name == updates["name"],
                Tenant.id != tenant.id
            ).first()
            if existing:
                raise HTTPException(
                    status_code=400,
                    detail=f"Tenant with name '{updates['name']}' already exists"
                )

        if "domain" in updates and updates["domain"]:
            existing = db.query(Tenant).filter(
                Tenant.domain == updates["domain"],
                Tenant.id != tenant.id
            ).first()
            if existing:
                raise HTTPException(
                    status_code=400,
                    detail=f"Tenant with domain '{updates['domain']}' already exists"
                )

        # Apply updates
        for key, value in updates.items():
            if hasattr(tenant, key):
                setattr(tenant, key, value)

        db.commit()
        db.refresh(tenant)

        # Log tenant update
        self._log_audit_event(
            db=db,
            tenant=tenant,
            action="UPDATE",
            resource_type="tenant",
            resource_id=tenant.uuid,
            details=updates
        )

        logger.info(f"Updated tenant: {tenant.name} (ID: {tenant.uuid})")
        return tenant

    def deactivate_tenant(self, db: Session, tenant_id: str) -> Tenant:
        """Deactivate a tenant"""
        tenant = db.query(Tenant).filter(Tenant.uuid == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        tenant.is_active = False
        db.commit()
        db.refresh(tenant)

        # Log tenant deactivation
        self._log_audit_event(
            db=db,
            tenant=tenant,
            action="DEACTIVATE",
            resource_type="tenant",
            resource_id=tenant.uuid,
            details={"reason": "admin_deactivation"}
        )

        logger.info(f"Deactivated tenant: {tenant.name} (ID: {tenant.uuid})")
        return tenant

    def get_tenant_users(self, db: Session, tenant_id: str) -> List[User]:
        """Get all users for a tenant"""
        tenant = db.query(Tenant).filter(Tenant.uuid == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        return tenant.users

    def get_tenant_services(self, db: Session, tenant_id: str):
        """Get all services for a tenant"""
        tenant = db.query(Tenant).filter(Tenant.uuid == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        return tenant.services

    def _log_audit_event(self, db: Session, tenant: Optional[Tenant] = None,
                        user: Optional[User] = None, action: str = "UNKNOWN",
                        resource_type: str = "unknown", resource_id: str = "",
                        details: dict = None):
        """Log audit event"""
        audit_log = AuditLog(
            tenant_id=tenant.id if tenant else None,
            user_id=user.id if user else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {}
        )

        db.add(audit_log)
        db.commit()

# Global tenant manager instance
tenant_manager = TenantManager()

# FastAPI dependencies
def get_current_tenant(request: Request, db: Session = Depends(get_db)) -> Tenant:
    """Get current tenant from request context"""
    tenant = tenant_manager.get_tenant_for_request(db, request)
    if not tenant:
        raise HTTPException(
            status_code=400,
            detail="Valid tenant required"
        )

    # Validate tenant access
    if not tenant_manager.validate_tenant_access(tenant):
        raise HTTPException(
            status_code=403,
            detail="Tenant access denied"
        )

    return tenant

def get_optional_tenant(request: Request, db: Session = Depends(get_db)) -> Optional[Tenant]:
    """Get current tenant from request context (optional)"""
    return tenant_manager.get_tenant_for_request(db, request)

def require_admin_tenant():
    """Require admin tenant context"""
    def check_admin_tenant(tenant: Tenant = Depends(get_current_tenant)):
        if tenant.name != "admin":
            raise HTTPException(
                status_code=403,
                detail="Admin tenant required"
            )
        return tenant
    return check_admin_tenant

# Middleware for tenant context
class TenantMiddleware:
    """Middleware to set tenant context for each request"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract tenant from request
        request = Request(scope, receive)

        # Set tenant context in request state
        # This will be used by the dependency injection
        scope["state"] = scope.get("state", {})
        scope["state"]["tenant_manager"] = tenant_manager

        await self.app(scope, receive, send)