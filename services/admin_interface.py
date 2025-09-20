"""
Admin interface for tenant and service management.
Provides comprehensive administrative capabilities for the Cenexo Unified Platform.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import logging

from .database import get_db
from .database_models import Tenant, User, Service, ServiceConfiguration, AuditLog
from .tenant_manager import tenant_manager, get_current_tenant, require_admin_tenant
from .auth import get_current_user, require_admin
from .enhanced_logging import enhanced_logger

logger = logging.getLogger(__name__)

def create_admin_router():
    """Create admin interface router"""
    router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

    @router.get("/tenants")
    async def list_tenants(
        skip: int = 0,
        limit: int = 100,
        include_inactive: bool = False,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin)
    ):
        """List all tenants"""
        query = db.query(Tenant)
        if not include_inactive:
            query = query.filter(Tenant.is_active == True)

        tenants = query.offset(skip).limit(limit).all()

        return {
            "tenants": [
                {
                    "id": tenant.uuid,
                    "name": tenant.name,
                    "domain": tenant.domain,
                    "is_active": tenant.is_active,
                    "max_users": tenant.max_users,
                    "max_services": tenant.max_services,
                    "created_at": tenant.created_at.isoformat(),
                    "updated_at": tenant.updated_at.isoformat(),
                    "user_count": len(tenant.users),
                    "service_count": len(tenant.services)
                }
                for tenant in tenants
            ],
            "total": query.count(),
            "skip": skip,
            "limit": limit
        }

    @router.post("/tenants")
    async def create_tenant(
        tenant_data: dict,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin)
    ):
        """Create a new tenant"""
        try:
            tenant = tenant_manager.create_tenant(
                db=db,
                name=tenant_data["name"],
                domain=tenant_data.get("domain"),
                description=tenant_data.get("description")
            )

            # Create default admin user for the tenant
            from .auth import get_password_hash
            admin_user = User(
                tenant_id=tenant.id,
                username=f"admin_{tenant.name}",
                email=tenant_data.get("admin_email", f"admin@{tenant.domain or 'localhost'}"),
                hashed_password=get_password_hash(tenant_data.get("admin_password", "admin123")),
                role="admin",
                is_active=True
            )
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)

            # Log tenant creation
            enhanced_logger.log_tenant_created(tenant, current_user)

            return {
                "message": "Tenant created successfully",
                "tenant": {
                    "id": tenant.uuid,
                    "name": tenant.name,
                    "domain": tenant.domain
                },
                "admin_user": {
                    "id": admin_user.uuid,
                    "username": admin_user.username,
                    "email": admin_user.email
                }
            }

        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=400, detail=str(e))

    @router.get("/tenants/{tenant_id}")
    async def get_tenant(
        tenant_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin)
    ):
        """Get tenant details"""
        tenant = db.query(Tenant).filter(Tenant.uuid == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        return {
            "id": tenant.uuid,
            "name": tenant.name,
            "domain": tenant.domain,
            "description": tenant.description,
            "is_active": tenant.is_active,
            "max_users": tenant.max_users,
            "max_services": tenant.max_services,
            "created_at": tenant.created_at.isoformat(),
            "updated_at": tenant.updated_at.isoformat(),
            "user_count": len(tenant.users),
            "service_count": len(tenant.services)
        }

    @router.put("/tenants/{tenant_id}")
    async def update_tenant(
        tenant_id: str,
        updates: dict,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin)
    ):
        """Update tenant"""
        try:
            tenant = tenant_manager.update_tenant(db, tenant_id, updates)

            return {
                "message": "Tenant updated successfully",
                "tenant": {
                    "id": tenant.uuid,
                    "name": tenant.name,
                    "domain": tenant.domain,
                    "is_active": tenant.is_active
                }
            }

        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=400, detail=str(e))

    @router.delete("/tenants/{tenant_id}")
    async def deactivate_tenant(
        tenant_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin)
    ):
        """Deactivate tenant"""
        try:
            tenant = tenant_manager.deactivate_tenant(db, tenant_id)

            return {
                "message": "Tenant deactivated successfully",
                "tenant": {
                    "id": tenant.uuid,
                    "name": tenant.name,
                    "is_active": tenant.is_active
                }
            }

        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=400, detail=str(e))

    @router.get("/users")
    async def list_users(
        tenant_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin)
    ):
        """List users across all tenants or specific tenant"""
        query = db.query(User)

        if tenant_id:
            tenant = db.query(Tenant).filter(Tenant.uuid == tenant_id).first()
            if not tenant:
                raise HTTPException(status_code=404, detail="Tenant not found")
            query = query.filter(User.tenant_id == tenant.id)

        users = query.offset(skip).limit(limit).all()

        return {
            "users": [
                {
                    "id": user.uuid,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role,
                    "is_active": user.is_active,
                    "tenant_id": user.tenant.uuid,
                    "tenant_name": user.tenant.name,
                    "last_login": user.last_login.isoformat() if user.last_login else None,
                    "created_at": user.created_at.isoformat()
                }
                for user in users
            ],
            "total": query.count(),
            "skip": skip,
            "limit": limit
        }

    @router.get("/services")
    async def list_services(
        tenant_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin)
    ):
        """List services across all tenants or specific tenant"""
        query = db.query(Service)

        if tenant_id:
            tenant = db.query(Tenant).filter(Tenant.uuid == tenant_id).first()
            if not tenant:
                raise HTTPException(status_code=404, detail="Tenant not found")
            query = query.filter(Service.tenant_id == tenant.id)

        services = query.offset(skip).limit(limit).all()

        return {
            "services": [
                {
                    "id": service.uuid,
                    "name": service.name,
                    "service_type": service.service_type,
                    "description": service.description,
                    "version": service.version,
                    "is_active": service.is_active,
                    "tenant_id": service.tenant.uuid,
                    "tenant_name": service.tenant.name,
                    "created_at": service.created_at.isoformat(),
                    "config_count": len(service.configurations)
                }
                for service in services
            ],
            "total": query.count(),
            "skip": skip,
            "limit": limit
        }

    @router.get("/audit-logs")
    async def get_audit_logs(
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin)
    ):
        """Get audit logs with filtering"""
        query = db.query(AuditLog)

        if tenant_id:
            tenant = db.query(Tenant).filter(Tenant.uuid == tenant_id).first()
            if not tenant:
                raise HTTPException(status_code=404, detail="Tenant not found")
            query = query.filter(AuditLog.tenant_id == tenant.id)

        if user_id:
            user = db.query(User).filter(User.uuid == user_id).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            query = query.filter(AuditLog.user_id == user.id)

        if action:
            query = query.filter(AuditLog.action == action)

        if resource_type:
            query = query.filter(AuditLog.resource_type == resource_type)

        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)

        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)

        audit_logs = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()

        return {
            "audit_logs": [
                {
                    "id": log.uuid,
                    "action": log.action,
                    "resource_type": log.resource_type,
                    "resource_id": log.resource_id,
                    "details": log.details,
                    "ip_address": log.ip_address,
                    "user_agent": log.user_agent,
                    "timestamp": log.timestamp.isoformat(),
                    "tenant": log.tenant.name if log.tenant else None,
                    "user": log.user.username if log.user else None
                }
                for log in audit_logs
            ],
            "total": query.count(),
            "skip": skip,
            "limit": limit
        }

    @router.get("/platform/stats")
    async def get_platform_stats(
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin)
    ):
        """Get platform statistics"""
        total_tenants = db.query(Tenant).filter(Tenant.is_active == True).count()
        total_users = db.query(User).filter(User.is_active == True).count()
        total_services = db.query(Service).filter(Service.is_active == True).count()
        total_audit_logs = db.query(AuditLog).count()

        # Get recent activity
        recent_logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(10).all()

        return {
            "summary": {
                "total_tenants": total_tenants,
                "total_users": total_users,
                "total_services": total_services,
                "total_audit_logs": total_audit_logs
            },
            "recent_activity": [
                {
                    "id": log.uuid,
                    "action": log.action,
                    "resource_type": log.resource_type,
                    "timestamp": log.timestamp.isoformat(),
                    "tenant": log.tenant.name if log.tenant else None,
                    "user": log.user.username if log.user else None
                }
                for log in recent_logs
            ],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    @router.get("/health")
    async def admin_health_check(
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin)
    ):
        """Admin health check with detailed information"""
        from .monitoring import perform_health_checks

        health_status = perform_health_checks()

        return {
            "status": "healthy",
            "admin_access": True,
            "user": current_user.username,
            "tenant": current_user.tenant.name,
            "health_checks": health_status,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    return router