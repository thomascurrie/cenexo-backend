"""
Enhanced database models for multi-tenant architecture.
Provides tenant isolation, user management, and service configuration.
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import uuid

Base = declarative_base()

# Pydantic models for API responses
class TenantBase(BaseModel):
    """Base tenant model"""
    name: str = Field(..., description="Tenant name", min_length=1, max_length=100)
    description: Optional[str] = Field(None, description="Tenant description", max_length=500)
    domain: Optional[str] = Field(None, description="Tenant domain", max_length=253)
    is_active: bool = Field(default=True, description="Whether tenant is active")
    max_users: int = Field(default=10, description="Maximum number of users", ge=1)
    max_services: int = Field(default=5, description="Maximum number of services", ge=1)

class UserBase(BaseModel):
    """Base user model"""
    username: str = Field(..., description="Username", min_length=3, max_length=50)
    email: str = Field(..., description="Email address")
    role: str = Field(default="user", description="User role")
    is_active: bool = Field(default=True, description="Whether user is active")

class ServiceBase(BaseModel):
    """Base service model"""
    name: str = Field(..., description="Service name", min_length=1, max_length=100)
    service_type: str = Field(..., description="Service type", min_length=1, max_length=50)
    description: Optional[str] = Field(None, description="Service description", max_length=500)
    version: str = Field(default="1.0.0", description="Service version")
    is_active: bool = Field(default=True, description="Whether service is active")

class ServiceConfigBase(BaseModel):
    """Base service configuration model"""
    config_key: str = Field(..., description="Configuration key", min_length=1, max_length=100)
    config_value: Dict[str, Any] = Field(..., description="Configuration value")
    is_encrypted: bool = Field(default=False, description="Whether value is encrypted")

# SQLAlchemy models
class Tenant(Base):
    """Tenant model for multi-tenant architecture"""
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(String(500))
    domain = Column(String(253), unique=True, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    max_users = Column(Integer, default=10, nullable=False)
    max_services = Column(Integer, default=5, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    services = relationship("Service", back_populates="tenant", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="tenant", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Tenant(id={self.id}, name='{self.name}', domain='{self.domain}')>"

class User(Base):
    """User model with tenant association"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    username = Column(String(50), index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    last_login = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")

    # Unique constraint: username must be unique within each tenant
    __table_args__ = (
        UniqueConstraint('tenant_id', 'username', name='unique_tenant_username'),
    )

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', tenant_id={self.tenant_id})>"

class Service(Base):
    """Service model for service registry"""
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(100), nullable=False)
    service_type = Column(String(50), nullable=False)
    description = Column(String(500))
    version = Column(String(20), default="1.0.0", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    service_endpoint = Column(String(500))  # API endpoint for the service
    config_schema = Column(JSON)  # JSON schema for service configuration
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    tenant = relationship("Tenant", back_populates="services")
    configurations = relationship("ServiceConfiguration", back_populates="service", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="service", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Service(id={self.id}, name='{self.name}', type='{self.service_type}')>"

class ServiceConfiguration(Base):
    """Service configuration model"""
    __tablename__ = "service_configurations"

    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(Integer, ForeignKey("services.id", ondelete="CASCADE"), nullable=False)
    config_key = Column(String(100), nullable=False)
    config_value = Column(JSON, nullable=False)
    is_encrypted = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    service = relationship("Service", back_populates="configurations")

    def __repr__(self):
        return f"<ServiceConfiguration(id={self.id}, service_id={self.service_id}, key='{self.config_key}')>"

class AuditLog(Base):
    """Audit log model for tracking all activities"""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    service_id = Column(Integer, ForeignKey("services.id", ondelete="SET NULL"))
    action = Column(String(100), nullable=False)  # e.g., 'CREATE', 'UPDATE', 'DELETE', 'LOGIN'
    resource_type = Column(String(50), nullable=False)  # e.g., 'user', 'service', 'tenant'
    resource_id = Column(String(100))  # ID of the affected resource
    details = Column(JSON)  # Additional details about the action
    ip_address = Column(String(45))  # IPv4 or IPv6 address
    user_agent = Column(String(500))
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    tenant = relationship("Tenant", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs")
    service = relationship("Service", back_populates="audit_logs")

    def __repr__(self):
        return f"<AuditLog(id={self.id}, action='{self.action}', resource_type='{self.resource_type}')>"

# Indexes for better performance
from sqlalchemy import Index
Index("idx_audit_logs_tenant_timestamp", AuditLog.tenant_id, AuditLog.timestamp)
Index("idx_audit_logs_user_timestamp", AuditLog.user_id, AuditLog.timestamp)
Index("idx_audit_logs_service_timestamp", AuditLog.service_id, AuditLog.timestamp)
Index("idx_service_configurations_service_key", ServiceConfiguration.service_id, ServiceConfiguration.config_key)