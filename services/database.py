"""
Database configuration and connection management for multi-tenant architecture.
Provides SQLAlchemy engine, session management, and tenant context isolation.
"""

import logging
from typing import Optional, Generator
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from fastapi import Request, HTTPException
import os
from .database_models import Base, Tenant, User

logger = logging.getLogger(__name__)

class DatabaseConfig:
    """Database configuration management"""

    def __init__(self):
        self.environment = os.getenv("ENVIRONMENT", "development")

        # Choose database based on environment
        if self.environment == "development":
            # Use SQLite for development
            self.database_url = os.getenv(
                "DATABASE_URL",
                "sqlite:///./cenexo_platform.db"
            )
            self.test_database_url = os.getenv(
                "TEST_DATABASE_URL",
                "sqlite:///./cenexo_test.db"
            )
            # SQLite doesn't need connection pooling
            self.pool_size = None
            self.max_overflow = None
            self.pool_timeout = None
            self.pool_recycle = None
        else:
            # Use PostgreSQL for production
            self.database_url = os.getenv(
                "DATABASE_URL",
                "postgresql://localhost:5432/cenexo_platform"
            )
            self.test_database_url = os.getenv(
                "TEST_DATABASE_URL",
                "postgresql://localhost:5432/cenexo_test"
            )
            self.pool_size = int(os.getenv("DB_POOL_SIZE", "10"))
            self.max_overflow = int(os.getenv("DB_MAX_OVERFLOW", "20"))
            self.pool_timeout = int(os.getenv("DB_POOL_TIMEOUT", "30"))
            self.pool_recycle = int(os.getenv("DB_POOL_RECYCLE", "3600"))

    def get_engine_config(self, test_mode: bool = False):
        """Get database engine configuration"""
        url = self.test_database_url if test_mode else self.database_url

        # Base configuration
        config = {
            "url": url,
            "echo": os.getenv("DB_ECHO", "false").lower() == "true"
        }

        # Add connection pooling for PostgreSQL only
        if self.environment != "development":
            config.update({
                "pool_size": self.pool_size,
                "max_overflow": self.max_overflow,
                "pool_timeout": self.pool_timeout,
                "pool_recycle": self.pool_recycle,
                "pool_pre_ping": True  # Validate connections before use
            })
        else:
            # SQLite-specific configuration
            config.update({
                "connect_args": {"check_same_thread": False},  # Allow multi-threading
                "poolclass": StaticPool  # SQLite works best with StaticPool
            })

        return config

# Global database configuration
db_config = DatabaseConfig()

# Create engines for different tenants
engines = {}
SessionLocal = None

def create_database_engine(tenant_id: Optional[str] = None, test_mode: bool = False):
    """Create database engine for tenant or default"""
    config = db_config.get_engine_config(test_mode)

    # Use tenant-specific database if tenant_id provided
    if tenant_id:
        # In a real implementation, you might have tenant-specific databases
        # For now, we'll use schema-based multi-tenancy
        config["url"] = config["url"].replace("cenexo_platform", f"cenexo_tenant_{tenant_id}")

    # Create engine key for caching
    engine_key = f"tenant_{tenant_id}" if tenant_id else "default"

    if engine_key not in engines:
        engines[engine_key] = create_engine(**config)
        logger.info(f"Created database engine for {engine_key}")

    return engines[engine_key]

def get_database_engine(tenant_id: Optional[str] = None):
    """Get database engine for tenant"""
    engine_key = f"tenant_{tenant_id}" if tenant_id else "default"
    if engine_key not in engines:
        create_database_engine(tenant_id)
    return engines[engine_key]

def init_database(test_mode: bool = False):
    """Initialize database and create tables"""
    global SessionLocal

    engine = create_database_engine(test_mode=test_mode)

    # Create all tables
    Base.metadata.create_all(bind=engine)

    # Create session factory
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    logger.info("Database initialized successfully")

def get_db() -> Generator[Session, None, None]:
    """Get database session"""
    if SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Tenant context management
class TenantContext:
    """Tenant context manager for request isolation"""

    def __init__(self):
        self.current_tenant: Optional[Tenant] = None
        self.current_user: Optional[User] = None

    def set_tenant(self, tenant: Tenant):
        """Set current tenant context"""
        self.current_tenant = tenant
        logger.info(f"Tenant context set to: {tenant.name} (ID: {tenant.id})")

    def set_user(self, user: User):
        """Set current user context"""
        self.current_user = user
        logger.info(f"User context set to: {user.username} (ID: {user.id})")

    def clear_context(self):
        """Clear tenant and user context"""
        self.current_tenant = None
        self.current_user = None
        logger.info("Tenant context cleared")

    def get_tenant_id(self) -> Optional[int]:
        """Get current tenant ID"""
        return self.current_tenant.id if self.current_tenant else None

    def get_user_id(self) -> Optional[int]:
        """Get current user ID"""
        return self.current_user.id if self.current_user else None

    def require_tenant(self) -> Tenant:
        """Get current tenant or raise exception"""
        if not self.current_tenant:
            raise HTTPException(
                status_code=400,
                detail="Tenant context not set"
            )
        return self.current_tenant

    def require_user(self) -> User:
        """Get current user or raise exception"""
        if not self.current_user:
            raise HTTPException(
                status_code=401,
                detail="User context not set"
            )
        return self.current_user

# Global tenant context
tenant_context = TenantContext()

def get_tenant_context() -> TenantContext:
    """Get global tenant context"""
    return tenant_context

# Database session with tenant context
@contextmanager
def get_tenant_db_session(tenant_id: Optional[str] = None):
    """Get database session with tenant context"""
    if SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")

    db = SessionLocal()
    try:
        # Set tenant context if tenant_id provided
        if tenant_id:
            tenant = db.query(Tenant).filter(Tenant.uuid == tenant_id).first()
            if tenant:
                tenant_context.set_tenant(tenant)
            else:
                raise HTTPException(
                    status_code=404,
                    detail=f"Tenant not found: {tenant_id}"
                )

        yield db
    finally:
        db.close()
        tenant_context.clear_context()

# Utility functions for database operations
def create_tenant_session(tenant: Tenant) -> Session:
    """Create a database session for a specific tenant"""
    engine = get_database_engine(tenant.uuid)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)()

def get_or_create_tenant(db: Session, name: str, domain: Optional[str] = None) -> Tenant:
    """Get existing tenant or create new one"""
    tenant = db.query(Tenant).filter(Tenant.name == name).first()

    if not tenant:
        tenant = Tenant(
            name=name,
            domain=domain,
            is_active=True
        )
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        logger.info(f"Created new tenant: {tenant.name}")

    return tenant

def create_default_admin_user(db: Session, tenant: Tenant, password: str = None) -> User:
    """Create default admin user for tenant"""
    from .auth import get_password_hash

    if password is None:
        password = os.getenv("DEFAULT_ADMIN_PASSWORD")
        if not password:
            raise ValueError("Admin password must be provided via parameter or DEFAULT_ADMIN_PASSWORD environment variable")

    admin_user = User(
        tenant_id=tenant.id,
        username="admin",
        email=f"admin@{tenant.domain or 'localhost'}",
        hashed_password=get_password_hash(password),
        role="admin",
        is_active=True
    )

    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)

    logger.info(f"Created default admin user for tenant: {tenant.name}")
    return admin_user

# Health check function
def check_database_health() -> dict:
    """Check database health and return status"""
    try:
        if SessionLocal is None:
            return {
                "status": "error",
                "message": "Database not initialized"
            }

        db = SessionLocal()
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        db.close()

        return {
            "status": "healthy",
            "message": "Database connection successful"
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "error",
            "message": f"Database connection failed: {str(e)}"
        }