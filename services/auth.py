"""
Authentication and authorization utilities for the security scanner service.
Provides API key and JWT token authentication with role-based access control.
"""

import os
import logging
import hmac
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from enum import Enum

from fastapi import HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from passlib.context import CryptContext
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt.

    Args:
        password: Plain text password

    Returns:
        Hashed password
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        plain_password: Plain text password
        hashed_password: Hashed password

    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)

# JWT settings
def get_secret_key():
    """Get JWT secret with validation - call this when needed, not at import time"""
    secret = os.getenv("JWT_SECRET_KEY")
    if not secret:
        environment = os.getenv("ENVIRONMENT", "development")
        if environment == "development":
            logger.warning("JWT_SECRET_KEY not set - using development default. "
                          "Set JWT_SECRET_KEY in production!")
            return "dev-secret-change-in-production"
        else:
            logger.error("JWT_SECRET_KEY environment variable must be set in production")
            raise ValueError("JWT_SECRET_KEY environment variable must be set")
    return secret

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# API Key settings
API_KEY_HEADER = "X-API-Key"

class UserRole(str, Enum):
    """User roles for authorization"""
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"

class User(BaseModel):
    """User model for authentication"""
    username: str
    role: UserRole
    api_key: str
    is_active: bool = True

class AuthService:
    """
    Authentication service providing API key and JWT token authentication.
    """

    def __init__(self):
        """Initialize the auth service with configured users."""
        self.users = self._load_users_from_env()

    def _load_users_from_env(self) -> dict:
        """
        Load users from environment variables.

        Returns:
            Dictionary of username -> User objects
        """
        users = {}
        admin_counter = 0
        user_counter = 0
        viewer_counter = 0

        # Load admin users
        admin_api_keys = os.getenv("ADMIN_API_KEYS", "")
        if admin_api_keys:
            for api_key in admin_api_keys.split(","):
                api_key = api_key.strip()
                if api_key:
                    admin_counter += 1
                    users[f"admin_{admin_counter}"] = User(
                        username=f"admin_{admin_counter}",
                        role=UserRole.ADMIN,
                        api_key=api_key
                    )

        # Load regular users
        user_api_keys = os.getenv("USER_API_KEYS", "")
        if user_api_keys:
            for api_key in user_api_keys.split(","):
                api_key = api_key.strip()
                if api_key:
                    user_counter += 1
                    users[f"user_{user_counter}"] = User(
                        username=f"user_{user_counter}",
                        role=UserRole.USER,
                        api_key=api_key
                    )

        # Load viewer users
        viewer_api_keys = os.getenv("VIEWER_API_KEYS", "")
        if viewer_api_keys:
            for api_key in viewer_api_keys.split(","):
                api_key = api_key.strip()
                if api_key:
                    viewer_counter += 1
                    users[f"viewer_{viewer_counter}"] = User(
                        username=f"viewer_{viewer_counter}",
                        role=UserRole.VIEWER,
                        api_key=api_key
                    )

        logger.info(f"Loaded {len(users)} users from environment")
        return users

    def authenticate_api_key(self, api_key: str) -> Optional[User]:
        """
        Authenticate using API key with timing-safe comparison.

        Args:
            api_key: API key to authenticate

        Returns:
            User object if authenticated, None otherwise
        """
        for user in self.users.values():
            if hmac.compare_digest(user.api_key, api_key) and user.is_active:
                return user
        return None

    def create_access_token(self, user: User) -> str:
        """
        Create JWT access token for user.

        Args:
            user: User to create token for

        Returns:
            JWT access token
        """
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode = {
            "sub": user.username,
            "role": user.role,
            "exp": expire
        }
        encoded_jwt = jwt.encode(to_encode, get_secret_key(), algorithm=ALGORITHM)
        return encoded_jwt

    def verify_token(self, token: str) -> Optional[User]:
        """
        Verify JWT token and return user.

        Args:
            token: JWT token to verify

        Returns:
            User object if token is valid, None otherwise
        """
        try:
            payload = jwt.decode(token, get_secret_key(), algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            role: str = payload.get("role")

            if username is None or role is None:
                return None

            # Find user by username
            for user in self.users.values():
                if user.username == username and user.role == role and user.is_active:
                    return user

            return None
        except jwt.PyJWTError:
            return None

    def require_role(self, required_roles: List[UserRole]):
        """
        Create dependency function that requires specific roles.

        Args:
            required_roles: List of required roles

        Returns:
            Dependency function
        """
        def role_checker(user: User = Depends(get_current_user)) -> User:
            if user.role not in required_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Operation requires one of: {required_roles}"
                )
            return user
        return role_checker

# Global auth service instance
auth_service = AuthService()

# FastAPI security schemes
security = HTTPBearer(auto_error=False)

def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> User:
    """
    Get current authenticated user from API key or JWT token.

    Args:
        request: FastAPI request object
        credentials: JWT token from Authorization header

    Returns:
        Authenticated user

    Raises:
        HTTPException: If authentication fails
    """
    # Try API key authentication first
    api_key = getattr(request.state, 'api_key', None)
    if api_key:
        user = auth_service.authenticate_api_key(api_key)
        if user:
            return user

    # Try JWT token authentication
    if credentials and credentials.scheme == "Bearer":
        user = auth_service.verify_token(credentials.credentials)
        if user:
            return user

    # No valid authentication found
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

def require_admin():
    """Dependency that requires admin role."""
    return auth_service.require_role([UserRole.ADMIN])

def require_user():
    """Dependency that requires user or admin role."""
    return auth_service.require_role([UserRole.USER, UserRole.ADMIN])

def require_viewer():
    """Dependency that requires any authenticated user."""
    return auth_service.require_role([UserRole.VIEWER, UserRole.USER, UserRole.ADMIN])