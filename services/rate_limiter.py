"""
Rate limiting service for the security scanner.
Provides Redis-based rate limiting to prevent abuse.
"""

import os
import time
import logging
from typing import Optional, Tuple
import redis
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class RateLimiter:
    """
    Redis-based rate limiter for API endpoints.
    """

    def __init__(self):
        """Initialize the rate limiter with Redis connection."""
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.redis_client = None
        self.enabled = os.getenv("RATE_LIMITING_ENABLED", "true").lower() == "true"

        # Try to connect to Redis
        try:
            self.redis_client = redis.from_url(redis_url, decode_responses=True)
            # Test the connection
            self.redis_client.ping()
            logger.info("Redis connection established for rate limiting")
        except redis.RedisError as e:
            logger.warning(f"Redis connection failed: {e}. Rate limiting will be disabled.")
            self.redis_client = None
            self.enabled = False

    def _get_redis_key(self, identifier: str, endpoint: str) -> str:
        """Generate Redis key for rate limiting."""
        return f"ratelimit:{identifier}:{endpoint}:{int(time.time() // 60)}"  # Per minute

    def _get_user_identifier(self, user) -> str:
        """Get user identifier for rate limiting."""
        if user:
            return f"user:{user.username}"
        return "anonymous"

    def check_rate_limit(
        self,
        user,
        endpoint: str,
        limit: int = None,
        window_minutes: int = 1
    ) -> Tuple[bool, Optional[int], Optional[int]]:
        """
        Check if request is within rate limits.

        Args:
            user: Authenticated user (can be None for anonymous)
            endpoint: API endpoint being accessed
            limit: Maximum requests per window (uses env var if None)
            window_minutes: Time window in minutes

        Returns:
            Tuple of (allowed: bool, remaining_requests: int, reset_time: int)
        """
        if not self.enabled:
            return True, None, None

        # Get rate limit from environment or use default
        if limit is None:
            if user and hasattr(user, 'role'):
                if user.role == "admin":
                    limit = int(os.getenv("RATE_LIMIT_ADMIN", "100"))
                elif user.role == "user":
                    limit = int(os.getenv("RATE_LIMIT_USER", "20"))
                else:  # viewer
                    limit = int(os.getenv("RATE_LIMIT_VIEWER", "10"))
            else:
                limit = int(os.getenv("RATE_LIMIT_ANONYMOUS", "5"))

        # Get user identifier
        user_id = self._get_user_identifier(user)

        # Create Redis key
        redis_key = self._get_redis_key(user_id, endpoint)

        # Check if Redis is available
        if not self.redis_client:
            logger.debug(f"Rate limiting disabled (no Redis connection) for {user_id} on {endpoint}")
            return True, None, None

        try:
            # Use Redis pipeline for atomic operations
            with self.redis_client.pipeline() as pipe:
                pipe.incr(redis_key)
                pipe.expire(redis_key, window_minutes * 60)  # Convert to seconds
                results = pipe.execute()

            current_count = results[0]
            ttl = self.redis_client.ttl(redis_key)

            # Check if limit exceeded
            if current_count > limit:
                logger.warning(
                    f"Rate limit exceeded for {user_id} on {endpoint}: "
                    f"{current_count}/{limit} requests"
                )
                return False, 0, ttl

            remaining = limit - current_count
            return True, remaining, ttl

        except redis.RedisError as e:
            logger.error(f"Redis error in rate limiting: {e}")
            # Configurable fail behavior based on environment
            fail_closed = os.getenv("RATE_LIMIT_FAIL_CLOSED", "true").lower() == "true"
            if fail_closed:
                # Fail closed: block requests during Redis outage
                logger.warning("Rate limiting failing closed due to Redis error")
                return False, 0, 60  # Block for 60 seconds
            else:
                # Fail open: allow requests during Redis outage (less secure)
                logger.warning("Rate limiting failing open due to Redis error")
                return True, None, None

    def get_rate_limit_status(
        self,
        user,
        endpoint: str
    ) -> dict:
        """
        Get current rate limit status for user and endpoint.

        Args:
            user: Authenticated user
            endpoint: API endpoint

        Returns:
            Dictionary with rate limit status
        """
        user_id = self._get_user_identifier(user)
        redis_key = self._get_redis_key(user_id, endpoint)

        # Check if Redis is available
        if not self.redis_client:
            # Get limits based on user role
            if user and hasattr(user, 'role'):
                if user.role == "admin":
                    limit = int(os.getenv("RATE_LIMIT_ADMIN", "100"))
                elif user.role == "user":
                    limit = int(os.getenv("RATE_LIMIT_USER", "20"))
                else:
                    limit = int(os.getenv("RATE_LIMIT_VIEWER", "10"))
            else:
                limit = int(os.getenv("RATE_LIMIT_ANONYMOUS", "5"))

            return {
                "current_count": 0,
                "limit": limit,
                "remaining": limit,
                "reset_in_seconds": 0,
                "reset_time": None,
                "note": "Rate limiting disabled (no Redis connection)"
            }

        try:
            current_count = int(self.redis_client.get(redis_key) or 0)
            ttl = self.redis_client.ttl(redis_key)

            # Get limits based on user role
            if user and hasattr(user, 'role'):
                if user.role == "admin":
                    limit = int(os.getenv("RATE_LIMIT_ADMIN", "100"))
                elif user.role == "user":
                    limit = int(os.getenv("RATE_LIMIT_USER", "20"))
                else:
                    limit = int(os.getenv("RATE_LIMIT_VIEWER", "10"))
            else:
                limit = int(os.getenv("RATE_LIMIT_ANONYMOUS", "5"))

            return {
                "current_count": current_count,
                "limit": limit,
                "remaining": max(0, limit - current_count),
                "reset_in_seconds": ttl,
                "reset_time": datetime.now() + timedelta(seconds=ttl) if ttl > 0 else None
            }
        except redis.RedisError as e:
            logger.error(f"Redis error getting rate limit status: {e}")
            return {
                "error": "Unable to retrieve rate limit status",
                "current_count": 0,
                "limit": 0,
                "remaining": 0,
                "reset_in_seconds": 0
            }

# Global rate limiter instance
rate_limiter = RateLimiter()