"""
Rate limiting module for BinaryIF MVP.

Provides sliding window rate limiting with per-key tracking.
"""

import time
import threading
from collections import defaultdict, deque
from typing import Dict, Tuple, Optional
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    remaining: int
    reset_at: float
    retry_after: Optional[float] = None


class RateLimiter:
    """
    Sliding window rate limiter.
    
    Thread-safe implementation using deques for efficient
    sliding window tracking.
    """
    
    def __init__(self, rpm: int, window_seconds: int = 60):
        """
        Initialize rate limiter.
        
        Args:
            rpm: Maximum requests per minute (or per window)
            window_seconds: Window size in seconds (default 60)
        """
        self._limit = max(1, rpm)
        self._window = window_seconds
        self._hits: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.RLock()
    
    def allow(self, key: str) -> bool:
        """
        Check if a request should be allowed.
        
        Args:
            key: Identifier for rate limiting (e.g., client ID, endpoint)
            
        Returns:
            True if request is allowed, False if rate limited
        """
        return self.check(key).allowed
    
    def check(self, key: str) -> RateLimitResult:
        """
        Check rate limit and return detailed result.
        
        Args:
            key: Identifier for rate limiting
            
        Returns:
            RateLimitResult with allowed status and metadata
        """
        now = time.time()
        window_start = now - self._window
        
        with self._lock:
            q = self._hits[key]
            
            # Remove expired entries
            while q and q[0] < window_start:
                q.popleft()
            
            current_count = len(q)
            remaining = max(0, self._limit - current_count)
            reset_at = (q[0] + self._window) if q else (now + self._window)
            
            if current_count >= self._limit:
                # Calculate retry-after
                retry_after = q[0] + self._window - now
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_at=reset_at,
                    retry_after=max(0, retry_after)
                )
            
            # Record this request
            q.append(now)
            
            return RateLimitResult(
                allowed=True,
                remaining=remaining - 1,
                reset_at=reset_at
            )
    
    def get_stats(self, key: str) -> Dict[str, int]:
        """
        Get current stats for a key.
        
        Args:
            key: Identifier for rate limiting
            
        Returns:
            Dict with current count and limit
        """
        now = time.time()
        window_start = now - self._window
        
        with self._lock:
            q = self._hits[key]
            
            # Count only non-expired entries
            count = sum(1 for t in q if t >= window_start)
            
            return {
                "current": count,
                "limit": self._limit,
                "remaining": max(0, self._limit - count),
                "window_seconds": self._window
            }
    
    def reset(self, key: Optional[str] = None) -> None:
        """
        Reset rate limit counters.
        
        Args:
            key: Specific key to reset, or None to reset all
        """
        with self._lock:
            if key:
                self._hits.pop(key, None)
            else:
                self._hits.clear()
    
    def cleanup_expired(self) -> int:
        """
        Remove expired entries from all keys.
        
        Returns:
            Number of entries removed
        """
        now = time.time()
        window_start = now - self._window
        removed = 0
        
        with self._lock:
            empty_keys = []
            
            for key, q in self._hits.items():
                while q and q[0] < window_start:
                    q.popleft()
                    removed += 1
                
                if not q:
                    empty_keys.append(key)
            
            # Remove empty keys
            for key in empty_keys:
                del self._hits[key]
        
        return removed


class TokenBucketLimiter:
    """
    Token bucket rate limiter for burst handling.
    
    Allows bursts up to bucket capacity while maintaining
    average rate over time.
    """
    
    def __init__(self, rate: float, capacity: int):
        """
        Initialize token bucket.
        
        Args:
            rate: Tokens added per second
            capacity: Maximum bucket capacity
        """
        self._rate = rate
        self._capacity = capacity
        self._buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_update)
        self._lock = threading.RLock()
    
    def allow(self, key: str, tokens: int = 1) -> bool:
        """
        Check if request should be allowed and consume tokens.
        
        Args:
            key: Identifier for rate limiting
            tokens: Number of tokens to consume
            
        Returns:
            True if request is allowed, False if rate limited
        """
        now = time.time()
        
        with self._lock:
            if key in self._buckets:
                current_tokens, last_update = self._buckets[key]
                # Add tokens based on time elapsed
                elapsed = now - last_update
                current_tokens = min(self._capacity, current_tokens + elapsed * self._rate)
            else:
                current_tokens = self._capacity
            
            if current_tokens >= tokens:
                self._buckets[key] = (current_tokens - tokens, now)
                return True
            else:
                self._buckets[key] = (current_tokens, now)
                return False
