"""
Global Rate Limiter - Coordinates rate limiting across ALL ManipulatorOrchestrator instances.

This ensures XSSSkill and CSTISkill don't saturate targets when running in parallel.
Supports adaptive throttling: reduces rate on 429 responses, recovers gradually on success.
"""

import asyncio
import time
from bugtrace.utils.logger import get_logger

logger = get_logger("tools.manipulator.global_rate_limiter")


class GlobalRateLimiter:
    """
    Singleton rate limiter shared by all ManipulatorOrchestrator instances.

    Ensures total request rate across XSS, CSTI, and future exploitation skills
    doesn't exceed configured limit.
    """

    _instance = None
    _lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, requests_per_second: float = None):
        """
        Args:
            requests_per_second: Total requests/second across ALL skills.
                                If None, loads from settings.MANIPULATOR_GLOBAL_RATE_LIMIT
        """
        if self._initialized:
            return

        # Load from config if not specified
        if requests_per_second is None:
            from bugtrace.core.config import settings
            requests_per_second = settings.MANIPULATOR_GLOBAL_RATE_LIMIT
            self.min_rate = settings.MANIPULATOR_RATE_LIMIT_MIN
            self.recovery_threshold = settings.MANIPULATOR_RATE_RECOVERY_THRESHOLD
        else:
            self.min_rate = 0.2
            self.recovery_threshold = 10

        self.requests_per_second = requests_per_second
        self.original_rate = requests_per_second
        self.min_interval = 1.0 / requests_per_second  # Seconds between requests
        self.last_request_time = 0.0
        self.successful_since_throttle = 0
        self._initialized = True

        logger.info(f"GlobalRateLimiter initialized: {requests_per_second} req/s global limit")

    async def acquire(self):
        """
        Acquire permission to make a request.
        Blocks until enough time has passed since last request.
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_request_time

            if elapsed < self.min_interval:
                wait_time = self.min_interval - elapsed
                await asyncio.sleep(wait_time)

            self.last_request_time = time.monotonic()

    def update_rate(self, requests_per_second: float):
        """Update rate limit dynamically (e.g., based on 429 responses)."""
        requests_per_second = max(requests_per_second, self.min_rate)
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.successful_since_throttle = 0
        logger.info(f"GlobalRateLimiter: Rate updated to {requests_per_second:.2f} req/s "
                    f"(original: {self.original_rate} req/s)")

    def try_recover(self):
        """Gradually recover rate after successful requests without 429."""
        if self.requests_per_second >= self.original_rate:
            return
        self.successful_since_throttle += 1
        if self.successful_since_throttle >= self.recovery_threshold:
            new_rate = min(self.requests_per_second * 1.25, self.original_rate)
            self.requests_per_second = new_rate
            self.min_interval = 1.0 / new_rate
            self.successful_since_throttle = 0
            logger.info(f"GlobalRateLimiter: Rate recovered to {new_rate:.2f} req/s "
                        f"(target: {self.original_rate} req/s)")


# Singleton instance (loads rate from settings.MANIPULATOR_GLOBAL_RATE_LIMIT)
global_rate_limiter = GlobalRateLimiter()
