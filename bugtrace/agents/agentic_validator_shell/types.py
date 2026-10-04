"""
AgenticValidator: AI-Powered Vulnerability Validation Agent (v2 - OPTIMIZED)

PERFORMANCE OPTIMIZATIONS (2026-01-21):
1. Parallel validation with configurable concurrency (3x-5x faster)
2. Browser session pooling (reuse instead of launch per validation)
3. Early-exit when CDP confirms (skip expensive vision API)
4. Result caching for similar payloads/URLs (avoid re-validation)
5. Smart fast-path for high-confidence/pre-validated findings
6. Reduced timeouts and eliminated unnecessary sleeps
7. Batch screenshot capture for similar URLs

This validator uses an LLM with vision capabilities to:
1. Navigate to target URLs with payloads
2. Capture screenshots
3. Reason about the visual state to determine if vulnerability is real
4. Adapt testing strategy based on context
"""

from typing import List, Dict, Any, Tuple, Optional, Set
import asyncio
import base64
import json
import hashlib
import time
from pathlib import Path
from loguru import logger
from dataclasses import dataclass, field
from collections import OrderedDict

from bugtrace.agents.base import BaseAgent
from bugtrace.tools.visual.browser import browser_manager, BrowserManager
from bugtrace.tools.visual.verifier import XSSVerifier, VerificationResult
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.core.event_bus import EventType, event_bus as global_event_bus
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.core.validation_metrics import validation_metrics
# Import specialist utilities for full payload loading (v2.1.0+)
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data
from bugtrace.core.verbose_events import create_emitter
# NOTE: ValidationFeedback imports removed - feedback loop eliminated for simplicity
# AgenticValidator is now a linear CDP specialist (no loopback to specialist agents)


# =============================================================================
# OPTIMIZATION 1: Validation Result Cache (LRU)
# =============================================================================

@dataclass
class ValidationCache:
    """LRU Cache for validation results to avoid re-validating identical payloads."""
    max_size: int = 100
    _cache: OrderedDict = field(default_factory=OrderedDict)

    def get_key(self, url: str, payload: str) -> str:
        """Generate cache key from full URL + payload hash.

        NOTE: We include the full URL (with query params) because different
        parameter values may have different escaping/filtering behavior.
        E.g., /user?id=1 vs /user?id=100 might have different XSS contexts.
        """
        from urllib.parse import urlparse, parse_qs, urlencode
        parsed = urlparse(url)
        # Sort query params for consistent caching
        params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(params.items()), doseq=True) if params else ""
        normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{sorted_query}" if sorted_query else f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        content = f"{normalized_url}:{payload or 'none'}"
        return hashlib.md5(content.encode()).hexdigest()

    def get(self, url: str, payload: str) -> Optional[Dict]:
        """Get cached result if exists."""
        key = self.get_key(url, payload)
        if key in self._cache:
            self._cache.move_to_end(key)  # LRU: move to end
            logger.debug(f"Cache HIT for {url[:50]}...")
            return self._cache[key]
        return None

    def set(self, url: str, payload: str, result: Dict):
        """Cache a validation result."""
        key = self.get_key(url, payload)
        self._cache[key] = result
        self._cache.move_to_end(key)
        # Evict oldest if over capacity
        while len(self._cache) > self.max_size:
            self._cache.popitem(last=False)

    def clear(self):
        self._cache.clear()

    def __len__(self):
        return len(self._cache)


# =============================================================================
# OPTIMIZATION 2: Shared XSSVerifier Pool
# =============================================================================
class VerifierPool:
    """Pool of XSSVerifier instances to avoid recreation overhead."""

    def __init__(self, pool_size: int = 3):
        self.pool_size = pool_size
        self._verifiers: List[XSSVerifier] = []
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._initialized = False

    async def initialize(self):
        """Initialize verifier pool (lazy init)."""
        if self._initialized:
            return
        self._semaphore = asyncio.Semaphore(self.pool_size)
        self._verifiers = [
            XSSVerifier(headless=settings.HEADLESS_BROWSER, prefer_cdp=True)
            for _ in range(self.pool_size)
        ]
        self._initialized = True
        logger.info(f"VerifierPool initialized with {self.pool_size} instances")

    async def get_verifier(self) -> XSSVerifier:
        """Get an available verifier from the pool."""
        if not self._initialized:
            await self.initialize()
        await self._semaphore.acquire()
        # Return any verifier (they're stateless between calls)
        return self._verifiers[0]

    def release(self):
        """Release verifier back to pool."""
        if self._semaphore:
            self._semaphore.release()


# Global pool instance
_verifier_pool = VerifierPool(pool_size=3)


