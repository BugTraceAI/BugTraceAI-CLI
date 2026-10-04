"""HTTP orchestrator shell module — extracted for size policy."""

from __future__ import annotations

import aiohttp
import asyncio
import random
import time
from enum import Enum
from typing import Optional, Dict, Any, Tuple, Callable, List
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
from collections import deque

from bugtrace.utils.logger import get_logger

logger = get_logger("core.http_orchestrator")


class CircuitOpenError(Exception):
    """Raised when circuit breaker is open."""
    pass


class ConnectionBlockedError(Exception):
    """Raised when new connections are blocked due to ghost connections."""
    pass


class OrchestratorNotStartedError(Exception):
    """Raised when orchestrator is used before start()."""
    pass
