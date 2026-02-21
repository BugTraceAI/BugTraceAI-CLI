import asyncio
import random
import httpx
from typing import Tuple
from bugtrace.utils.logger import logger
from .models import MutableRequest
from .global_rate_limiter import global_rate_limiter

MAX_429_RETRIES = 3
BASE_429_DELAY = 2.0


class RequestController:
    """
    Controlador de peticiones HTTP con mecanismos de seguridad (Circuit Breaker, Throttling).
    Inspirado en Shift Agents v2 Request Controller.

    Uses GlobalRateLimiter to coordinate requests across all ManipulatorOrchestrator instances
    (XSSSkill, CSTISkill running in parallel).

    On HTTP 429: reduces global rate, retries with exponential backoff + jitter.
    Only opens circuit breaker after exhausting retries.
    """
    def __init__(self, rate_limit: float = 0.5, max_consecutive_errors: int = 5, use_global_limiter: bool = True):
        self.rate_limit = rate_limit  # Fallback if global limiter disabled
        self.use_global_limiter = use_global_limiter
        self.max_consecutive_errors = max_consecutive_errors
        self.error_count = 0
        self.circuit_open = False
        self.client = httpx.AsyncClient(verify=False, timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=True)

    async def execute(self, request: MutableRequest) -> Tuple[int, str, float]:
        """
        Ejecuta una petición mutable respetando los límites.
        Retorna: (status_code, response_text, response_time)
        """
        if self.circuit_open:
            logger.warning("RequestController: Circuit breaker is OPEN. Rejecting request.")
            return 0, "CIRCUIT_OPEN", 0.0

        # Use global rate limiter if enabled (coordinates across XSS/CSTI)
        if self.use_global_limiter:
            await global_rate_limiter.acquire()
        else:
            await asyncio.sleep(self.rate_limit)

        try:
            status, text, elapsed = await self._do_request(request)

            if status == 429:
                status, text, elapsed = await self._handle_429(request)

            # Successful request (any non-429 response = network is reachable)
            if status != 429:
                self.error_count = 0
                global_rate_limiter.try_recover()

            return status, text, elapsed

        except httpx.RequestError as e:
            self.error_count += 1
            logger.error(f"RequestController: Network error: {e}", exc_info=True)
            if self.error_count >= self.max_consecutive_errors:
                self.circuit_open = True
                logger.critical("RequestController: Max errors reached. Opening Circuit Breaker.")
            return 0, str(e), 0.0
        except Exception as e:
            logger.error(f"RequestController: Unexpected error: {e}", exc_info=True)
            return 0, str(e), 0.0

    async def _do_request(self, request: MutableRequest) -> Tuple[int, str, float]:
        """Execute a single HTTP request."""
        kwargs = {
            "headers": request.headers,
            "params": request.params,
            "cookies": request.cookies
        }
        if request.json_payload:
            kwargs["json"] = request.json_payload
        elif request.data:
            kwargs["data"] = request.data

        response = await self.client.request(
            method=request.method,
            url=request.url,
            **kwargs
        )
        return response.status_code, response.text, response.elapsed.total_seconds()

    async def _handle_429(self, request: MutableRequest) -> Tuple[int, str, float]:
        """Handle 429 Too Many Requests with adaptive rate reduction and retries."""
        # Reduce global rate by half
        new_rate = global_rate_limiter.requests_per_second * 0.5
        global_rate_limiter.update_rate(new_rate)

        for attempt in range(MAX_429_RETRIES):
            delay = BASE_429_DELAY * (2 ** attempt)
            delay *= random.uniform(0.8, 1.2)  # jitter
            logger.warning(f"RequestController: 429 Too Many Requests. "
                           f"Retry {attempt + 1}/{MAX_429_RETRIES} after {delay:.1f}s "
                           f"(rate: {global_rate_limiter.requests_per_second:.2f} req/s)")
            await asyncio.sleep(delay)

            status, text, elapsed = await self._do_request(request)
            if status != 429:
                return status, text, elapsed

            # Still 429 — reduce rate further
            new_rate = global_rate_limiter.requests_per_second * 0.5
            global_rate_limiter.update_rate(new_rate)

        # Exhausted retries — count as error for circuit breaker
        self.error_count += 1
        logger.warning(f"RequestController: 429 persists after {MAX_429_RETRIES} retries "
                       f"({self.error_count}/{self.max_consecutive_errors})")
        if self.error_count >= self.max_consecutive_errors:
            self.circuit_open = True
            logger.critical("RequestController: Max errors reached. Opening Circuit Breaker.")
        return 429, "Rate limited", 0.0

    async def close(self):
        await self.client.aclose()
