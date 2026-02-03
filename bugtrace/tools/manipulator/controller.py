import asyncio
import httpx
from typing import Optional, Tuple
from bugtrace.utils.logger import logger
from .models import MutableRequest
from .global_rate_limiter import global_rate_limiter

class RequestController:
    """
    Controlador de peticiones HTTP con mecanismos de seguridad (Circuit Breaker, Throttling).
    Inspirado en Shift Agents v2 Request Controller.

    Uses GlobalRateLimiter to coordinate requests across all ManipulatorOrchestrator instances
    (XSSSkill, CSTISkill running in parallel).
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
            # Prepare arguments
            kwargs = {
                "headers": request.headers,
                "params": request.params,
                "cookies": request.cookies
            }
            if request.json_payload:
                kwargs["json"] = request.json_payload
            elif request.data:
                kwargs["data"] = request.data

            # Execute
            response = await self.client.request(
                method=request.method,
                url=request.url,
                **kwargs
            )
            
            # Reset error count on success (2xx/3xx/4xx are "success" in terms of network reachable)
            # We only count network errors or 429s as "errors" for circuit breaker
            if response.status_code != 429:
                self.error_count = 0
            else:
                self.error_count += 1
                logger.warning(f"RequestController: Received 429 Too Many Requests ({self.error_count}/{self.max_consecutive_errors})")

            return response.status_code, response.text, response.elapsed.total_seconds()

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

    async def close(self):
        await self.client.aclose()
