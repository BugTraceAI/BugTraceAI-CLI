"""
SQLMap Runner

I/O layer for SQLMap Docker execution, process management,
WAF detection, and rate limiting.

Extracted from sqlmap_agent.py for modularity.
"""

import asyncio
from typing import Dict, List, Optional, Any, Tuple

from bugtrace.agents.sqlmap.core import (
    SQLMapConfig,
    SQLiEvidence,
    DBType,
    WAFBypassStrategy,
    strip_ansi_codes,
    build_full_command,
    build_reproduction_command,
    build_docker_command,
    cache_key,
    parse_sqlmap_output,
    process_sqlmap_output,
    check_sqlmap_error_patterns,
)


# =============================================================================
# GLOBAL SEMAPHORE FOR RATE LIMITING (TASK-39)
# =============================================================================

_sqlmap_semaphore: Optional[asyncio.Semaphore] = None


def get_sqlmap_semaphore(max_concurrent: int = 2) -> asyncio.Semaphore:  # I/O
    """Get or create the global SQLMap semaphore for rate limiting (TASK-39).

    Args:
        max_concurrent: Maximum concurrent SQLMap processes

    Returns:
        Asyncio Semaphore instance
    """
    global _sqlmap_semaphore
    if _sqlmap_semaphore is None:
        _sqlmap_semaphore = asyncio.Semaphore(max_concurrent)
    return _sqlmap_semaphore


# =============================================================================
# WAF DETECTION (I/O)
# =============================================================================

async def detect_waf_async(url: str, waf_fingerprinter_ref=None, logger=None) -> Tuple[str, float]:  # I/O
    """
    Detect WAF using framework's intelligent fingerprinter.

    Args:
        url: Target URL
        waf_fingerprinter_ref: Reference to waf_fingerprinter module
        logger: Optional logger

    Returns:
        Tuple of (waf_name, confidence)
    """
    try:
        if waf_fingerprinter_ref is None:
            from bugtrace.tools.waf import waf_fingerprinter as waf_fingerprinter_ref
        waf_name, confidence = await waf_fingerprinter_ref.detect(url)
        if waf_name != "unknown" and logger:
            logger.info(f"WAF Detected: {waf_name} (confidence: {confidence:.0%})")
        return waf_name, confidence
    except Exception as e:
        if logger:
            logger.debug(f"WAF detection failed: {e}")
        return "unknown", 0.0


async def get_smart_bypass_strategies(
    url: str,
    max_strategies: int = 5,
    strategy_router_ref=None,
    logger=None,
) -> Tuple[str, List[str]]:  # I/O
    """
    Get optimized bypass strategies using Q-Learning router.

    Args:
        url: Target URL
        max_strategies: Max number of strategies to return
        strategy_router_ref: Reference to strategy_router module
        logger: Optional logger

    Returns:
        Tuple of (waf_name, list_of_tamper_names)
    """
    try:
        if strategy_router_ref is None:
            from bugtrace.tools.waf import strategy_router as strategy_router_ref
        waf_name, strategies = await strategy_router_ref.get_strategies_for_target(url, max_strategies)

        # Convert encoding technique names to SQLMap tamper scripts
        tampers = WAFBypassStrategy.convert_strategies_to_tampers(strategies)

        # Add fallback tampers if we didn't get enough
        if len(tampers) < 3:
            WAFBypassStrategy.add_fallback_tampers(tampers, waf_name, max_strategies)

        return waf_name, tampers[:max_strategies]

    except Exception as e:
        if logger:
            logger.warning(f"Strategy router failed: {e}, using fallback")
        return "unknown", WAFBypassStrategy.WAF_TAMPER_FALLBACK["generic"]


# =============================================================================
# ENHANCED SQLMAP RUNNER
# =============================================================================

class EnhancedSQLMapRunner:  # I/O
    """
    Enhanced SQLMap execution with intelligent configuration.

    Security improvements (2026-01-26):
    - TASK-35: Version verification
    - TASK-39: Rate limiting via semaphore
    - TASK-40: Result caching
    """

    # TASK-40: Class-level cache for SQLMap results
    _result_cache: Dict[str, SQLiEvidence] = {}

    def __init__(self, cookies: List[Dict] = None, headers: Dict[str, str] = None, docker_cmd: str = None):
        self.cookies = cookies or []
        self.headers = headers or {}
        self._sqlmap_verified = False

        if docker_cmd is None:
            from bugtrace.tools.external import external_tools
            self.docker_cmd = external_tools.docker_cmd
        else:
            self.docker_cmd = docker_cmd

        self._logger = None

    def _get_logger(self):
        """Lazy-load logger."""
        if self._logger is None:
            from bugtrace.utils.logger import get_logger
            self._logger = get_logger("agents.sqlmap_v2")
        return self._logger

    @classmethod
    async def verify_sqlmap(cls, docker_cmd: str = None) -> bool:  # I/O
        """
        Verify SQLMap is available and get version (TASK-35).

        Args:
            docker_cmd: Path to docker binary

        Returns:
            True if SQLMap is available, False otherwise
        """
        if docker_cmd is None:
            from bugtrace.tools.external import external_tools
            docker_cmd = external_tools.docker_cmd

        if not docker_cmd:
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                docker_cmd, "run", "--rm", "googlesky/sqlmap:latest", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

            if proc.returncode == 0:
                version = strip_ansi_codes(stdout.decode().strip())
                return True
            else:
                return False
        except asyncio.TimeoutError:
            return False
        except FileNotFoundError:
            return False
        except Exception:
            return False

    @classmethod
    def _cache_key(cls, url: str, method: str, data: Optional[str]) -> str:  # PURE
        """Generate cache key for SQLMap results (TASK-40)."""
        return cache_key(url, method, data)

    async def run_intelligent(
        self,
        url: str,
        param: Optional[str] = None,
        config: SQLMapConfig = None,
        post_data: Optional[str] = None,
        db_type: DBType = DBType.UNKNOWN,
    ) -> SQLiEvidence:  # I/O
        """
        Run SQLMap with intelligent configuration based on context.

        Args:
            url: Target URL
            param: Specific parameter to test (optional)
            config: SQLMap configuration
            post_data: POST body data (for POST requests)
            db_type: Pre-detected database type

        Returns:
            SQLiEvidence with results

        Security improvements (2026-01-26):
        - TASK-35: Verify SQLMap before first run
        - TASK-39: Rate limiting via semaphore
        - TASK-40: Result caching
        """
        logger = self._get_logger()

        if not self.docker_cmd:
            logger.warning("Docker not available, cannot run SQLMap")
            return SQLiEvidence(vulnerable=False)

        # TASK-35: Verify SQLMap on first run
        if not self._sqlmap_verified:
            if not await self.verify_sqlmap(self.docker_cmd):
                logger.error("SQLMap verification failed, aborting")
                return SQLiEvidence(vulnerable=False)
            self._sqlmap_verified = True

        config = config or SQLMapConfig()

        # TASK-40: Check cache first
        method = "POST" if post_data else "GET"
        ck = self._cache_key(url, method, post_data)
        if ck in self._result_cache:
            logger.info(f"Using cached SQLMap result for {url}")
            return self._result_cache[ck]

        # TASK-39: Rate limiting - acquire semaphore before execution
        from bugtrace.core.config import settings
        max_concurrent = getattr(settings, 'MAX_CONCURRENT_SQLMAP', 2)
        semaphore = get_sqlmap_semaphore(max_concurrent)

        async with semaphore:
            logger.debug(f"Acquired SQLMap semaphore, executing scan on {url}")

            # Build command
            cmd = build_full_command(
                url, param, config, post_data, db_type,
                cookies=self.cookies, headers=self.headers, logger=logger,
            )
            reproduction_cmd = build_reproduction_command(
                url, param, config, post_data, cookies=self.cookies,
            )

            # Execute
            from bugtrace.core.ui import dashboard
            dashboard.log(f"[SQLMapAgent] Executing intelligent scan on {url}", "INFO")
            output = await self._execute_sqlmap(cmd)

            # Parse results
            evidence = parse_sqlmap_output(output, url, param)
            evidence.reproduction_command = reproduction_cmd

            # TASK-40: Cache the result
            self._result_cache[ck] = evidence

            return evidence

    async def _execute_sqlmap(self, cmd: List[str]) -> str:  # I/O
        """Execute SQLMap via Docker.

        Security improvements (2026-01-26):
        - TASK-34: Strip ANSI codes from output
        - TASK-36: Configurable timeout
        - TASK-37: Output size limit
        - TASK-38: Better error detection

        Args:
            cmd: SQLMap arguments

        Returns:
            Cleaned stdout text
        """
        logger = self._get_logger()
        full_cmd = build_docker_command(self.docker_cmd, cmd)

        cmd_str = ' '.join(full_cmd)
        logger.info(f"SQLMap executing: {cmd_str[:200]}...")

        from bugtrace.core.config import settings
        from bugtrace.core.ui import dashboard

        dashboard.log(f"[SQLMapAgent] Executing SQLMap...", "DEBUG")
        timeout_seconds = getattr(settings, 'SQLMAP_TIMEOUT_SECONDS', 600)
        max_output_size = getattr(settings, 'SQLMAP_MAX_OUTPUT_SIZE', 10_000_000)

        try:
            proc = await asyncio.create_subprocess_exec(
                *full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)

            stdout_text, stderr_text = process_sqlmap_output(
                stdout, stderr, proc.returncode,
                max_output_size=max_output_size, logger=logger,
            )

            self._log_sqlmap_result(stdout_text, proc.returncode)
            return stdout_text

        except asyncio.TimeoutError:
            logger.warning(f"SQLMap execution timed out ({timeout_seconds}s)")
            return ""
        except ConnectionError as e:
            logger.warning(f"SQLMap connection error: {e}", exc_info=True)
            return ""
        except Exception as e:
            logger.error(f"SQLMap execution error: {e}", exc_info=True)
            return ""

    def _log_sqlmap_result(self, stdout_text: str, returncode: int) -> None:  # I/O
        """Log SQLMap execution result."""
        logger = self._get_logger()
        if "is vulnerable" in stdout_text.lower():
            logger.info("SQLMap detected vulnerability!")
        elif "no injection found" in stdout_text.lower():
            logger.debug("SQLMap: No injection found")
        elif not stdout_text:
            logger.warning("SQLMap returned empty output")
        else:
            logger.debug(f"SQLMap output preview: {stdout_text[:200]}")
