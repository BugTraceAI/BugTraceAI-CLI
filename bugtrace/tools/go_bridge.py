"""
GoFuzzerBridge - Python bridge to the Go XSS Fuzzer.

Encapsulates subprocess calls to the compiled Go binary, providing
high-performance payload testing with Python orchestration.

Author: BugtraceAI Team
Version: 1.0.0
Date: 2026-02-03
"""

import asyncio
import json
import tempfile
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

logger = get_logger("tools.go_bridge")


@dataclass
class Reflection:
    """A single payload reflection result from Go fuzzer."""
    payload: str
    reflected: bool
    encoded: bool
    encoding_type: str
    context: str  # javascript, attribute_value, attribute_unquoted, html_text
    status_code: int
    response_length: int

    @property
    def is_suspicious(self) -> bool:
        """Check if reflection indicates potential XSS."""
        # Unencoded reflection in dangerous contexts is highly suspicious
        if self.reflected and not self.encoded:
            if self.context in ("javascript", "attribute_value", "attribute_unquoted"):
                return True
        return False


@dataclass
class FuzzResult:
    """Complete result from a Go fuzzer run."""
    target: str
    param: str
    total_payloads: int
    total_requests: int
    duration_ms: int
    requests_per_second: float
    reflections: List[Reflection] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)

    @property
    def has_reflections(self) -> bool:
        return len(self.reflections) > 0

    @property
    def suspicious_count(self) -> int:
        return sum(1 for r in self.reflections if r.is_suspicious)

    @classmethod
    def from_json(cls, data: dict) -> "FuzzResult":
        """Parse Go fuzzer JSON output into FuzzResult."""
        metadata = data.get("metadata", {})
        reflections = [
            Reflection(
                payload=r.get("payload", ""),
                reflected=r.get("reflected", False),
                encoded=r.get("encoded", False),
                encoding_type=r.get("encoding_type", ""),
                context=r.get("context", "unknown"),
                status_code=r.get("status_code", 0),
                response_length=r.get("response_length", 0)
            )
            for r in (data.get("reflections") or [])
        ]
        errors = data.get("errors") or []

        return cls(
            target=metadata.get("target", ""),
            param=metadata.get("param", ""),
            total_payloads=metadata.get("total_payloads", 0),
            total_requests=metadata.get("total_requests", 0),
            duration_ms=metadata.get("duration_ms", 0),
            requests_per_second=metadata.get("requests_per_second", 0.0),
            reflections=reflections,
            errors=errors
        )


class GoFuzzerBridge:
    """
    Bridge to execute the Go XSS Fuzzer binary.

    Handles:
    - Locating and compiling the Go binary (if needed)
    - Preparing payloads file
    - Injecting FUZZ marker into URL
    - Parsing JSON output
    - Error handling

    Usage:
        bridge = GoFuzzerBridge()
        result = await bridge.run(
            url="http://target.com/search",
            param="q",
            payloads=["<script>alert(1)</script>", "..."]
        )
    """

    # Path relative to project root
    BINARY_NAME = "go-xss-fuzzer"
    SOURCE_DIR = Path(__file__).parent.parent.parent / "tools" / "go-xss-fuzzer"
    BIN_DIR = Path(__file__).parent.parent.parent / "tools" / "bin"

    def __init__(
        self,
        concurrency: int = 50,
        timeout: int = 5,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ):
        """
        Initialize the Go fuzzer bridge.

        Args:
            concurrency: Number of concurrent requests (default: 50)
            timeout: Request timeout in seconds (default: 5)
            proxy: HTTP proxy URL (optional)
            headers: Additional HTTP headers (optional)
        """
        self.concurrency = concurrency
        self.timeout = timeout
        self.proxy = proxy
        self.headers = headers or {}
        self._binary_path: Optional[Path] = None

    def _get_binary_path(self) -> Path:
        """Get path to Go binary, checking multiple locations."""
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        # Check bin directory first
        bin_path = self.BIN_DIR / self.BINARY_NAME
        if bin_path.exists():
            self._binary_path = bin_path
            return bin_path

        # Check if go-xss-fuzzer is in PATH
        which_path = shutil.which(self.BINARY_NAME)
        if which_path:
            self._binary_path = Path(which_path)
            return self._binary_path

        raise FileNotFoundError(
            f"Go XSS fuzzer binary not found. "
            f"Please compile it with: cd {self.SOURCE_DIR} && go build -o {bin_path} main.go"
        )

    async def compile_if_needed(self) -> bool:
        """
        Compile the Go fuzzer if binary doesn't exist.

        Returns:
            True if compilation was needed and succeeded
        """
        try:
            self._get_binary_path()
            return False  # Already compiled
        except FileNotFoundError:
            pass

        # Ensure bin directory exists
        self.BIN_DIR.mkdir(parents=True, exist_ok=True)
        output_path = self.BIN_DIR / self.BINARY_NAME

        logger.info(f"Compiling Go XSS fuzzer to {output_path}")

        # Check if source exists
        if not (self.SOURCE_DIR / "main.go").exists():
            raise FileNotFoundError(f"Go source not found at {self.SOURCE_DIR}/main.go")

        # Compile
        process = await asyncio.create_subprocess_exec(
            "go", "build", "-o", str(output_path), "main.go",
            cwd=str(self.SOURCE_DIR),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_msg = stderr.decode() if stderr else "Unknown error"
            raise RuntimeError(f"Go compilation failed: {error_msg}")

        logger.info("Go XSS fuzzer compiled successfully")
        self._binary_path = output_path
        return True

    def _inject_fuzz_marker(self, url: str, param: str) -> str:
        """
        Replace parameter value with FUZZ marker.

        Args:
            url: Original URL (e.g., http://target.com/search?q=test&other=1)
            param: Parameter to fuzz (e.g., "q")

        Returns:
            URL with FUZZ marker (e.g., http://target.com/search?q=FUZZ&other=1)
        """
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        if param in query_params:
            query_params[param] = ["FUZZ"]
        else:
            # Parameter not in URL, append it
            query_params[param] = ["FUZZ"]

        # Rebuild query string (flatten single-value lists)
        new_query = urlencode(
            {k: v[0] if len(v) == 1 else v for k, v in query_params.items()},
            doseq=True
        )

        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

        return new_url

    async def _save_payloads_to_temp(self, payloads: List[str]) -> Path:
        """Save payloads to a temporary file."""
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="xss_payloads_")
        with open(fd, 'w', encoding='utf-8') as f:
            for payload in payloads:
                f.write(payload + "\n")
        return Path(path)

    async def run(
        self,
        url: str,
        param: str,
        payloads: List[str],
        extra_headers: Optional[Dict[str, str]] = None
    ) -> FuzzResult:
        """
        Execute the Go fuzzer against a target.

        Args:
            url: Target URL
            param: Parameter to fuzz
            payloads: List of payloads to test
            extra_headers: Additional headers for this run

        Returns:
            FuzzResult with reflections and metadata
        """
        if not payloads:
            logger.warning("No payloads provided to Go fuzzer")
            return FuzzResult(
                target=url,
                param=param,
                total_payloads=0,
                total_requests=0,
                duration_ms=0,
                requests_per_second=0.0
            )

        # Get binary path (may compile if needed)
        try:
            binary_path = self._get_binary_path()
        except FileNotFoundError:
            await self.compile_if_needed()
            binary_path = self._get_binary_path()

        # Prepare URL with FUZZ marker
        fuzz_url = self._inject_fuzz_marker(url, param)

        # Write payloads to temp file
        payloads_file = await self._save_payloads_to_temp(payloads)

        try:
            # Build command
            cmd = [
                str(binary_path),
                "-u", fuzz_url,
                "-p", str(payloads_file),
                "-c", str(self.concurrency),
                "-t", str(self.timeout),
                "-json"
            ]

            # Add proxy if configured
            if self.proxy:
                cmd.extend(["--proxy", self.proxy])

            # Merge headers
            all_headers = {**self.headers, **(extra_headers or {})}
            if all_headers:
                header_str = ",".join(f"{k}: {v}" for k, v in all_headers.items())
                cmd.extend(["-H", header_str])

            logger.debug(f"Executing Go fuzzer: {' '.join(cmd)}")

            # Execute
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Go fuzzer failed (exit {process.returncode}): {error_msg}")
                return FuzzResult(
                    target=url,
                    param=param,
                    total_payloads=len(payloads),
                    total_requests=0,
                    duration_ms=0,
                    requests_per_second=0.0,
                    errors=[{"error": error_msg}]
                )

            # Parse JSON output
            try:
                data = json.loads(stdout.decode())
                result = FuzzResult.from_json(data)
                result.param = param  # Ensure param is set

                logger.info(
                    f"Go fuzzer completed: {result.total_requests} requests, "
                    f"{len(result.reflections)} reflections, "
                    f"{result.requests_per_second:.1f} req/s"
                )

                return result

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Go fuzzer output: {e}")
                return FuzzResult(
                    target=url,
                    param=param,
                    total_payloads=len(payloads),
                    total_requests=0,
                    duration_ms=0,
                    requests_per_second=0.0,
                    errors=[{"error": f"JSON parse error: {e}"}]
                )

        finally:
            # Cleanup temp file
            try:
                payloads_file.unlink()
            except Exception:
                pass

    async def run_omniprobe(
        self,
        url: str,
        param: str,
        omniprobe_payload: str
    ) -> Optional[Reflection]:
        """
        Run a single omniprobe payload (Phase 1 quick check).

        Args:
            url: Target URL
            param: Parameter to test
            omniprobe_payload: The omniprobe payload string

        Returns:
            Reflection if reflected, None otherwise
        """
        result = await self.run(url, param, [omniprobe_payload])

        if result.reflections:
            return result.reflections[0]
        return None


# Singleton instance for convenience
_bridge_instance: Optional[GoFuzzerBridge] = None


def get_go_bridge(
    concurrency: int = 50,
    timeout: int = 5,
    proxy: Optional[str] = None
) -> GoFuzzerBridge:
    """
    Get or create a GoFuzzerBridge singleton.

    Args:
        concurrency: Number of concurrent requests
        timeout: Request timeout in seconds
        proxy: HTTP proxy URL

    Returns:
        GoFuzzerBridge instance
    """
    global _bridge_instance
    if _bridge_instance is None:
        _bridge_instance = GoFuzzerBridge(
            concurrency=concurrency,
            timeout=timeout,
            proxy=proxy
        )
    return _bridge_instance
