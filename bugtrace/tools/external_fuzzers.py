"""ExternalTools mixin."""

from __future__ import annotations

import shutil
import asyncio
import json
import re
import os
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin

from bugtrace.utils.logger import get_logger
from bugtrace.utils.parsers import extract_sqlmap_verdict
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.exceptions import (
    ToolError, DockerError, DockerTimeoutError, DockerNotFoundError,
    SubprocessError, FuzzerError, FuzzerTimeoutError, NucleiError, JSONParseError,
)
import bugtrace.tools.external_util as _eu
from bugtrace.tools.external_util import *  # noqa: F401,F403
from bugtrace.tools.external_util import _parse_tool_output  # import * skips _names

logger = get_logger("tools.external")


class ExternalFuzzersMixin:
    """Go XSS/SSRF/LFI/IDOR fuzzer runners."""

    def _build_fuzz_url(self, url: str, param: str) -> str:
        """Build URL with FUZZ marker replacing parameter value.

        Handles three cases:
        1. Query parameter exists in URL → replace its value with FUZZ
        2. Path-based parameter (URL Path, :param, {param}) → replace path segment
        3. Fallback → append as new query parameter
        """
        # Case 1: query param exists in URL
        if f"{param}=" in url:
            return re.sub(rf"([?&]{re.escape(param)})=([^&]*)", r"\1=FUZZ", url)

        # Case 2: path-based parameter — replace last numeric/template segment
        path_indicators = {"URL Path", "url_path", "path", "path_id"}
        is_path_param = (
            param in path_indicators
            or param.startswith(":")
            or (param.startswith("{") and param.endswith("}"))
        )
        if is_path_param:
            parsed = urlparse(url)
            segments = parsed.path.rstrip("/").split("/")
            # Replace last numeric/UUID segment, or append FUZZ if URL ends with /
            replaced = False
            for i in range(len(segments) - 1, -1, -1):
                seg = segments[i]
                if not seg:
                    continue
                # Template vars: :id, {id}
                if seg.startswith(":") or (seg.startswith("{") and seg.endswith("}")):
                    segments[i] = "FUZZ"
                    replaced = True
                    break
                # Numeric IDs
                if seg.isdigit():
                    segments[i] = "FUZZ"
                    replaced = True
                    break
            if not replaced:
                # URL like /api/orders/ → append FUZZ as path segment
                segments.append("FUZZ")
            new_path = "/".join(segments)
            base = f"{parsed.scheme}://{parsed.netloc}{new_path}"
            if parsed.query:
                return f"{base}?{parsed.query}"
            return base

        # Case 3: fallback — add as new query parameter
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}{param}=FUZZ"

    async def _write_payloads_file(self, payloads: List[str]) -> str:
        """Write payloads to temporary file and return path."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("\n".join(payloads))
            return f.name

    async def _cleanup_temp_file(self, filepath: str) -> None:
        """Clean up temporary file safely."""
        if filepath and os.path.exists(filepath):
            try:
                os.unlink(filepath)
            except OSError:
                logger.warning(f"Failed to cleanup temp file: {filepath}")

    async def run_go_xss_fuzzer(self, url: str, param: str, payloads: List[str] = None) -> Optional[Dict]:
        """
        Run the Go XSS fuzzer for high-performance payload testing.

        Returns:
            {
                "reflections": [...],
                "metadata": {...}
            }
        """
        binary_path = settings.BASE_DIR / "bin" / "go-xss-fuzzer"

        if not binary_path.exists():
            logger.warning(f"Go XSS fuzzer not found at {binary_path}, falling back to Python")
            return None

        fuzz_url = self._build_fuzz_url(url, param)
        cmd = [str(binary_path), "-u", fuzz_url, "-c", "100", "-t", "5", "--json"]

        payloads_file = None
        try:
            if payloads:
                payloads_file = await self._write_payloads_file(payloads)
                cmd.extend(["-p", payloads_file])
                logger.debug(f"Go XSS Fuzzer using custom payloads file: {payloads_file}")

            logger.info(f"Launching Go XSS Fuzzer against {param} on {url}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)

            if process.returncode == 0:
                result = _parse_tool_output(stdout.decode())
                logger.debug(f"Go XSS Fuzzer finished successfully. Metadata: {result.get('metadata')}")
                return result
            else:
                logger.error(f"Go XSS fuzzer failed (Exit Code {process.returncode}): {stderr.decode()}")
                return None
        except Exception as e:
            logger.error(f"Go XSS fuzzer error: {e}", exc_info=True)
            return None
        finally:
            await self._cleanup_temp_file(payloads_file)

    def _build_ssrf_command(
        self,
        binary_path: str,
        fuzz_url: str,
        oob_url: Optional[str]
    ) -> List[str]:
        """Build command for SSRF fuzzer execution."""
        cmd = [
            str(binary_path),
            "-u", fuzz_url,
            "-c", "100",
            "-t", "5",
            "--json"
        ]

        if oob_url:
            cmd.extend(["--oob", oob_url])

        return cmd

    async def run_go_ssrf_fuzzer(self, url: str, param: str, oob_url: str = None) -> Optional[Dict]:
        """
        Run the Go SSRF fuzzer for high-performance bypass testing.

        Returns:
            {
                "hits": [...],
                "metadata": {...}
            }
        """
        binary_path = settings.BASE_DIR / "bin" / "go-ssrf-fuzzer"

        if not binary_path.exists():
            logger.warning(f"Go SSRF fuzzer not found at {binary_path}")
            return None

        fuzz_url = self._build_fuzz_url(url, param)
        cmd = self._build_ssrf_command(binary_path, fuzz_url, oob_url)

        try:
            logger.info(f"Launching Go SSRF Fuzzer against {param} on {url}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)

            if process.returncode == 0:
                return _parse_tool_output(stdout.decode())
            else:
                logger.error(f"Go SSRF fuzzer failed: {stderr.decode()}")
                return None
        except Exception as e:
            logger.error(f"Go SSRF fuzzer error: {e}", exc_info=True)
            return None

    async def run_go_lfi_fuzzer(self, url: str, param: str, os_hint: str = "both") -> Optional[Dict]:
        """
        Run the Go LFI fuzzer for high-performance path traversal testing.
        
        Returns:
            {
                "hits": [...],
                "metadata": {...}
            }
        """
        binary_path = settings.BASE_DIR / "bin" / "go-lfi-fuzzer"
        
        if not binary_path.exists():
            logger.warning(f"Go LFI fuzzer not found at {binary_path}")
            return None
        
        fuzz_url = url
        if f"{param}=" in url:
            fuzz_url = re.sub(rf"([?&]{re.escape(param)})=([^&]*)", r"\1=FUZZ", url)
        else:
            separator = "&" if "?" in url else "?"
            fuzz_url = f"{url}{separator}{param}=FUZZ"
            
        cmd = [
            str(binary_path),
            "-u", fuzz_url,
            "-c", "100",
            "-t", "5",
            "--os", os_hint,
            "--json"
        ]
        
        try:
            logger.info(f"Launching Go LFI Fuzzer against {param} on {url}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            
            if process.returncode == 0:
                return _parse_tool_output(stdout.decode())
            else:
                logger.error(f"Go LFI fuzzer failed: {stderr.decode()}")
                return None
        except Exception as e:
            logger.error(f"Go LFI fuzzer error: {e}", exc_info=True)
            return None

    async def _run_go_fuzzer(
        self,
        binary_name: str,
        url: str,
        param: str,
        extra_args: List[str],
        timeout: int = 120
    ) -> Optional[Dict]:
        """Generic Go fuzzer execution helper."""
        binary_path = settings.BASE_DIR / "bin" / binary_name

        if not binary_path.exists():
            logger.warning(f"{binary_name} not found at {binary_path}")
            return None

        fuzz_url = self._build_fuzz_url(url, param)
        cmd = [str(binary_path), "-u", fuzz_url] + extra_args + ["--json"]

        try:
            logger.info(f"Launching {binary_name} against {param} on {url}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)

            if process.returncode == 0:
                return _parse_tool_output(stdout.decode())
            else:
                logger.error(f"{binary_name} failed: {stderr.decode()}")
                return None
        except Exception as e:
            logger.error(f"{binary_name} error: {e}", exc_info=True)
            return None

    async def run_go_idor_fuzzer(
        self,
        url: str,
        param: str,
        id_range: str = "1-100",
        baseline_id: str = "1",
        auth_header: str = None
    ) -> Optional[Dict]:
        """
        Run the Go IDOR fuzzer for high-performance ID enumeration.

        Returns:
            {
                "hits": [...],
                "metadata": {...}
            }
        """
        extra_args = ["-range", id_range, "-baseline", baseline_id, "-c", "200", "-t", "5"]
        if auth_header:
            extra_args.extend(["-H", auth_header])

        return await self._run_go_fuzzer("go-idor-fuzzer", url, param, extra_args, timeout=300)

