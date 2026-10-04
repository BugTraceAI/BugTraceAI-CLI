"""External security tools facade (Docker / native binaries).

Split: external_util, external_gospider, external_fuzzers, external_sqlmap.
"""

import shutil
import asyncio
import json
import re
import os
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin
from bugtrace.utils.logger import get_logger
from bugtrace.utils.parsers import extract_sqlmap_verdict
logger = get_logger("tools.external")
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.exceptions import (
    ToolError,
    DockerError,
    DockerTimeoutError,
    DockerNotFoundError,
    SubprocessError,
    FuzzerError,
    FuzzerTimeoutError,
    NucleiError,
    JSONParseError,
)

# Security constants for JSON parsing
MAX_JSON_SIZE = 10_000_000  # 10MB max
MAX_JSON_DEPTH = 20

# Whitelist of trusted Docker images (TASK-111)
TRUSTED_DOCKER_IMAGES = frozenset({
    "projectdiscovery/nuclei:latest",
    "projectdiscovery/nuclei",
    "googlesky/sqlmap:latest",
    "googlesky/sqlmap",
    "trickest/gospider",
    "trickest/gospider:latest",
})



from bugtrace.tools.external_util import *  # re-export helpers/constants
# import * skips leading-underscore names — pull the private helpers explicitly
from bugtrace.tools.external_util import (
    _sanitize_output,
    _validate_docker_image,
    ANSI_ESCAPE_PATTERN,
    TRUSTED_DOCKER_IMAGES,
    MAX_JSON_SIZE,
    MAX_JSON_DEPTH,
)
from bugtrace.tools.external_gospider import ExternalGospiderMixin
from bugtrace.tools.external_fuzzers import ExternalFuzzersMixin
from bugtrace.tools.external_sqlmap import ExternalSqlmapMixin

class ExternalToolManager(ExternalGospiderMixin, ExternalFuzzersMixin, ExternalSqlmapMixin):
    """
    Manages execution of external security tools.
    Prefers native binaries (fastest), falls back to Docker execution.
    """

    # Tool version tracking (TASK-115)
    TOOL_VERSIONS = {
        "nuclei": "projectdiscovery/nuclei:latest",
        "sqlmap": "googlesky/sqlmap:latest",
        "gospider": "trickest/gospider:latest",
    }

    def __init__(self):
        self.docker_cmd = self._find_docker()
        self._native_tools = self._detect_native_tools()
        self._tool_run_counts: Dict[str, int] = {}
        self._tool_last_run: Dict[str, float] = {}

    def _find_docker(self) -> str:
        cmd = shutil.which("docker")
        if not cmd:
            logger.info("Docker CLI not found (native tools will be preferred if available)")
            return ""
        return cmd

    def _detect_native_tools(self) -> Dict[str, str]:
        """Detect natively installed security tools (preferred over Docker)."""
        tools = {}
        for name in ("nuclei", "sqlmap", "gospider"):
            path = shutil.which(name)
            if path:
                tools[name] = path
                logger.info(f"Native tool available: {name} -> {path}")

        if tools:
            logger.info(f"Native tools: {', '.join(tools.keys())} (preferred over Docker)")
        if not tools and not self.docker_cmd:
            logger.warning("No native tools and no Docker — external scanning disabled")

        return tools

    def get_tool_info(self) -> Dict[str, Any]:
        """
        Get tool version and usage information (TASK-115).

        Returns:
            Dict with tool versions and run statistics
        """
        return {
            "versions": self.TOOL_VERSIONS.copy(),
            "native_tools": {k: True for k in self._native_tools},
            "run_counts": self._tool_run_counts.copy(),
            "last_run": self._tool_last_run.copy(),
            "docker_available": bool(self.docker_cmd),
        }

    def _record_tool_run(self, tool_name: str) -> None:
        """
        Record a tool execution for metrics tracking (TASK-116).

        Args:
            tool_name: Name of the tool being run
        """
        import time as time_module
        self._tool_run_counts[tool_name] = self._tool_run_counts.get(tool_name, 0) + 1
        self._tool_last_run[tool_name] = time_module.time()
        logger.debug(f"Tool '{tool_name}' run #{self._tool_run_counts[tool_name]}")

    async def _run_native(
        self,
        tool_name: str,
        command: List[str],
        timeout: int = 300,
        tolerate_nonzero: bool = False,
    ) -> str:
        """
        Run a tool natively via subprocess (no Docker overhead).

        Args:
            tool_name: Tool name for logging
            command: Full command list [binary_path, arg1, arg2, ...]
            timeout: Maximum execution time in seconds
            tolerate_nonzero: If True, return output even on non-zero exit
        """
        logger.debug(f"Native Exec [{tool_name}]: {' '.join(command[:8])}...")
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )

            if proc.returncode != 0 and not tolerate_nonzero:
                err = stderr.decode().strip()
                logger.error(
                    f"Native {tool_name} failed (code {proc.returncode}): "
                    f"{err[:500] if err else 'no stderr'}"
                )
                return ""

            return _sanitize_output(stdout.decode())
        except asyncio.TimeoutError:
            if proc and proc.returncode is None:
                proc.kill()
                await proc.wait()
            logger.error(f"Native {tool_name} timeout after {timeout}s")
            raise SubprocessError(
                f"Native {tool_name} timed out after {timeout}s",
                tool_name=tool_name,
                timeout_seconds=timeout,
            )
        except SubprocessError:
            raise
        except Exception as e:
            logger.error(f"Native {tool_name} error: {e}", exc_info=True)
            return ""

    async def _run_native_with_limit(
        self,
        tool_name: str,
        command: List[str],
        line_limit: int,
        timeout: int = 600,
    ) -> str:
        """Run a native tool with streaming output, kill after N lines."""
        logger.debug(f"Native Streaming [{tool_name}]: limit={line_limit} lines")
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        output_lines = []
        try:
            while len(output_lines) < line_limit:
                try:
                    line_bytes = await asyncio.wait_for(
                        process.stdout.readline(), timeout=30
                    )
                    if not line_bytes:
                        break
                    output_lines.append(line_bytes.decode("utf-8", errors="replace"))
                except asyncio.TimeoutError:
                    if output_lines:
                        break
                    raise

            if len(output_lines) >= line_limit:
                logger.info(f"{tool_name} limit reached ({line_limit} lines). Terminating...")
                try:
                    process.kill()
                except (ProcessLookupError, OSError):
                    pass
        except Exception as e:
            logger.error(f"Native streaming {tool_name} error: {e}")
            try:
                process.kill()
            except (ProcessLookupError, OSError):
                pass

        try:
            if process.returncode is None:
                process.kill()
                await process.wait()
        except Exception:
            pass

        return "".join(output_lines)

    def _build_docker_command(
        self,
        image: str,
        command: List[str],
        memory_limit: str,
        cpu_limit: str,
        network_mode: str
    ) -> List[str]:
        """Build Docker command with security constraints."""
        full_cmd = [
            self.docker_cmd, "run", "--rm",
            # Resource limits (TASK-108)
            "--memory", memory_limit,
            "--cpus", cpu_limit,
            "--pids-limit", "100",
            # Security options
            "--security-opt", "no-new-privileges",
            # Note: --read-only removed - Nuclei needs write access to /root/.config
            # for templates download and config storage
            "--tmpfs", "/tmp:size=100m,mode=1777",
            # Network isolation (TASK-114)
            "--network", network_mode,
        ]
        full_cmd.append(image)
        full_cmd.extend(command)
        return full_cmd

    async def _execute_docker_process(
        self,
        cmd: List[str],
        timeout: int
    ) -> tuple[asyncio.subprocess.Process, bytes, bytes]:
        """Execute Docker process with timeout handling."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )
            return proc, stdout, stderr
        except asyncio.TimeoutError:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            raise

    def _handle_docker_exit_code(self, returncode: int, stderr: bytes, image: str) -> bool:
        """
        Check if Docker exit code indicates failure.
        Returns True if execution should continue, False if should abort.
        """
        if returncode == 0:
            return True

        err = stderr.decode().strip()
        # SQLMap sometimes exits with non-zero on minor errors but still outputs findings
        if "sqlmap" not in image:
            logger.error(f"Docker command failed (Code {returncode}): {err if err else 'No stderr output'}")
            return False
        return True

    async def _cleanup_docker_process(self, proc: asyncio.subprocess.Process) -> None:
        """Ensure Docker subprocess is properly cleaned up."""
        if proc is not None:
            try:
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
            except Exception as e:
                logger.debug(f"Process cleanup failed: {e}")

    async def _run_container(
        self,
        image: str,
        command: List[str],
        timeout: int = 300,
        memory_limit: str = "2048m",
        cpu_limit: str = "2.0",
        network_mode: str = "bridge"
    ) -> str:
        """
        Runs a docker container with security constraints and returns output.

        Args:
            image: Docker image name
            command: Command arguments for the container
            timeout: Maximum execution time in seconds (default 5 min)
            memory_limit: Memory limit (default 512MB)
            cpu_limit: CPU limit (default 1 core)
            network_mode: Network mode - 'bridge' (isolated) or 'host'
        """
        if not self.docker_cmd:
            return ""

        # Validate image against whitelist (TASK-111)
        if not _validate_docker_image(image):
            logger.error(f"Blocked execution of untrusted image: {image}", exc_info=True)
            return ""

        full_cmd = self._build_docker_command(image, command, memory_limit, cpu_limit, network_mode)
        logger.debug(f"Docker Exec: {' '.join(full_cmd)}")

        proc = None
        try:
            proc, stdout, stderr = await self._execute_docker_process(full_cmd, timeout)

            if not self._handle_docker_exit_code(proc.returncode, stderr, image):
                return ""

            return _sanitize_output(stdout.decode())
        except asyncio.TimeoutError as e:
            # Transient: Container timed out - may succeed with longer timeout
            logger.error(f"Docker container timeout after {timeout}s: {image}")
            raise DockerTimeoutError(
                f"Docker container timed out after {timeout}s",
                tool_name=image,
                timeout_seconds=timeout
            ) from e
        except DockerError:
            # Re-raise typed Docker exceptions
            raise
        except Exception as e:
            # Unexpected error - wrap in DockerError
            logger.error(f"Docker subprocess error: {e}", exc_info=True)
            raise DockerError(
                f"Docker execution failed: {e}",
                tool_name=image,
                cause=e
            ) from e
        finally:
            await self._cleanup_docker_process(proc)

    async def _exec_tool(self, tool_name: str, docker_image: str, cmd: List[str], **kwargs) -> str:
        """Execute tool via native binary (preferred) or Docker (fallback)."""
        native = self._native_tools.get(tool_name)
        if native:
            return await self._run_native(tool_name, [native] + cmd, **kwargs)
        return await self._run_container(docker_image, cmd, **kwargs)

    async def run_nuclei(
        self,
        target: str,
        cookies: List[Dict] = None,
        headers: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """
        Runs three-phase Nuclei scan (native preferred, Docker fallback):
        1. Tech Detection (-tags tech,misconfig,exposure,token)
        2. Deterministic Scan (fixed -tags) — guaranteed floor, same tags every run
        3. Automatic Scan (-as) — opportunistic re-fishing on top of the floor

        Returns:
            Dict with 'tech_findings' and 'vuln_findings' (vulns deduped across 2/3)
        """
        native = self._native_tools.get("nuclei")
        if not native and not self.docker_cmd:
            return {"tech_findings": [], "vuln_findings": []}

        self._record_tool_run("nuclei")
        mode = "native" if native else "Docker"
        logger.info(f"Starting Three-Phase Nuclei Scan on {target} ({mode})...")
        dashboard.log(f"[External] Launching Nuclei Engine ({mode}) against {target}", "INFO")

        cookie_header = None
        if cookies:
            cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in cookies])

        request_headers = dict(headers or {})
        if cookie_header:
            request_headers["Cookie"] = cookie_header

        def add_request_headers(command: List[str]) -> None:
            for name, value in request_headers.items():
                command.extend(["-H", f"{name}: {value}"])

        # === PHASE 1: Tech Detection ===
        dashboard.update_task("nuclei", name="Nuclei Tech-Detect", status="Phase 1/3: Tech Detection")

        tech_cmd = ["-u", target, "-tags", "tech,misconfig,exposure,token", "-silent", "-jsonl"]
        add_request_headers(tech_cmd)

        tech_output = await self._exec_tool("nuclei", "projectdiscovery/nuclei:latest", tech_cmd)
        tech_findings = self._parse_nuclei_jsonl(tech_output)

        logger.info(f"[Nuclei] Phase 1: {len(tech_findings)} tech/infrastructure detections")
        dashboard.log(f"[External] Tech-Detect: {len(tech_findings)} technologies identified", "INFO")

        # === PHASE 2: Deterministic Scan (the floor) ===
        dashboard.update_task(
            "nuclei", name="Nuclei Deterministic Scan", status="Phase 2/3: Deterministic Vulnerability Scan"
        )

        deterministic_cmd = [
            "-u", target,
            "-tags", "cves,vulnerabilities,exposures,misconfig,technologies,default-login",
            "-silent", "-jsonl",
        ]
        add_request_headers(deterministic_cmd)
        if request_headers:
            deterministic_cmd.extend(["-H", "User-Agent: BugtraceAI/1.0"])

        deterministic_output = await self._exec_tool(
            "nuclei", "projectdiscovery/nuclei:latest", deterministic_cmd
        )
        deterministic_findings = self._parse_nuclei_jsonl(deterministic_output)

        logger.info(
            f"[Nuclei] Phase 2: {len(deterministic_findings)} deterministic vulnerability detections"
        )
        dashboard.log(
            f"[External] Deterministic Scan: {len(deterministic_findings)} findings", "INFO"
        )

        # === PHASE 3: Automatic Scan (opportunistic re-fishing) ===
        dashboard.update_task(
            "nuclei", name="Nuclei Auto-Scan", status="Phase 3/3: Automatic Re-fishing"
        )

        auto_cmd = ["-u", target, "-as", "-silent", "-jsonl"]
        add_request_headers(auto_cmd)
        if request_headers:
            auto_cmd.extend(["-H", "User-Agent: BugtraceAI/1.0"])

        auto_output = await self._exec_tool("nuclei", "projectdiscovery/nuclei:latest", auto_cmd)
        auto_findings = self._parse_nuclei_jsonl(auto_output)

        logger.info(f"[Nuclei] Phase 3: {len(auto_findings)} auto-scan vulnerability detections")

        from bugtrace.tools.nuclei_results import is_nuclei_infrastructure_finding

        # Technology/WAF templates can also appear in automatic scans. They are
        # useful recon context, but never vulnerability findings.
        vuln_findings = [
            finding
            for finding in self._dedupe_nuclei_findings(
                deterministic_findings + auto_findings
            )
            if not is_nuclei_infrastructure_finding(finding)
        ]

        total_findings = len(tech_findings) + len(vuln_findings)
        if total_findings > 0:
            dashboard.log(
                f"[External] Nuclei Complete: {len(tech_findings)} tech + {len(vuln_findings)} vulns",
                "SUCCESS",
            )

        return {
            "tech_findings": tech_findings,
            "vuln_findings": vuln_findings,
        }

    @staticmethod
    def _parse_nuclei_jsonl(output: str) -> List[Dict[str, Any]]:
        """Parse Nuclei -jsonl output into finding dicts, skipping bad lines."""
        findings = []
        for line in (output or "").splitlines():
            try:
                if line.strip().startswith("{"):
                    findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return findings

    @staticmethod
    def _dedupe_nuclei_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Dedup by (template-id, matched-at) across deterministic + auto phases."""
        seen = set()
        deduped = []
        for finding in findings or []:
            key = (finding.get("template-id"), finding.get("matched-at") or finding.get("host"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped

    async def _run_container_with_limit(
        self,
        image: str,
        command: List[str],
        line_limit: int,
        timeout: int = 600
    ) -> str:
        """
        Runs a Docker container and KILLS it after N lines of output.
        Used for optimization (stop crawling when we have enough URLs).
        """
        if not self.docker_cmd or not _validate_docker_image(image):
            return ""

        full_cmd = self._build_docker_command(image, command, "512m", "1.0", "bridge")
        logger.debug(f"Docker Streaming Exec: {' '.join(full_cmd)}")

        process = await asyncio.create_subprocess_exec(
            *full_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        output_lines = []
        try:
            # Read line by line until limit or EOF
            while len(output_lines) < line_limit:
                try:
                    line_bytes = await asyncio.wait_for(process.stdout.readline(), timeout=30)
                    if not line_bytes:
                        break # EOF
                    line = line_bytes.decode('utf-8', errors='replace')
                    output_lines.append(line)
                except asyncio.TimeoutError:
                    if len(output_lines) > 0:
                        break # Stop if it hangs but we have data
                    else:
                        raise # Real timeout
            
            # If we reached limit, kill process
            if len(output_lines) >= line_limit:
                logger.info(f"GoSpider limit reached ({line_limit} lines). Terminating crawler...")
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                except OSError as e:
                    logger.debug(f"Process cleanup error: {e}")

        except Exception as e:
            logger.error(f"Streaming execution failed: {e}")
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except OSError as e:
                logger.debug(f"Process cleanup error: {e}")
        
        # Ensure cleanup
        await self._cleanup_docker_process(process)
        
        return "".join(output_lines)

external_tools = ExternalToolManager()
