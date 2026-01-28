import shutil
import asyncio
import json
import re
import os
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse
from bugtrace.utils.logger import get_logger
logger = get_logger("tools.external")
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard

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


def _validate_docker_image(image: str) -> bool:
    """
    Validate Docker image against whitelist.

    Args:
        image: Docker image name with optional tag

    Returns:
        True if image is trusted, False otherwise
    """
    # Normalize image name (remove tag for comparison)
    base_image = image.split(':')[0] if ':' in image else image

    # Check exact match first
    if image in TRUSTED_DOCKER_IMAGES:
        return True

    # Check base image (without tag)
    if base_image in TRUSTED_DOCKER_IMAGES:
        return True

    # Check with :latest suffix
    if f"{base_image}:latest" in TRUSTED_DOCKER_IMAGES:
        return True

    logger.warning(f"Untrusted Docker image blocked: {image}")
    return False


# ANSI escape sequence pattern (TASK-113)
ANSI_ESCAPE_PATTERN = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def _sanitize_output(output: str) -> str:
    """
    Sanitize tool output by removing ANSI escape codes and control characters.

    Args:
        output: Raw tool output

    Returns:
        Sanitized output string
    """
    # Remove ANSI escape sequences
    sanitized = ANSI_ESCAPE_PATTERN.sub('', output)

    # Remove other control characters except newlines and tabs
    sanitized = ''.join(
        char for char in sanitized
        if char == '\n' or char == '\t' or (ord(char) >= 32 and ord(char) != 127)
    )

    return sanitized


def _check_json_depth(obj: Any, current_depth: int = 0) -> None:
    """Check JSON nesting depth to prevent DoS attacks."""
    if current_depth > MAX_JSON_DEPTH:
        raise ValueError(f"JSON depth exceeds maximum allowed ({MAX_JSON_DEPTH})")

    if isinstance(obj, dict):
        for value in obj.values():
            _check_json_depth(value, current_depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_json_depth(item, current_depth + 1)


def _parse_tool_output(output: str, max_size: int = MAX_JSON_SIZE) -> Dict:
    """
    Parse and validate tool output JSON securely.

    Args:
        output: Raw JSON string from tool
        max_size: Maximum allowed output size in bytes

    Returns:
        Parsed and validated dict

    Raises:
        ValueError: If output exceeds size limit or depth limit
        json.JSONDecodeError: If invalid JSON
    """
    if len(output) > max_size:
        raise ValueError(f"Tool output too large: {len(output)} bytes (max: {max_size})")

    try:
        data = json.loads(output)
        _check_json_depth(data)
        return data
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON from tool: {e}")
        raise

class ExternalToolManager:
    """
    Manages execution of external security tools via Docker.
    Ports capabilities from legacy tools/docker_manager.py
    """

    # Tool version tracking (TASK-115)
    TOOL_VERSIONS = {
        "nuclei": "projectdiscovery/nuclei:latest",
        "sqlmap": "googlesky/sqlmap:latest",
        "gospider": "trickest/gospider:latest",
    }

    def __init__(self):
        self.docker_cmd = self._find_docker()
        self._tool_run_counts: Dict[str, int] = {}
        self._tool_last_run: Dict[str, float] = {}
        
    def _find_docker(self) -> str:
        cmd = shutil.which("docker")
        if not cmd:
            logger.warning("Docker not found! External tools (Nuclei, SQLMap) will be disabled.")
            return ""
        return cmd

    def get_tool_info(self) -> Dict[str, Any]:
        """
        Get tool version and usage information (TASK-115).

        Returns:
            Dict with tool versions and run statistics
        """
        return {
            "versions": self.TOOL_VERSIONS.copy(),
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

    async def _run_container(
        self,
        image: str,
        command: List[str],
        timeout: int = 300,
        memory_limit: str = "512m",
        cpu_limit: str = "1.0",
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
            logger.error(f"Blocked execution of untrusted image: {image}")
            return ""

        full_cmd = [
            self.docker_cmd, "run", "--rm",
            # Resource limits (TASK-108)
            "--memory", memory_limit,
            "--cpus", cpu_limit,
            "--pids-limit", "100",
            # Security options
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--tmpfs", "/tmp:size=100m,mode=1777",
            # Network isolation (TASK-114)
            "--network", network_mode,
        ]
        full_cmd.append(image)
        full_cmd.extend(command)

        logger.debug(f"Docker Exec: {' '.join(full_cmd)}")

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Timeout handling (TASK-109)
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.error(f"Docker container timeout after {timeout}s: {image}")
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
                return ""

            if proc.returncode != 0:
                err = stderr.decode().strip()
                # SQLMap sometimes exits with non-zero on minor errors but still outputs findings
                if "sqlmap" not in image:
                    logger.error(f"Docker command failed (Code {proc.returncode}): {err if err else 'No stderr output'}")
                    return ""

            # Sanitize output (TASK-113)
            return _sanitize_output(stdout.decode())
        except Exception as e:
            logger.error(f"Docker subprocess error: {e}")
            return ""
        finally:
            # Ensure subprocess is properly cleaned up
            if proc is not None:
                try:
                    if proc.returncode is None:
                        proc.kill()
                        await proc.wait()
                except Exception:
                    pass

    async def run_nuclei(self, target: str, cookies: List[Dict] = None) -> List[Dict]:
        """
        Runs Nuclei scan on the target with optional session cookies.
        """
        if not self.docker_cmd: return []

        self._record_tool_run("nuclei")
        logger.info(f"Starting Nuclei Scan on {target}...")
        dashboard.log(f"[External] Launching Nuclei Engine against {target}", "INFO")
        dashboard.update_task("nuclei", name="Nuclei Engine", status=f"Scanning: {target}")
        
        # Nuclei args: -u target -silent -jsonl -severity critical,high
        cmd = [
            "-u", target,
            "-silent",
            "-jsonl",
            "-severity", "critical,high,medium,low,info"
        ]
        
        # Add Cookies if present
        if cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            cmd.extend(["-H", f"Cookie: {cookie_str}"])
            cmd.extend(["-H", "User-Agent: BugtraceAI/1.0"]) # Standard UA

        # Use projectdiscovery/nuclei image
        output = await self._run_container("projectdiscovery/nuclei:latest", cmd)
        
        findings = []
        for line in output.splitlines():
            try:
                if line.strip().startswith("{"):
                    findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
                
        logger.info(f"Nuclei found {len(findings)} issues.")
        if len(findings) > 0:
            dashboard.log(f"[External] Nuclei found {len(findings)} vulnerabilities.", "SUCCESS")
        return findings

    async def run_sqlmap(self, url: str, cookies: List[Dict] = None, target_param: str = None) -> Optional[Dict]:
        """
        Runs SQLMap active scan with session context on specific URL/Param.
        AVOIDS redundant crawling by targeting specific parameters found by GoSpider.
        """
        if not self.docker_cmd: return None

        self._record_tool_run("sqlmap")
        target_info = f"param '{target_param}' on {url}" if target_param else url
        logger.info(f"Starting SQLMap Scan on {target_info}...")
        dashboard.log(f"[External] Launching SQLMap (Sniper Mode) against {target_info}", "INFO")
        
        # SQLMap args: -u URL --batch ...
        # Improved: technique=BEUSTQ (All), level=2, risk=2 (Balanced)
        reproduction_cmd = f"sqlmap -u '{url}' --batch --random-agent --technique=BEUSTQ --level 2 --risk 2"
        
        cmd = [
            "-u", url,
            "--batch",
            "--random-agent",
            "--technique=BEUSTQ",
            "--level", "2",
            "--risk", "2",
            "--parse-errors", # Help catch error-based
            "--flush-session",
            "--output-dir=/tmp"
        ]
        
        if target_param:
            cmd.extend(["-p", target_param])
            reproduction_cmd += f" -p {target_param}"
            # Disable forms searching if we target a param (strict mode)
            cmd.append("--skip-urlencoding")
        else:
            # Only if no param is known do we enable forms
            cmd.append("--forms")
            reproduction_cmd += " --forms"
        
        if cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            cmd.append(f"--cookie={cookie_str}")
            reproduction_cmd += f" --cookie='{cookie_str}'"
        
        # Use googlesky/sqlmap image (community maintained)
        output = await self._run_container("googlesky/sqlmap:latest", cmd)
        
        # Robust Parsing using Regex
        param_match = re.search(r"Parameter:\s+(.+?)\s+\(", output)
        type_match = re.search(r"Type:\s+(.+?)\s", output)
        
        is_vulnerable = bool(param_match and type_match)
        
        if is_vulnerable:
            param = param_match.group(1)
            vuln_type = type_match.group(1)
            msg = f"SQLMap Confirmed: {vuln_type} on parameter '{param}'"
            
            return {
                "vulnerable": True,
                "parameter": param,
                "type": vuln_type,
                "reproduction_command": reproduction_cmd,
                "output_snippet": output[:1000] # Capture first 1000 chars of output for evidence
            }
        return None

    async def run_gospider(self, url: str, cookies: List[Dict] = None, depth: int = 3) -> List[str]:
        """
        Runs GoSpider to crawl the target with session.

        Args:
            url: Target URL to crawl
            cookies: Optional session cookies
            depth: Crawl depth (default 3 to find parameterized URLs)
        """
        if not self.docker_cmd: return []

        self._record_tool_run("gospider")
        logger.info(f"Starting GoSpider on {url} (depth={depth})...")
        dashboard.log(f"[External] Launching GoSpider (depth={depth}) against {url}", "INFO")
        dashboard.update_task("gospider", name="GoSpider", status=f"Crawling: {url}")
        
        # GoSpider args: -s URL -d DEPTH -c 10
        cmd = [
            "-s", url,
            "-d", str(depth),
            "-c", "10"
        ]
        
        if cookies:
             cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
             cmd.extend(["--cookie", cookie_str])

        # Use trickest/gospider image
        output = await self._run_container("trickest/gospider", cmd)
        
        urls = []
        target_domain = urlparse(url).hostname.lower()
        logger.info(f"GoSpider raw output (first 10 lines):\n{chr(10).join(output.splitlines()[:10])}")
        
        for line in output.splitlines():
            # GoSpider output can be:
            # [url] - [200] - [type]
            # [type] - [url]
            # or just a URL
            parts = line.replace("[", "").replace("]", "").split(" - ")
            for p in parts:
                p = p.strip()
                if p.startswith("http"):
                    try:
                        parsed = urlparse(p)
                        url_host = (parsed.hostname or "").lower()
                        if url_host == target_domain or url_host.endswith("." + target_domain):
                            urls.append(p)
                    except Exception as e:
                        logger.debug(f"URL parsing error in GoSpider output: {e}")
                        continue
                    
        unique_urls = list(set(urls))
        logger.info(f"GoSpider found {len(unique_urls)} in-scope URLs out of {len(output.splitlines())} total lines.")
        dashboard.log(f"[External] GoSpider discovered {len(unique_urls)} in-scope endpoints.", "INFO")
        return unique_urls

    async def run_go_xss_fuzzer(self, url: str, param: str, payloads: List[str] = None) -> Optional[Dict]:
        """
        Run the Go XSS fuzzer for high-performance payload testing.
        
        Returns:
            {
                "reflections": [...],
                "metadata": {...}
            }
        """
        # Binary is in the root bin/ directory (relative to project root)
        binary_path = settings.BASE_DIR / "bin" / "go-xss-fuzzer"
        
        if not binary_path.exists():
            logger.warning(f"Go XSS fuzzer not found at {binary_path}, falling back to Python")
            return None
        
        # Build URL with FUZZ marker
        # We need to be careful with existing query params. 
        # The simplest way is to replace 'param=value' with 'param=FUZZ'
        fuzz_url = url
        if f"{param}=" in url:
            # Replace the parameter value with FUZZ
            # Handle cases like ?q=val&p=val or ?q=val
            fuzz_url = re.sub(rf"([?&]{re.escape(param)})=([^&]*)", r"\1=FUZZ", url)
        else:
            # Fallback: append if not found (though it should be there)
            separator = "&" if "?" in url else "?"
            fuzz_url = f"{url}{separator}{param}=FUZZ"
            
        cmd = [
            str(binary_path),
            "-u", fuzz_url,
            "-c", "100",       # 100 concurrent goroutines
            "-t", "5",         # 5 second timeout
            "--json"
        ]
        
        payloads_file = None
        try:
            if payloads:
                # Write payloads to temp file with secure handling
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    f.write("\n".join(payloads))
                    payloads_file = f.name
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
            logger.error(f"Go XSS fuzzer error: {e}")
            return None
        finally:
            # Secure cleanup - always runs
            if payloads_file and os.path.exists(payloads_file):
                try:
                    os.unlink(payloads_file)
                except OSError:
                    logger.warning(f"Failed to cleanup temp file: {payloads_file}")

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
            "--json"
        ]
        
        if oob_url:
            cmd.extend(["--oob", oob_url])
        
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
            logger.error(f"Go SSRF fuzzer error: {e}")
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
            logger.error(f"Go LFI fuzzer error: {e}")
            return None

    async def run_go_idor_fuzzer(self, url: str, param: str, id_range: str = "1-100", 
                                 baseline_id: str = "1", auth_header: str = None) -> Optional[Dict]:
        """
        Run the Go IDOR fuzzer for high-performance ID enumeration.
        
        Returns:
            {
                "hits": [...],
                "metadata": {...}
            }
        """
        binary_path = settings.BASE_DIR / "bin" / "go-idor-fuzzer"
        
        if not binary_path.exists():
            logger.warning(f"Go IDOR fuzzer not found at {binary_path}")
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
            "-range", id_range,
            "-baseline", baseline_id,
            "-c", "200",
            "-t", "5",
            "--json"
        ]
        
        if auth_header:
            cmd.extend(["-H", auth_header])
        
        try:
            logger.info(f"Launching Go IDOR Fuzzer against {param} on {url} (Range: {id_range})")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            
            if process.returncode == 0:
                return _parse_tool_output(stdout.decode())
            else:
                logger.error(f"Go IDOR fuzzer failed: {stderr.decode()}")
                return None
        except Exception as e:
            logger.error(f"Go IDOR fuzzer error: {e}")
            return None

external_tools = ExternalToolManager()
