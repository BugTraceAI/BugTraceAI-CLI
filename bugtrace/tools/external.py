import shutil
import asyncio
import json
import re
import os
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin
from bugtrace.utils.logger import get_logger
logger = get_logger("tools.external")
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.http_orchestrator import orchestrator, DestinationType

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
        logger.error(f"Invalid JSON from tool: {e}", exc_info=True)
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
            "--read-only",
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
        except asyncio.TimeoutError:
            logger.error(f"Docker container timeout after {timeout}s: {image}", exc_info=True)
            return ""
        except Exception as e:
            logger.error(f"Docker subprocess error: {e}", exc_info=True)
            return ""
        finally:
            await self._cleanup_docker_process(proc)

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

    def _build_sqlmap_command(
        self,
        url: str,
        target_param: Optional[str],
        cookies: Optional[List[Dict]]
    ) -> tuple[List[str], str]:
        """Build SQLMap command and reproduction command."""
        reproduction_cmd = f"sqlmap -u '{url}' --batch --random-agent --technique=BEUSTQ --level 2 --risk 2"

        cmd = [
            "-u", url,
            "--batch",
            "--random-agent",
            "--technique=BEUSTQ",
            "--level", "2",
            "--risk", "2",
            "--parse-errors",
            "--flush-session",
            "--output-dir=/tmp"
        ]

        if target_param:
            cmd.extend(["-p", target_param])
            reproduction_cmd += f" -p {target_param}"
            cmd.append("--skip-urlencoding")
        else:
            cmd.append("--forms")
            reproduction_cmd += " --forms"

        if cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            cmd.append(f"--cookie={cookie_str}")
            reproduction_cmd += f" --cookie='{cookie_str}'"

        return cmd, reproduction_cmd

    def _parse_sqlmap_output(self, output: str) -> Optional[tuple[str, str]]:
        """Parse SQLMap output for vulnerability detection."""
        param_match = re.search(r"Parameter:\s+(.+?)\s+\(", output)
        type_match = re.search(r"Type:\s+(.+?)\s", output)

        if param_match and type_match:
            return param_match.group(1), type_match.group(1)
        return None

    async def run_sqlmap(self, url: str, cookies: List[Dict] = None, target_param: str = None) -> Optional[Dict]:
        """
        Runs SQLMap active scan with session context on specific URL/Param.
        AVOIDS redundant crawling by targeting specific parameters found by GoSpider.
        """
        if not self.docker_cmd:
            return None

        self._record_tool_run("sqlmap")
        target_info = f"param '{target_param}' on {url}" if target_param else url
        logger.info(f"Starting SQLMap Scan on {target_info}...")
        dashboard.log(f"[External] Launching SQLMap (Sniper Mode) against {target_info}", "INFO")

        cmd, reproduction_cmd = self._build_sqlmap_command(url, target_param, cookies)
        output = await self._run_container("googlesky/sqlmap:latest", cmd)

        result = self._parse_sqlmap_output(output)
        if result:
            param, vuln_type = result
            return {
                "vulnerable": True,
                "parameter": param,
                "type": vuln_type,
                "reproduction_command": reproduction_cmd,
                "output_snippet": output[:1000]
            }
        return None

    def _parse_gospider_urls(self, output: str, target_domain: str) -> Tuple[List[str], List[str]]:
        """
        Parse URLs from GoSpider output, filtering to target domain.

        Returns:
            Tuple of (all_urls, form_urls) - form_urls need parameter extraction
        """
        urls = []
        form_urls = []

        for line in output.splitlines():
            line = line.strip()

            # Detect line type BEFORE stripping brackets
            is_form = line.startswith("[form]")

            # Extract URL from line
            parts = line.replace("[", "").replace("]", "").split(" - ")
            extracted = self._extract_urls_from_parts(parts, target_domain)

            urls.extend(extracted)

            # Track form URLs separately for parameter extraction
            if is_form:
                form_urls.extend(extracted)

        return list(set(urls)), list(set(form_urls))

    def _extract_urls_from_parts(self, parts: list, target_domain: str) -> list:
        """Extract in-scope URLs from line parts."""
        urls = []
        for p in parts:
            p = p.strip()
            if not p.startswith("http"):
                continue

            url = self._parse_url_if_in_scope(p, target_domain)
            if url:
                urls.append(url)
        return urls

    def _parse_url_if_in_scope(self, url: str, target_domain: str) -> str:
        """Parse URL and return it if in scope, otherwise None."""
        try:
            parsed = urlparse(url)
            url_host = (parsed.hostname or "").lower()
            if url_host == target_domain or url_host.endswith("." + target_domain):
                return url
        except Exception as e:
            logger.debug(f"URL parsing error in GoSpider output: {e}")
        return None

    async def run_gospider(self, url: str, cookies: List[Dict] = None, depth: int = 3) -> List[str]:
        """
        Runs GoSpider to crawl the target with session.

        Args:
            url: Target URL to crawl
            cookies: Optional session cookies
            depth: Crawl depth (default 3 to find parameterized URLs)
        """
        if not self.docker_cmd:
            return []

        self._record_tool_run("gospider")
        logger.info(f"Starting GoSpider on {url} (depth={depth})...")
        dashboard.log(f"[External] Launching GoSpider (depth={depth}) against {url}", "INFO")
        dashboard.update_task("gospider", name="GoSpider", status=f"Crawling: {url}")

        # IMPROVED 2026-01-30: Use GoSpider's full power
        # -a: Query Wayback Machine, CommonCrawl, VirusTotal, AlienVault for historical URLs
        # --sitemap: Parse sitemap.xml for additional URLs
        # --robots: Parse robots.txt (enabled by default)
        # --js: Extract links from JavaScript (enabled by default)
        cmd = [
            "-s", url,
            "-d", str(depth),
            "-c", "10",
            "-a",           # OTHER SOURCES: Wayback, CommonCrawl, VirusTotal, AlienVault
            "--sitemap",    # Parse sitemap.xml
        ]

        if cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            cmd.extend(["--cookie", cookie_str])

        # Optional: Don't follow redirects to catch .env, .htaccess, .git/config leaks
        # When a sensitive file redirects to 403/404, the original response may contain info
        from bugtrace.core.config import settings
        if settings.GOSPIDER_NO_REDIRECT:
            cmd.append("--no-redirect")
            logger.info("[GoSpider] No-redirect mode enabled (catching redirect leaks)")

        output = await self._run_container("trickest/gospider", cmd)

        target_domain = urlparse(url).hostname.lower()
        logger.info(f"GoSpider raw output (first 10 lines):\n{chr(10).join(output.splitlines()[:10])}")

        # Parse URLs AND identify forms (IMPROVED 2026-01-30)
        unique_urls, form_urls = self._parse_gospider_urls(output, target_domain)
        logger.info(f"GoSpider found {len(unique_urls)} in-scope URLs, {len(form_urls)} forms.")

        # Extract parameters from forms (CRITICAL for CSTI, SQLi detection)
        if form_urls:
            logger.info(f"[GoSpider] Extracting parameters from {len(form_urls)} forms...")
            param_urls = await self._extract_form_params(form_urls, cookies)
            if param_urls:
                logger.info(f"[GoSpider] Extracted {len(param_urls)} parameterized URLs from forms")
                unique_urls = list(set(unique_urls + param_urls))

        dashboard.log(f"[External] GoSpider discovered {len(unique_urls)} endpoints (including form params).", "INFO")
        return unique_urls

    async def _extract_form_params(self, form_urls: List[str], cookies: List[Dict] = None) -> List[str]:
        """
        Fetch form URLs and extract input names to build parameterized URLs.

        This is CRITICAL for discovering vulnerabilities like:
        - /blog?search=X (CSTI)
        - /catalog?category=X (SQLi, CSTI)
        - /login?username=X (SQLi)

        Extracts from:
        1. HTML forms (<input name="...">)
        2. Inline JavaScript (URLs with query params in JS objects/strings)

        Args:
            form_urls: List of URLs where GoSpider detected forms
            cookies: Optional session cookies

        Returns:
            List of URLs with discovered parameters (e.g., /blog?search=FUZZ)
        """
        from bs4 import BeautifulSoup

        param_urls = []
        headers = {"User-Agent": settings.USER_AGENT}

        # Build cookie header if provided
        cookie_header = None
        if cookies:
            cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in cookies])

        async with orchestrator.session(DestinationType.TARGET) as session:
            for form_url in form_urls:
                try:
                    req_headers = headers.copy()
                    if cookie_header:
                        req_headers["Cookie"] = cookie_header

                    async with session.get(form_url, headers=req_headers, ssl=False) as resp:
                        if resp.status != 200:
                            continue

                        html = await resp.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        base_domain = urlparse(form_url).hostname

                        # 1. Extract from HTML forms
                        for form in soup.find_all('form'):
                            action = form.get('action', '')
                            method = form.get('method', 'GET').upper()

                            # Build form action URL
                            if action:
                                action_url = urljoin(form_url, action)
                            else:
                                action_url = form_url

                            # Ensure action URL is in scope
                            action_domain = urlparse(action_url).hostname
                            if action_domain and action_domain != base_domain:
                                continue

                            # Extract all input elements
                            inputs = form.find_all(['input', 'textarea', 'select'])
                            for inp in inputs:
                                name = inp.get('name')
                                inp_type = inp.get('type', 'text').lower()

                                # Skip hidden tokens, CSRF, submit buttons
                                if not name:
                                    continue
                                if inp_type in ('hidden', 'submit', 'button', 'image', 'reset'):
                                    continue
                                if name.lower() in ('csrf', 'token', '_token', 'csrfmiddlewaretoken'):
                                    continue

                                # Build URL with parameter
                                separator = "&" if "?" in action_url else "?"
                                param_url = f"{action_url}{separator}{name}=FUZZ"
                                param_urls.append(param_url)
                                logger.debug(f"[GoSpider] Found form param: {name} at {action_url}")

                        # 2. Extract URLs with params from inline JavaScript
                        # This catches dynamic navigation like: {"/catalog?category=Gin"}
                        js_param_urls = self._extract_js_urls(html, form_url, base_domain)
                        param_urls.extend(js_param_urls)

                except Exception as e:
                    logger.debug(f"[GoSpider] Failed to extract form params from {form_url}: {e}")

        return list(set(param_urls))

    def _extract_js_urls(self, html: str, base_url: str, base_domain: str) -> List[str]:
        """
        Extract URLs with query parameters from inline JavaScript.

        Catches patterns like:
        - "/catalog?category=Accessories"
        - '/blog?search=' + query
        - href="/page?param=value"

        Args:
            html: Page HTML content
            base_url: Base URL for resolving relative paths
            base_domain: Domain for scope checking

        Returns:
            List of discovered parameterized URLs
        """
        urls = []

        # Pattern to find URLs with query params in JS strings
        # Matches: "/path?param=value" or '/path?param=value'
        js_url_pattern = re.compile(r'["\'](/[^"\']*\?[^"\']+)["\']')

        for match in js_url_pattern.finditer(html):
            relative_url = match.group(1)
            try:
                full_url = urljoin(base_url, relative_url)
                url_domain = urlparse(full_url).hostname

                # Check scope
                if url_domain == base_domain:
                    urls.append(full_url)
                    logger.debug(f"[GoSpider] Found JS URL with params: {full_url}")
            except Exception:
                pass

        return urls

    def _build_fuzz_url(self, url: str, param: str) -> str:
        """Build URL with FUZZ marker replacing parameter value."""
        if f"{param}=" in url:
            return re.sub(rf"([?&]{re.escape(param)})=([^&]*)", r"\1=FUZZ", url)
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

external_tools = ExternalToolManager()
