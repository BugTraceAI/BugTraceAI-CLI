import asyncio
from typing import Dict, List, Any, Optional
from pathlib import Path
from loguru import logger

from bugtrace.core.llm_client import llm_client
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.utils.parsers import XmlParser
from bugtrace.core.event_bus import event_bus, EventType

from bugtrace.agents.base import BaseAgent

class DASTySASTAgent(BaseAgent):
    """
    DAST + SAST Analysis Agent.
    Performs 5-approach analysis on a URL to identify potential vulnerabilities.
    Phase 2 (Part A) of the Sequential Pipeline.
    """
    
    def __init__(self, url: str, tech_profile: Dict, report_dir: Path, state_manager: Any = None, scan_context: str = None):
        super().__init__("DASTySASTAgent", "Security Analysis", agent_id="analysis_agent")
        self.url = url
        self.tech_profile = tech_profile
        self.report_dir = report_dir
        self.state_manager = state_manager
        self.scan_context = scan_context or f"scan_{id(self)}"  # Default scan context

        # 6 different analysis approaches for maximum coverage
        # 5 core LLM approaches + 1 skeptical approach for early FP elimination
        self.approaches = ["pentester", "bug_bounty", "code_auditor", "red_team", "researcher", "skeptical_agent"]
        self.model = getattr(settings, "ANALYSIS_PENTESTER_MODEL", None) or settings.DEFAULT_MODEL
        
    async def run_loop(self):
        """Standard run loop executing the DAST+SAST analysis."""
        return await self.run()

    async def run(self) -> Dict:
        """Performs 6-approach analysis on the URL (DAST+SAST) with event emission."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Running DAST+SAST Analysis on {self.url[:50]}...", "INFO")

        # Use phase-specific analysis semaphore for tracking (v2.4)
        try:
            from bugtrace.core.phase_semaphores import phase_semaphores, ScanPhase
            phase_semaphores.initialize()
            phase_ctx = phase_semaphores.acquire(ScanPhase.ANALYSIS)
        except ImportError:
            phase_ctx = None

        try:
            if phase_ctx:
                await phase_ctx.__aenter__()

            # 1. Prepare Context
            context = await self._run_prepare_context()

            # 2. Parallel Analysis
            valid_analyses = await self._run_execute_analyses(context)
            if not valid_analyses:
                dashboard.log(f"[{self.name}] All analysis approaches failed.", "ERROR")
                # Emit event even on failure (empty findings)
                await self._emit_url_analyzed([])
                return {"error": "Analysis failed", "vulnerabilities": []}

            # 3. Consolidate & Review
            consolidated = self._consolidate(valid_analyses)
            vulnerabilities = await self._skeptical_review(consolidated)

            # 4. Save Results
            await self._run_save_results(vulnerabilities)

            # 5. Emit url_analyzed event (Phase 17: DISC-04)
            await self._emit_url_analyzed(vulnerabilities)

            return {
                "url": self.url,
                "vulnerabilities": vulnerabilities,
                "report_file": str(self.report_dir / f"vulnerabilities_{self._get_safe_name()}.md"),
                "fp_stats": {
                    "total_findings": len(vulnerabilities),
                    "high_confidence": len([v for v in vulnerabilities if v.get('fp_confidence', 0) >= 0.7]),
                    "medium_confidence": len([v for v in vulnerabilities if 0.5 <= v.get('fp_confidence', 0) < 0.7]),
                    "low_confidence": len([v for v in vulnerabilities if v.get('fp_confidence', 0) < 0.5])
                }
            }

        except Exception as e:
            logger.error(f"DASTySASTAgent failed: {e}", exc_info=True)
            # Emit event even on exception (empty findings)
            try:
                await self._emit_url_analyzed([])
            except Exception:
                pass  # Best effort
            return {"error": str(e), "vulnerabilities": []}
        finally:
            # Release phase semaphore (v2.4)
            if phase_ctx:
                await phase_ctx.__aexit__(None, None, None)

    async def _run_prepare_context(self) -> Dict:
        """Prepare analysis context with OOB payload and HTML content."""
        from bugtrace.tools.interactsh import interactsh_client, get_oob_payload

        # Ensure registered (lazy init)
        if not interactsh_client.registered:
            await interactsh_client.register()

        oob_payload, oob_url = await get_oob_payload("generic")

        context = {
            "url": self.url,
            "tech_stack": self.tech_profile.get("frameworks", []),
            "html_content": "",
            "oob_info": {
                "callback_url": oob_url,
                "payload_template": oob_payload,
                "instructions": "Use this callback URL for Blind XSS/SSRF/RCE testing. If you inject this and it's triggered, we will detect it Out-of-Band."
            }
        }

        # Fetch HTML Content
        try:
            from bugtrace.tools.visual.browser import browser_manager
            await browser_manager.start()
            capture = await browser_manager.capture_state(self.url)
            if capture and capture.get("html"):
                html_full = capture["html"]
                if len(html_full) > 15000:
                     context["html_content"] = html_full[:7500] + "\n...[TRUNCATED]...\n" + html_full[-7500:]
                else:
                    context["html_content"] = html_full

                logger.info(f"[{self.name}] Fetched HTML content ({len(context['html_content'])} chars) for analysis.")
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to fetch HTML content: {e}")

        return context

    async def _run_execute_analyses(self, context: Dict) -> List[Dict]:
        """Execute parallel analyses with all approaches."""
        # Run 5 core approaches in parallel first
        core_approaches = [a for a in self.approaches if a != "skeptical_agent"]
        tasks = [
            self._analyze_with_approach(context, approach)
            for approach in core_approaches
        ]

        # Add Header Injection Check
        from bugtrace.tools.exploitation.header_injection import header_detector
        tasks.append(self._check_header_injection(header_detector))

        # Add SQLi Probe Check (active testing for error-based SQLi)
        tasks.append(self._check_sqli_probes())

        # Add Cookie SQLi Probe Check (cookies need level=2 testing)
        tasks.append(self._check_cookie_sqli_probes())

        analyses = await asyncio.gather(*tasks, return_exceptions=True)
        valid_analyses = [a for a in analyses if isinstance(a, dict) and not a.get("error")]

        # Run skeptical_agent AFTER to review findings from core approaches
        if "skeptical_agent" in self.approaches:
            skeptical_result = await self._run_skeptical_approach(context, valid_analyses)
            if skeptical_result and not skeptical_result.get("error"):
                valid_analyses.append(skeptical_result)

        return valid_analyses

    async def _run_save_results(self, vulnerabilities: List[Dict]):
        """Save vulnerabilities to state manager and markdown report."""
        logger.info(f"🔍 DASTySAST Result: {len(vulnerabilities)} candidates for {self.url[:50]}")

        for v in vulnerabilities:
            self._save_single_vulnerability(v)

        # Save markdown report
        report_path = self.report_dir / f"vulnerabilities_{self._get_safe_name()}.md"
        self._save_markdown_report(report_path, vulnerabilities)

        dashboard.log(f"[{self.name}] Found {len(vulnerabilities)} potential vulnerabilities.", "SUCCESS")

    def _save_single_vulnerability(self, v: Dict):
        """Save a single vulnerability to state manager with fp_confidence."""
        # Normalize field names
        v_name = v.get("vulnerability_name") or v.get("name") or v.get("vulnerability") or "Vulnerability"
        v_desc = v.get("description") or v.get("reasoning") or v.get("details") or "No description provided."

        # Ensure v_name is descriptive
        v_name = self._normalize_vulnerability_name(v_name, v_desc, v)

        # Get severity
        v_type_upper = (v.get("type") or v_name or "").upper()
        v_severity = self._get_severity_for_type(v_type_upper, v.get("severity"))

        self.state_manager.add_finding(
            url=self.url,
            type=str(v_name),
            description=str(v_desc),
            severity=str(v_severity),
            parameter=v.get("parameter") or v.get("vulnerable_parameter"),
            payload=v.get("payload") or v.get("logic") or v.get("exploitation_strategy"),
            evidence=v.get("evidence") or v.get("reasoning"),
            screenshot_path=v.get("screenshot_path"),
            validated=v.get("validated", False),
            # Phase 17: Add FP confidence fields
            fp_confidence=v.get("fp_confidence", 0.5),
            skeptical_score=v.get("skeptical_score", 5),
            fp_reason=v.get("fp_reason", "")
        )

    def _normalize_vulnerability_name(self, v_name: str, v_desc: str, v: Dict) -> str:
        """Normalize vulnerability name to be more descriptive."""
        if v_name.lower() not in ["vulnerability", "security issue", "finding"]:
            return v_name

        desc_lower = str(v_desc).lower()
        if "xss" in desc_lower or "script" in desc_lower:
            return "Potential XSS Issue"
        if "sql" in desc_lower:
            return "Potential SQL Injection Issue"
        return f"Potential {v.get('type', 'Security')} Issue"

    def _get_safe_name(self) -> str:
        """Generate safe filename from URL."""
        return self.url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")[:50]

    def _get_severity_for_type(self, vuln_type: str, llm_severity: Optional[str] = None) -> str:
        """
        Maps vulnerability type to appropriate severity.
        SQLi, RCE, XXE = CRITICAL
        XSS, Header Injection = HIGH  
        IDOR, SSRF, CSRF = MEDIUM
        Info Disclosure = LOW
        """
        vuln_type_upper = vuln_type.upper()
        
        # CRITICAL: Direct database/system compromise
        critical_patterns = ["SQL", "SQLI", "RCE", "REMOTE CODE", "COMMAND INJECTION", 
                           "XXE", "XML EXTERNAL", "DESERIALIZATION", "NOSQL", "SSTI"]
        for pattern in critical_patterns:
            if pattern in vuln_type_upper:
                return "Critical"
        
        # HIGH: Client-side execution or significant impact
        high_patterns = ["XSS", "CROSS-SITE SCRIPTING", "HEADER INJECTION", "CRLF", 
                        "RESPONSE SPLITTING", "LFI", "LOCAL FILE", "PATH TRAVERSAL",
                        "AUTHENTICATION BYPASS", "SESSION", "CSTI"]
        for pattern in high_patterns:
            if pattern in vuln_type_upper:
                return "High"
        
        # MEDIUM: Authorization/logic flaws
        medium_patterns = ["IDOR", "INSECURE DIRECT", "OBJECT REFERENCE", "BROKEN ACCESS",
                          "SSRF", "SERVER-SIDE REQUEST", "CSRF", "CROSS-SITE REQUEST",
                          "PROTOTYPE POLLUTION", "BUSINESS LOGIC", "OPEN REDIRECT"]
        for pattern in medium_patterns:
            if pattern in vuln_type_upper:
                return "Medium"
        
        # LOW: Information disclosure
        low_patterns = ["INFORMATION", "DISCLOSURE", "VERBOSE", "DEBUG", "STACK TRACE"]
        for pattern in low_patterns:
            if pattern in vuln_type_upper:
                return "Low"
        
        # Fallback to LLM's suggestion or default to High
        if llm_severity and llm_severity.capitalize() in ["Critical", "High", "Medium", "Low", "Information"]:
            return llm_severity.capitalize()
        return "High"


    async def _check_header_injection(self, detector) -> Dict:
        """Wrapper to run header injection check and format as analysis result."""
        try:
            result = await detector.check(self.url)
            if result:
                message, screenshot = result
                return {
                    "vulnerabilities": [{
                        "type": "Header Injection",
                        "vulnerability": "HTTP Response Splitting / CRLF Injection",
                        "parameter": "URL/Query",
                        "confidence": 1.0, # Verified by detector
                        "reasoning": message,
                        "severity": "High",
                        "evidence": message,
                        "screenshot_path": screenshot,
                        "validated": True,
                        "description": f"HTTP Header Injection (CRLF) vulnerability detected. Attacker can inject arbitrary headers into HTTP responses. Evidence: {message[:200] if message else 'N/A'}",
                        "reproduction": f"curl -I '{self.url}%0d%0aX-Injected:%20true' | grep -i x-injected"
                    }]
                }
            return {"vulnerabilities": []}
        except Exception as e:
            logger.error(f"Header injection check failed: {e}", exc_info=True)
            return {"vulnerabilities": []}

    async def _check_sqli_probes(self) -> Dict:
        """
        Active SQLi probe: Send basic payloads to detect error-based SQL injection.
        Uses two detection methods:
        1. SQL error messages in response body
        2. Status code differential (500 on ' but 200 on '' = classic SQLi)
        """
        import aiohttp
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        # SQL error patterns for major databases
        SQL_ERRORS = [
            # MySQL
            "you have an error in your sql syntax",
            "mysql_fetch", "mysql_num_rows", "mysql_query",
            "warning: mysql",
            # PostgreSQL
            "postgresql.*error", "pg_query", "pg_exec",
            "unterminated quoted string",
            # MSSQL
            "microsoft sql server", "mssql_query",
            "unclosed quotation mark",
            # Oracle
            "ora-00933", "ora-00921", "ora-01756",
            "oracle.*driver", "oracle.*error",
            # SQLite
            "sqlite3.operationalerror", "sqlite_error",
            "unrecognized token",
            # Generic
            "sql syntax.*mysql", "valid sql statement",
            "sqlstate", "odbc.*driver",
        ]

        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            if not params:
                return {"vulnerabilities": []}

            findings = []

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                for param_name in params:
                    # Test: Single quote should break SQL, double quote should escape
                    test_params_single = {k: v[0] if v else "" for k, v in params.items()}
                    test_params_single[param_name] = "'"

                    test_params_double = {k: v[0] if v else "" for k, v in params.items()}
                    test_params_double[param_name] = "''"

                    url_single = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params_single), parsed.fragment
                    ))
                    url_double = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params_double), parsed.fragment
                    ))

                    try:
                        async with session.get(url_single, ssl=False) as resp_single:
                            status_single = resp_single.status
                            body_single = await resp_single.text()

                        async with session.get(url_double, ssl=False) as resp_double:
                            status_double = resp_double.status

                        # Detection Method 1: Status code differential
                        # If ' gives 500 but '' gives 200 = classic SQLi pattern
                        if status_single >= 500 and status_double < 400:
                            logger.info(f"[SQLi Probe] Status differential in {param_name}: '={status_single}, ''={status_double}")
                            findings.append({
                                "type": "SQLi",
                                "vulnerability": "SQL Injection (Error-based)",
                                "parameter": param_name,
                                "payload": "'",
                                "confidence": 0.9,
                                "severity": "Critical",
                                "validated": False,
                                "fp_confidence": 0.85,
                                "skeptical_score": 8,
                                "evidence": f"Status code differential: single quote (') returns {status_single}, escaped quote ('') returns {status_double}",
                                "description": f"Error-based SQL injection detected in parameter '{param_name}'. Single quote causes server error (500) while escaped quote works normally, indicating SQL query breakage.",
                                "reproduction": f"curl -s -o /dev/null -w '%{{http_code}}' '{url_single}' # Returns {status_single}"
                            })
                            continue  # Found SQLi, next param

                        # Detection Method 2: SQL error messages in body
                        body_lower = body_single.lower()
                        for error_pattern in SQL_ERRORS:
                            if error_pattern in body_lower:
                                logger.info(f"[SQLi Probe] Found SQL error '{error_pattern}' in {param_name}")
                                findings.append({
                                    "type": "SQLi",
                                    "vulnerability": "SQL Injection (Error-based)",
                                    "parameter": param_name,
                                    "payload": "'",
                                    "confidence": 0.95,
                                    "severity": "Critical",
                                    "validated": False,
                                    "fp_confidence": 0.9,
                                    "skeptical_score": 9,
                                    "evidence": f"SQL error detected: '{error_pattern}' in response",
                                    "description": f"Error-based SQL injection detected in parameter '{param_name}'. Database error message exposed in response.",
                                    "reproduction": f"curl '{url_single}' | grep -i 'error\\|sql'"
                                })
                                break

                    except Exception as e:
                        logger.debug(f"[SQLi Probe] Network error testing {param_name}: {e}")
                        continue

            return {"vulnerabilities": findings}

        except Exception as e:
            logger.error(f"SQLi probe check failed: {e}", exc_info=True)
            return {"vulnerabilities": []}

    async def _check_cookie_sqli_probes(self) -> Dict:
        """
        Active SQLi probe for cookies: Test each cookie value for SQL injection.
        Handles Base64-encoded values (like TrackingId with JSON inside).
        """
        import aiohttp
        import base64
        import json
        from urllib.parse import urlparse

        findings = []

        try:
            # Get cookies from browser session
            from bugtrace.tools.visual.browser import browser_manager
            session_data = await browser_manager.export_session_context()
            cookies = session_data.get("cookies", [])

            if not cookies:
                return {"vulnerabilities": []}

            parsed = urlparse(self.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                for cookie in cookies:
                    cookie_name = cookie.get("name", "")
                    cookie_value = cookie.get("value", "")

                    if not cookie_name or not cookie_value:
                        continue

                    # Skip session/auth cookies (don't want to break session)
                    if cookie_name.lower() in ["session", "sessionid", "phpsessid", "jsessionid"]:
                        continue

                    # Prepare test values
                    test_values = []

                    # Test 1: Direct injection
                    test_values.append(("direct", f"{cookie_value}'", f"{cookie_value}''"))

                    # Test 2: Try Base64 decode and inject inside
                    try:
                        # Pad Base64 if needed
                        padded = cookie_value + "=" * (4 - len(cookie_value) % 4) if len(cookie_value) % 4 else cookie_value
                        decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')

                        # Check if it's JSON
                        if decoded.strip().startswith('{'):
                            try:
                                json_data = json.loads(decoded)
                                # Inject in each JSON field
                                for key in json_data:
                                    if isinstance(json_data[key], str):
                                        # Create modified JSON with injection
                                        json_single = json_data.copy()
                                        json_single[key] = "'"
                                        json_double = json_data.copy()
                                        json_double[key] = "''"

                                        val_single = base64.b64encode(json.dumps(json_single).encode()).decode()
                                        val_double = base64.b64encode(json.dumps(json_double).encode()).decode()
                                        test_values.append((f"base64_json_{key}", val_single, val_double))
                            except json.JSONDecodeError:
                                pass
                        else:
                            # Plain Base64, inject in decoded value
                            val_single = base64.b64encode(f"{decoded}'".encode()).decode()
                            val_double = base64.b64encode(f"{decoded}''".encode()).decode()
                            test_values.append(("base64_plain", val_single, val_double))
                    except Exception:
                        pass  # Not Base64, skip

                    # Run tests
                    for test_type, val_single, val_double in test_values:
                        try:
                            # Build cookie strings
                            other_cookies = {c["name"]: c["value"] for c in cookies if c["name"] != cookie_name}

                            cookies_single = "; ".join([f"{k}={v}" for k, v in other_cookies.items()] + [f"{cookie_name}={val_single}"])
                            cookies_double = "; ".join([f"{k}={v}" for k, v in other_cookies.items()] + [f"{cookie_name}={val_double}"])

                            headers_single = {"Cookie": cookies_single}
                            headers_double = {"Cookie": cookies_double}

                            async with session.get(base_url, headers=headers_single, ssl=False) as resp_single:
                                status_single = resp_single.status

                            async with session.get(base_url, headers=headers_double, ssl=False) as resp_double:
                                status_double = resp_double.status

                            # Detection: Status code differential
                            if status_single >= 500 and status_double < 400:
                                logger.info(f"[Cookie SQLi Probe] Status differential in cookie {cookie_name} ({test_type}): '={status_single}, ''={status_double}")
                                findings.append({
                                    "type": "SQLi",
                                    "vulnerability": "SQL Injection in Cookie (Error-based)",
                                    "parameter": f"Cookie: {cookie_name}",
                                    "payload": "'" if "base64" not in test_type else f"Base64-encoded ' in {test_type}",
                                    "confidence": 0.9,
                                    "severity": "Critical",
                                    "validated": False,
                                    "fp_confidence": 0.85,
                                    "skeptical_score": 8,
                                    "evidence": f"Status code differential: single quote returns {status_single}, escaped quote returns {status_double}",
                                    "description": f"Error-based SQL injection detected in cookie '{cookie_name}' ({test_type}). Single quote causes server error while escaped quote works normally.",
                                    "reproduction": f"curl -b '{cookie_name}={val_single}' '{base_url}' # Returns {status_single}"
                                })
                                break  # Found SQLi in this cookie, move on

                        except Exception as e:
                            logger.debug(f"[Cookie SQLi Probe] Error testing {cookie_name}: {e}")
                            continue

            return {"vulnerabilities": findings}

        except Exception as e:
            logger.error(f"Cookie SQLi probe check failed: {e}", exc_info=True)
            return {"vulnerabilities": []}

    async def _analyze_with_approach(self, context: Dict, approach: str) -> Dict:
        """Analyze with a specific persona."""
        skill_context = self._approach_get_skill_context()
        system_prompt = self._get_system_prompt(approach)
        user_prompt = self._approach_build_prompt(context, skill_context)

        try:
            response = await llm_client.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                module_name="DASTySASTAgent",
                max_tokens=8000
            )

            if not response:
                return {"error": "Empty response from LLM"}

            return self._approach_parse_response(response)

        except Exception as e:
            logger.error(f"Failed to analyze with approach {approach}: {e}", exc_info=True)
            return {"vulnerabilities": []}

    def _approach_get_skill_context(self) -> str:
        """Get skill context for enrichment."""
        from bugtrace.agents.skills.loader import get_skills_for_findings

        if hasattr(self, "_prior_findings") and self._prior_findings:
            return get_skills_for_findings(self._prior_findings, max_skills=2)
        return ""

    def _approach_build_prompt(self, context: Dict, skill_context: str) -> str:
        """Build analysis prompt with context."""
        return f"""Analyze this URL for security vulnerabilities:

URL: {self.url}
Technology Stack: {self.tech_profile.get('frameworks', [])}
Page HTML Source (Snippet):
{context.get('html_content', 'Not available')[:10000]}

REQUIRED ANALYSIS (SURGICAL PRECISION):
1. Extract ALL parameters from the URL.
2. For EACH parameter, evaluate if it is a vector for vulnerabilities based on CONCRETE evidence.
3. Assign a CONFIDENCE SCORE from 0 to 10:
   - 0-3: Weak - parameter name only, no evidence
   - 4-5: Low - some patterns but unconfirmed
   - 6-7: Medium - clear patterns, worth testing
   - 8-9: High - error messages, unescaped reflection
   - 10: Confirmed - obvious vulnerability

4. IMPORTANT: Be skeptical. Real vulnerabilities require concrete evidence. Do NOT report vulnerabilities based solely on parameter names.
5. Provide a specific 'payload' for the specialist agent. This MUST be a raw, executable string (e.g., specific SQLi injection or XSS script). Do NOT provide a description.

OOB Callback: {context.get('oob_info', {}).get('callback_url', 'http://oast.fun')}

{f"=== SPECIALIZED KNOWLEDGE ==={chr(10)}{skill_context}{chr(10)}" if skill_context else ""}

EXAMPLE OUTPUT FORMAT (XML-Like):
<vulnerabilities>
  <vulnerability>
    <type>SQL Injection</type>
    <parameter>id</parameter>
    <confidence_score>7</confidence_score>
    <reasoning>Numeric ID in path is likely used in raw SQL query</reasoning>
    <severity>High</severity>
    <payload>' OR 1=1--</payload>
  </vulnerability>
</vulnerabilities>

Return ONLY valid XML tags. Do not add markdown code blocks.
"""

    def _approach_parse_response(self, response: str) -> Dict:
        """Parse LLM response into vulnerabilities."""
        parser = XmlParser()
        vuln_contents = parser.extract_list(response, "vulnerability")

        vulnerabilities = []
        for vc in vuln_contents:
            vuln = self._parse_single_vulnerability(parser, vc)
            if vuln:
                vulnerabilities.append(vuln)

        return {"vulnerabilities": vulnerabilities}

    def _parse_single_vulnerability(self, parser: XmlParser, vc: str) -> Optional[Dict]:
        """Parse a single vulnerability entry."""
        try:
            conf = self._parse_confidence_score(parser, vc)

            return {
                "type": parser.extract_tag(vc, "type") or "Unknown",
                "parameter": parser.extract_tag(vc, "parameter") or "unknown",
                "confidence_score": conf,
                "reasoning": parser.extract_tag(vc, "reasoning") or "",
                "severity": parser.extract_tag(vc, "severity") or "Medium",
                "exploitation_strategy": parser.extract_tag(vc, "payload") or parser.extract_tag(vc, "exploitation_strategy") or ""
            }
        except Exception as ex:
            logger.warning(f"Failed to parse vulnerability entry: {ex}")
            return None

    def _parse_confidence_score(self, parser: XmlParser, vc: str) -> int:
        """Parse and validate confidence score."""
        conf_str = parser.extract_tag(vc, "confidence_score") or parser.extract_tag(vc, "confidence") or "5"
        try:
            conf = int(float(conf_str))
            return max(0, min(10, conf))  # Clamp to 0-10
        except (ValueError, TypeError):
            return 5

    def _get_system_prompt(self, approach: str) -> str:
        """Get system prompt from external config."""
        if approach == "skeptical_agent":
            return self._get_skeptical_system_prompt()

        personas = self.agent_config.get("personas", {})
        if approach in personas:
            return personas[approach].strip()

        return self.system_prompt or "You are an expert security analyst."

    def _get_skeptical_system_prompt(self) -> str:
        """
        Get system prompt for skeptical_agent approach.

        The skeptical agent's job is to:
        1. Challenge findings from other approaches
        2. Identify common false positive patterns
        3. Assign FP likelihood scores
        """
        return """You are a SKEPTICAL security auditor. Your job is to CHALLENGE vulnerability findings and identify FALSE POSITIVES.

SKEPTICAL MINDSET:
- Parameter names alone (id, user, file) are NOT evidence of vulnerability
- Generic patterns without concrete evidence are likely false positives
- Error messages must be SPECIFIC SQL/command errors, not generic 500s
- XSS requires UNESCAPED reflection in dangerous contexts, not just reflection
- WAF-blocked requests indicate the app HAS protections

FALSE POSITIVE INDICATORS:
- "Could be vulnerable" or "potentially" without concrete evidence
- Vulnerability based on parameter NAME only (id -> SQLi assumption)
- No specific payload that would trigger the issue
- Technology stack inference without actual testing
- Assumptions based on common patterns

LIKELY TRUE POSITIVE INDICATORS:
- Specific error messages (SQL syntax errors, stack traces)
- Unescaped user input in script/event handler contexts
- Demonstrated behavioral differences (time-based, boolean-based)
- OOB callbacks received
- Specific version with known CVE

For EACH potential vulnerability, assign a SKEPTICAL_SCORE:
- 0-3: LIKELY FALSE POSITIVE - Reject, based on weak evidence
- 4-5: UNCERTAIN - Could be either, needs specialist validation
- 6-7: PLAUSIBLE - Some evidence, worth specialist investigation
- 8-10: LIKELY TRUE POSITIVE - Strong evidence, high priority

REMEMBER: Being skeptical SAVES TIME. False positives waste specialist agent resources."""

    def _calculate_fp_confidence(self, finding: Dict) -> float:
        """
        Calculate false positive confidence score for a finding.

        FP Confidence Scale (0.0-1.0):
        - 0.0: Almost certainly a FALSE POSITIVE
        - 0.5: Uncertain - needs specialist investigation
        - 1.0: Almost certainly a TRUE POSITIVE

        Formula:
        fp_confidence = (skeptical_component + votes_component + evidence_component)

        Where:
        - skeptical_component = (skeptical_score / 10) * FP_SKEPTICAL_WEIGHT
        - votes_component = (votes / max_votes) * FP_VOTES_WEIGHT
        - evidence_component = evidence_quality * FP_EVIDENCE_WEIGHT

        Args:
            finding: Vulnerability finding dict

        Returns:
            float: FP confidence score between 0.0 and 1.0
        """
        # Get weights from config
        skeptical_weight = getattr(settings, 'FP_SKEPTICAL_WEIGHT', 0.4)
        votes_weight = getattr(settings, 'FP_VOTES_WEIGHT', 0.3)
        evidence_weight = getattr(settings, 'FP_EVIDENCE_WEIGHT', 0.3)

        # 1. Skeptical component (0.0 - 0.4)
        skeptical_score = finding.get('skeptical_score', 5)
        skeptical_component = (skeptical_score / 10.0) * skeptical_weight

        # 2. Votes component (0.0 - 0.3)
        votes = finding.get('votes', 1)
        max_votes = len([a for a in self.approaches if a != 'skeptical_agent'])  # 5 core approaches
        votes_component = min(votes / max_votes, 1.0) * votes_weight

        # 3. Evidence component (0.0 - 0.3)
        evidence_quality = self._assess_evidence_quality(finding)
        evidence_component = evidence_quality * evidence_weight

        # Sum components (max = 1.0)
        fp_confidence = skeptical_component + votes_component + evidence_component

        # Clamp to 0.0-1.0
        return max(0.0, min(1.0, fp_confidence))

    def _assess_evidence_quality(self, finding: Dict) -> float:
        """
        Assess the quality of evidence for a finding.

        Evidence Quality Scale (0.0-1.0):
        - 0.0: No concrete evidence (parameter name only)
        - 0.5: Some patterns/indicators
        - 1.0: Concrete proof (error messages, reflection, OOB callback)

        Args:
            finding: Vulnerability finding dict

        Returns:
            float: Evidence quality score between 0.0 and 1.0
        """
        evidence_score = 0.0
        reasoning = str(finding.get('reasoning', '')).lower()
        payload = str(finding.get('exploitation_strategy', finding.get('payload', ''))).lower()
        vuln_type = str(finding.get('type', '')).lower()

        # Strong evidence indicators (+0.3 each, max 1.0)
        strong_indicators = [
            # SQL error patterns
            ('sql' in vuln_type and any(err in reasoning for err in ['syntax error', 'mysql', 'postgresql', 'sqlite', 'ora-'])),
            # XSS reflection
            ('xss' in vuln_type and any(ind in reasoning for ind in ['unescaped', 'reflected', 'rendered', 'executed'])),
            # Error messages
            any(err in reasoning for err in ['stack trace', 'exception', 'error message', 'debug']),
            # OOB callback
            'callback' in reasoning or 'oob' in reasoning or 'interactsh' in reasoning,
            # Validated/confirmed
            finding.get('validated', False) or 'confirmed' in reasoning,
        ]

        for indicator in strong_indicators:
            if indicator:
                evidence_score += 0.3

        # Medium evidence indicators (+0.15 each)
        medium_indicators = [
            # Has specific payload
            len(payload) > 10 and any(c in payload for c in ["'", '"', '<', '>', '{', '}']),
            # Has confidence score >= 7
            finding.get('confidence_score', 5) >= 7,
            # Multiple votes
            finding.get('votes', 1) >= 3,
        ]

        for indicator in medium_indicators:
            if indicator:
                evidence_score += 0.15

        # Weak evidence penalty (-0.2 each)
        weak_indicators = [
            # Parameter name only
            'parameter name' in reasoning or 'common parameter' in reasoning,
            # Speculation
            'could be' in reasoning or 'might be' in reasoning or 'potentially' in reasoning,
            # No payload
            len(payload) < 5,
        ]

        for indicator in weak_indicators:
            if indicator:
                evidence_score -= 0.2

        return max(0.0, min(1.0, evidence_score))


    async def _run_skeptical_approach(self, context: Dict, prior_analyses: List[Dict]) -> Dict:
        """
        Run skeptical_agent approach to review findings from core approaches.

        The skeptical agent sees ALL prior findings and challenges them,
        assigning skeptical_scores to help filter false positives early.
        """
        # Consolidate prior findings for skeptical review
        prior_findings = []
        for analysis in prior_analyses:
            for vuln in analysis.get("vulnerabilities", []):
                prior_findings.append(vuln)

        if not prior_findings:
            return {"vulnerabilities": []}

        # Build skeptical review prompt
        system_prompt = self._get_skeptical_system_prompt()
        user_prompt = self._build_skeptical_prompt(context, prior_findings)

        try:
            response = await llm_client.generate(
                prompt=user_prompt,
                system_prompt=system_prompt,
                model_override=settings.SKEPTICAL_MODEL,  # Use fast model for efficiency
                module_name="DASTySASTAgent_Skeptical",
                max_tokens=4000
            )

            if not response:
                return {"error": "Empty response from skeptical agent"}

            return self._parse_skeptical_response(response, prior_findings)

        except Exception as e:
            logger.error(f"Skeptical approach failed: {e}", exc_info=True)
            return {"error": str(e)}

    def _build_skeptical_prompt(self, context: Dict, prior_findings: List[Dict]) -> str:
        """Build prompt for skeptical review of prior findings."""
        findings_summary = []
        for i, f in enumerate(prior_findings):
            findings_summary.append(
                f"{i+1}. {f.get('type', 'Unknown')} on '{f.get('parameter', 'unknown')}' "
                f"(confidence: {f.get('confidence_score', 5)}/10)\n"
                f"   Reasoning: {f.get('reasoning', 'No reasoning')[:200]}"
            )

        return f"""Review these vulnerability findings and identify FALSE POSITIVES:

=== TARGET ===
URL: {self.url}

=== FINDINGS TO REVIEW ({len(prior_findings)} total) ===
{chr(10).join(findings_summary)}

=== YOUR TASK ===
For EACH finding, assign a SKEPTICAL_SCORE (0-10):
- 0-3: LIKELY FALSE POSITIVE (reject)
- 4-5: UNCERTAIN (needs validation)
- 6-7: PLAUSIBLE (investigate)
- 8-10: LIKELY TRUE POSITIVE (high priority)

Return XML:
<skeptical_review>
  <finding>
    <index>1</index>
    <type>XSS</type>
    <skeptical_score>3</skeptical_score>
    <fp_reason>Based on parameter name only, no evidence of reflection</fp_reason>
  </finding>
</skeptical_review>

Be RUTHLESS. False positives waste resources."""

    def _parse_skeptical_response(self, response: str, prior_findings: List[Dict]) -> Dict:
        """Parse skeptical review response and tag findings with skeptical scores."""
        parser = XmlParser()
        finding_blocks = parser.extract_list(response, "finding")

        scored_findings = []

        for block in finding_blocks:
            try:
                idx = int(parser.extract_tag(block, "index")) - 1
                if 0 <= idx < len(prior_findings):
                    finding = prior_findings[idx].copy()
                    finding["skeptical_score"] = int(parser.extract_tag(block, "skeptical_score") or "5")
                    finding["fp_reason"] = parser.extract_tag(block, "fp_reason") or ""
                    scored_findings.append(finding)
            except (ValueError, IndexError) as e:
                logger.warning(f"Failed to parse skeptical finding: {e}")

        logger.info(f"[{self.name}] Skeptical review: {len(scored_findings)} findings scored")
        return {"vulnerabilities": scored_findings, "approach": "skeptical_agent"}

    def _consolidate(self, analyses: List[Dict]) -> List[Dict]:
        """
        Consolidate findings from different approaches using voting/merging.

        Now incorporates skeptical_agent scores to reduce false positives early.
        Findings with low skeptical_score (<=3) are filtered BEFORE specialist dispatch.
        """
        merged = {}
        skeptical_data = {}  # Track skeptical scores separately

        def to_float(val, default=0.5):
            try:
                return float(val)
            except (ValueError, TypeError):
                return default

        # First pass: collect all findings
        for analysis in analyses:
            is_skeptical = analysis.get("approach") == "skeptical_agent"

            for vuln in analysis.get("vulnerabilities", []):
                v_type = vuln.get("type", vuln.get("vulnerability", "Unknown"))
                v_param = vuln.get("parameter", "none")
                key = f"{v_type}:{v_param}"

                conf = int(vuln.get("confidence_score", 5))

                if is_skeptical:
                    # Store skeptical data for later merge
                    skeptical_data[key] = {
                        "skeptical_score": vuln.get("skeptical_score", 5),
                        "fp_reason": vuln.get("fp_reason", "")
                    }
                else:
                    # Standard consolidation for core approaches
                    if key not in merged:
                        merged[key] = vuln.copy()
                        merged[key]["votes"] = 1
                        merged[key]["confidence_score"] = conf
                    else:
                        merged[key]["votes"] += 1
                        # Average confidence
                        merged[key]["confidence_score"] = int((merged[key]["confidence_score"] + conf) / 2)

        # Second pass: merge skeptical scores and calculate fp_confidence
        for key, vuln in merged.items():
            if key in skeptical_data:
                vuln["skeptical_score"] = skeptical_data[key]["skeptical_score"]
                vuln["fp_reason"] = skeptical_data[key]["fp_reason"]
            else:
                # No skeptical review for this finding - default to uncertain
                vuln["skeptical_score"] = 5
                vuln["fp_reason"] = "Not reviewed by skeptical agent"

            # Calculate FP confidence (Phase 17 enhancement)
            vuln['fp_confidence'] = self._calculate_fp_confidence(vuln)

        # Apply consensus filter - require at least 4 votes to reduce false positives
        min_votes = getattr(settings, "ANALYSIS_CONSENSUS_VOTES", 4)
        filtered = [v for v in merged.values() if v.get("votes", 1) >= min_votes]

        # Log skeptical filtering stats
        low_skeptical = [v for v in filtered if v.get("skeptical_score", 5) <= 3]
        if low_skeptical:
            logger.info(f"[{self.name}] Skeptical filter: {len(low_skeptical)} findings flagged as likely FP")

        return filtered

    async def _skeptical_review(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Use a skeptical LLM (Claude Haiku) to review findings and filter false positives.
        This is the final gate before findings reach specialist agents.

        Phase 17: Now uses fp_confidence for smart pre-filtering.
        Findings with low fp_confidence AND low skeptical_score are rejected early.
        """
        # 1. Pre-filter based on fp_confidence threshold (Phase 17 enhancement)
        threshold = getattr(settings, 'FP_CONFIDENCE_THRESHOLD', 0.5)

        pre_filtered = []
        rejected_count = 0
        for v in vulnerabilities:
            fp_conf = v.get('fp_confidence', 0.5)
            skeptical_score = v.get('skeptical_score', 5)

            # Reject if BOTH skeptical_score is low AND fp_confidence is below threshold
            if skeptical_score <= 3 and fp_conf < threshold:
                logger.info(f"[{self.name}] Pre-filtered FP: {v.get('type')} on '{v.get('parameter')}' "
                           f"(fp_confidence: {fp_conf:.2f}, skeptical: {skeptical_score})")
                rejected_count += 1
            else:
                pre_filtered.append(v)

        if rejected_count > 0:
            logger.info(f"[{self.name}] FP pre-filter: {rejected_count} removed (threshold: {threshold}), {len(pre_filtered)} remaining")

        if not pre_filtered:
            return []

        # 2. Deduplicate
        vulnerabilities = self._review_deduplicate(pre_filtered)
        if not vulnerabilities:
            return []

        # 3. Build prompt
        prompt = self._review_build_prompt(vulnerabilities)

        # 4. Execute review
        try:
            response = await llm_client.generate(
                prompt=prompt,
                system_prompt="You are a skeptical security expert. Reject false positives ruthlessly.",
                model_override=settings.SKEPTICAL_MODEL,
                module_name="DASTySAST_Skeptical",
                max_tokens=2000
            )

            if not response:
                logger.warning(f"[{self.name}] Skeptical review empty - keeping all")
                return vulnerabilities

            # 4. Parse and approve
            return self._review_parse_approval(response, vulnerabilities)

        except Exception as e:
            logger.error(f"[{self.name}] Skeptical review failed: {e}", exc_info=True)
            return vulnerabilities

    def _review_deduplicate(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Deduplicate vulnerabilities by type+parameter, keeping highest confidence."""
        deduped = {}
        for v in vulnerabilities:
            key = (v.get('type'), v.get('parameter'))
            existing = deduped.get(key)
            if not existing or v.get('confidence', 0) > existing.get('confidence', 0):
                deduped[key] = v

        result = list(deduped.values())
        logger.info(f"[{self.name}] Deduplicated: {len(result)} unique findings")
        return result

    def _review_build_prompt(self, vulnerabilities: List[Dict]) -> str:
        """Build skeptical review prompt with enriched context."""
        from bugtrace.agents.skills.loader import get_scoring_guide, get_false_positives

        vulns_summary_parts = []
        for i, v in enumerate(vulnerabilities):
            vuln_type = v.get('type', 'Unknown')
            scoring_guide = get_scoring_guide(vuln_type)
            fp_guide = get_false_positives(vuln_type)

            part = f"""{i+1}. {vuln_type} on '{v.get('parameter')}'
   DASTySAST Score: {v.get('confidence_score', 5)}/10 | Votes: {v.get('votes', 1)}/5
   Reasoning: {v.get('reasoning') or 'No reasoning'}

   {scoring_guide[:500] if scoring_guide else ''}
   {fp_guide[:300] if fp_guide else ''}"""
            vulns_summary_parts.append(part)

        vulns_summary = "\n\n".join(vulns_summary_parts)

        return f"""You are a security expert reviewing vulnerability findings.

=== TARGET ===
URL: {self.url}

=== FINDINGS ({len(vulnerabilities)} total) ===
{vulns_summary}

=== YOUR TASK ===
For EACH finding, evaluate and assign a FINAL CONFIDENCE SCORE (0-10).

SCORING GUIDE:
- 0-3: REJECT - No evidence, parameter name only, "EXPECTED: SAFE" present
- 4-5: LOW - Weak indicators, probably false positive
- 6-7: MEDIUM - Some patterns, worth testing by specialist
- 8-9: HIGH - Clear evidence (SQL errors, unescaped reflection)
- 10: CONFIRMED - Obvious vulnerability

RULES:
1. If the "DASTySAST Score" is high AND "Votes" are 4/5 or 5/5, lean towards a higher FINAL SCORE (6+).
2. Parameter NAME alone (webhook, id, xml) is NOT enough for score > 5, UNLESS votes are 5/5.
3. If "EXPECTED: SAFE" is found in reasoning, REJECT immediately (score 0-3).
4. "EXPECTED: VULNERABLE" in context → score 8-10
5. SQL errors visible → score 8+
6. Unescaped HTML reflection → score 7+
7. Adjust DASTySAST score up/down based on your analysis

Return XML:
<reviewed>
  <finding>
    <index>1</index>
    <type>XSS</type>
    <final_score>7</final_score>
    <reasoning>Brief explanation</reasoning>
  </finding>
</reviewed>
"""

    def _review_parse_approval(self, response: str, vulnerabilities: List[Dict]) -> List[Dict]:
        """Parse skeptical review response and approve findings above threshold."""
        parser = XmlParser()
        finding_blocks = parser.extract_list(response, "finding")

        approved = []

        for block in finding_blocks:
            self._process_review_finding(parser, block, vulnerabilities, approved)

        logger.info(f"[{self.name}] Skeptical Review: {len(approved)} passed, {len(vulnerabilities)-len(approved)} rejected")
        return approved

    def _process_review_finding(self, parser: XmlParser, block: str,
                                vulnerabilities: List[Dict], approved: List[Dict]):
        """Process a single review finding."""
        try:
            idx = int(parser.extract_tag(block, "index")) - 1
            vuln_type = parser.extract_tag(block, "type") or "UNKNOWN"
            final_score = int(parser.extract_tag(block, "final_score") or "0")
            reasoning = parser.extract_tag(block, "reasoning") or ""

            if not (0 <= idx < len(vulnerabilities)):
                return

            vuln = vulnerabilities[idx]
            vuln["skeptical_score"] = final_score
            vuln["skeptical_reasoning"] = reasoning

            # Get type-specific threshold
            threshold = settings.get_threshold_for_type(vuln_type)

            if final_score >= threshold:
                logger.info(f"[{self.name}] ✅ APPROVED #{idx+1} {vuln_type} (score: {final_score}/10 >= {threshold}): {reasoning[:60]}")
                approved.append(vuln)
            else:
                logger.info(f"[{self.name}] ❌ REJECTED #{idx+1} {vuln_type} (score: {final_score}/10 < {threshold}): {reasoning[:60]}")
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to parse finding: {e}")

    async def _emit_url_analyzed(self, vulnerabilities: List[Dict]):
        """
        Emit url_analyzed event with filtered findings.

        Event payload:
        - url: The analyzed URL
        - scan_context: Context for ordering guarantees
        - findings: List of findings with fp_confidence
        - stats: Summary statistics

        This event is consumed by:
        - ThinkingConsolidationAgent (Phase 18): For deduplication and queue distribution
        - Dashboard: For real-time progress updates
        """
        # Prepare findings payload with essential fields
        findings_payload = []
        for v in vulnerabilities:
            findings_payload.append({
                "type": v.get("type", "Unknown"),
                "parameter": v.get("parameter", "unknown"),
                "url": self.url,
                "fp_confidence": v.get("fp_confidence", 0.5),
                "skeptical_score": v.get("skeptical_score", 5),
                "confidence_score": v.get("confidence_score", 5),
                "votes": v.get("votes", 1),
                "severity": v.get("severity", "Medium"),
                "reasoning": v.get("reasoning", "")[:500],  # Truncate for event size
                "payload": v.get("exploitation_strategy", v.get("payload", ""))[:200],
                "fp_reason": v.get("fp_reason", "")[:200]
            })

        # Build event data
        event_data = {
            "url": self.url,
            "scan_context": self.scan_context,
            "findings": findings_payload,
            "stats": {
                "total": len(findings_payload),
                "high_confidence": len([f for f in findings_payload if f.get("fp_confidence", 0) >= 0.7]),
                "by_type": self._count_by_type(findings_payload)
            },
            "tech_profile": {
                "frameworks": self.tech_profile.get("frameworks", [])[:5]  # Limit for event size
            },
            "timestamp": __import__('time').time()
        }

        # Emit event
        try:
            await event_bus.emit(EventType.URL_ANALYZED, event_data)
            logger.info(f"[{self.name}] Emitted url_analyzed: {len(findings_payload)} findings for {self.url[:50]}")
        except Exception as e:
            logger.error(f"[{self.name}] Failed to emit url_analyzed event: {e}")


    def _count_by_type(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by vulnerability type."""
        counts = {}
        for f in findings:
            v_type = f.get("type", "Unknown")
            counts[v_type] = counts.get(v_type, 0) + 1
        return counts

    def _save_markdown_report(self, path: Path, vulnerabilities: List[Dict]):
        """Saves markdown report with FP confidence scores."""
        content = f"# Potential Vulnerabilities for {self.url}\n\n"

        if not vulnerabilities:
            content += "No vulnerabilities detected by DAST+SAST analysis.\n"
        else:
            content += "| Type | Parameter | FP Confidence | Skeptical Score | Votes |\n"
            content += "|------|-----------|---------------|-----------------|-------|\n"

            for v in sorted(vulnerabilities, key=lambda x: x.get('fp_confidence', 0), reverse=True):
                fp_conf = v.get('fp_confidence', 0.5)
                fp_indicator = '++' if fp_conf >= 0.7 else '+' if fp_conf >= 0.5 else '-'

                content += f"| {v.get('type', 'Unknown')} | {v.get('parameter', 'N/A')} | "
                content += f"{fp_conf:.2f} {fp_indicator} | {v.get('skeptical_score', 5)}/10 | "
                content += f"{v.get('votes', 1)}/5 |\n"

            content += "\n## Details\n\n"

            for v in vulnerabilities:
                content += f"### {v.get('type')} on `{v.get('parameter')}`\n\n"
                content += f"- **FP Confidence**: {v.get('fp_confidence', 0.5):.2f}\n"
                content += f"- **Skeptical Score**: {v.get('skeptical_score', 5)}/10\n"
                content += f"- **Votes**: {v.get('votes', 1)}/5 approaches\n"
                content += f"- **Reasoning**: {v.get('reasoning', 'N/A')}\n"
                if v.get('fp_reason'):
                    content += f"- **FP Analysis**: {v.get('fp_reason')}\n"
                content += "\n"

        with open(path, "w") as f:
            f.write(content)
