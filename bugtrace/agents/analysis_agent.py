import asyncio
from typing import Dict, List, Any, Optional
from pathlib import Path
from loguru import logger

from bugtrace.core.llm_client import llm_client
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.utils.parsers import XmlParser

from bugtrace.agents.base import BaseAgent

class DASTySASTAgent(BaseAgent):
    """
    DAST + SAST Analysis Agent.
    Performs 5-approach analysis on a URL to identify potential vulnerabilities.
    Phase 2 (Part A) of the Sequential Pipeline.
    """
    
    def __init__(self, url: str, tech_profile: Dict, report_dir: Path, state_manager: Any = None):
        super().__init__("DASTySASTAgent", "Security Analysis", agent_id="analysis_agent")
        self.url = url
        self.tech_profile = tech_profile
        self.report_dir = report_dir
        self.state_manager = state_manager
        
        # 5 different analysis approaches for maximum coverage
        self.approaches = ["pentester", "bug_bounty", "code_auditor", "red_team", "researcher"]
        self.model = getattr(settings, "ANALYSIS_PENTESTER_MODEL", None) or settings.DEFAULT_MODEL
        
    async def run_loop(self):
        """Standard run loop executing the DAST+SAST analysis."""
        return await self.run()

    async def run(self) -> Dict:
        """Performs 5-approach analysis on the URL (DAST+SAST)."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Running DAST+SAST Analysis on {self.url[:50]}...", "INFO")

        try:
            # 1. Prepare Context
            context = await self._run_prepare_context()

            # 2. Parallel Analysis
            valid_analyses = await self._run_execute_analyses(context)
            if not valid_analyses:
                dashboard.log(f"[{self.name}] All analysis approaches failed.", "ERROR")
                return {"error": "Analysis failed", "vulnerabilities": []}

            # 3. Consolidate & Review
            consolidated = self._consolidate(valid_analyses)
            vulnerabilities = await self._skeptical_review(consolidated)

            # 4. Save Results
            await self._run_save_results(vulnerabilities)

            return {
                "url": self.url,
                "vulnerabilities": vulnerabilities,
                "report_file": str(self.report_dir / f"vulnerabilities_{self._get_safe_name()}.md")
            }

        except Exception as e:
            logger.error(f"DASTySASTAgent failed: {e}", exc_info=True)
            return {"error": str(e), "vulnerabilities": []}

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
        tasks = [
            self._analyze_with_approach(context, approach)
            for approach in self.approaches
        ]

        # Add Header Injection Check
        from bugtrace.tools.exploitation.header_injection import header_detector
        tasks.append(self._check_header_injection(header_detector))

        analyses = await asyncio.gather(*tasks, return_exceptions=True)
        return [a for a in analyses if isinstance(a, dict) and not a.get("error")]

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
        """Save a single vulnerability to state manager."""
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
            validated=v.get("validated", False)
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
        personas = self.agent_config.get("personas", {})
        if approach in personas:
            return personas[approach].strip()
            
        return self.system_prompt or "You are an expert security analyst."

    def _consolidate(self, analyses: List[Dict]) -> List[Dict]:
        """Consolidate findings from different approaches using simple voting/merging."""
        merged = {}
        
        def to_float(val, default=0.5):
            try:
                return float(val)
            except (ValueError, TypeError):
                return default

        for analysis in analyses:
            for vuln in analysis.get("vulnerabilities", []):
                v_type = vuln.get("type", vuln.get("vulnerability", "Unknown"))
                v_param = vuln.get("parameter", "none")
                key = f"{v_type}:{v_param}"
                
                conf = int(vuln.get("confidence_score", 5))
                
                if key not in merged:
                    merged[key] = vuln
                    merged[key]["votes"] = 1
                    merged[key]["confidence_score"] = conf
                else:
                    merged[key]["votes"] += 1
                    # Average confidence
                    merged[key]["confidence_score"] = int((merged[key]["confidence_score"] + conf) / 2)
        
        # Apply consensus filter - require at least 4 votes to reduce false positives
        min_votes = getattr(settings, "ANALYSIS_CONSENSUS_VOTES", 4)
        return [v for v in merged.values() if v.get("votes", 1) >= min_votes]

    async def _skeptical_review(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Use a skeptical LLM (Claude Haiku) to review findings and filter false positives.
        This is the final gate before findings reach specialist agents.
        """
        # 1. Deduplicate
        vulnerabilities = self._review_deduplicate(vulnerabilities)
        if not vulnerabilities:
            return []

        # 2. Build prompt
        prompt = self._review_build_prompt(vulnerabilities)

        # 3. Execute review
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

    def _save_markdown_report(self, path: Path, vulnerabilities: List[Dict]):
        """Saves a human-readable markdown report of potential vulnerabilities."""
        content = f"# Potential Vulnerabilities for {self.url}\n\n"
        if not vulnerabilities:
            content += "No vulnerabilities detected by DAST+SAST analysis.\n"
        else:
            for v in vulnerabilities:
                content += f"## {v.get('type')} (Confidence: {v.get('confidence')})\n"
                content += f"- **Parameter**: {v.get('parameter')}\n"
                content += f"- **Reasoning**: {v.get('reasoning')}\n"
                content += f"- **Votes**: {v.get('votes', 1)}/5 approaches\n\n"
        
        with open(path, "w") as f:
            f.write(content)
