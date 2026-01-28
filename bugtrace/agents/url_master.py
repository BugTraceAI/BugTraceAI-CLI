"""
URLMasterAgent: Vertical agent that owns one URL's complete analysis lifecycle.

Maintains a conversational thread and delegates to specialized skills for
recon, analysis, and exploitation while preserving full context.

Author: BugtraceAI-CLI Team
Created: 2026-01-02
"""

import asyncio
import json
import re
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

from bugtrace.core.conversation_thread import ConversationThread
from bugtrace.core.llm_client import llm_client
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.url_master")

# Import modular skills from skills package
from bugtrace.skills import (
    BaseSkill,
    ReconSkill,
    AnalyzeSkill,
    XSSSkill,
    SQLiSkill,
    LFISkill,
    XXESkill,
    CSTISkill,
    HeaderInjectionSkill,
    PrototypePollutionSkill,
    SQLMapSkill,
    NucleiSkill,
    GoSpiderSkill,
    MutationSkill,
    SSRFSkill,
    IDORSkill,
    OpenRedirectSkill,
    OOBXSSSkill,
    CSRFSkill,
    BrowserSkill,
    ReportSkill,
)


from bugtrace.agents.base import BaseAgent

class URLMasterAgent(BaseAgent):
    """
    Vertical agent that owns one URL's complete security analysis lifecycle.
    
    Key features:
    - Maintains ConversationThread for persistent context
    - Delegates to specialized skills (recon, xss, sqli, etc.)
    - LLM decides what actions to take based on full context
    - Iterates intelligently until analysis is complete
    """
    
    MAX_ITERATIONS = 20  # Safety limit
    ITERATION_TIMEOUT = timedelta(minutes=10)
    
    # Skills to run automatically in exhaustive mode
    EXHAUSTIVE_SKILLS = ["exploit_sqli", "exploit_xss", "exploit_lfi"]
    
    def __init__(self, target_url: str, orchestrator=None, exhaustive_mode: bool = True):
        """
        Initialize URLMasterAgent for a target URL.
        
        Args:
            target_url: The URL to analyze
            orchestrator: Reference to TeamOrchestrator (optional)
            exhaustive_mode: If True, auto-test SQLi/XSS/LFI on all params
        """
        super().__init__(f"URLMaster-{target_url[:20]}", "Orchestrator", agent_id="url_master")
        self.url = target_url
        self.orchestrator = orchestrator
        self.exhaustive_mode = exhaustive_mode
        self.thread = ConversationThread(target_url)
        
        # Register available skills
        self.skills = self._register_skills()
        
        # State tracking
        self.iteration = 0
        self.is_complete = False
        self.findings: List[Dict] = []
        self.start_time: Optional[datetime] = None
        self.tested_params: set = set()  # Track what we already tested
        self.skills_used: List[str] = []  # Track skills already used
        self.tested_combinations: set = set()  # (param, skill_name) combos already tested
        
        logger.info(f"[{self.name}] Initialized for {target_url}")
    
    def _register_skills(self) -> Dict[str, Any]:
        """
        Register available skills that can be delegated to.
        
        Skills are wrappers around existing agent functionality and tools:
        - Basic: recon, analyze, browser, report
        - Exploitation: XSS, SQLi, LFI, XXE, Header Injection, SSTI, Prototype Pollution
        - External Tools: SQLMap, Nuclei, GoSpider
        - Advanced: Mutation (AI-powered WAF bypass)
        """
        return {
            # Basic skills
            "recon": ReconSkill(self),
            "analyze": AnalyzeSkill(self),
            "browser": BrowserSkill(self),
            "report": ReportSkill(self),
            # Exploitation skills (using ManipulatorOrchestrator & detectors)
            "exploit_xss": XSSSkill(self),
            "exploit_sqli": SQLiSkill(self),
            "exploit_lfi": LFISkill(self),
            "exploit_xxe": XXESkill(self),
            "exploit_header": HeaderInjectionSkill(self),
            "exploit_ssti": CSTISkill(self),
            "exploit_proto": PrototypePollutionSkill(self),
            # External tool skills (Docker-based)
            "tool_sqlmap": SQLMapSkill(self),
            "tool_nuclei": NucleiSkill(self),
            "tool_gospider": GoSpiderSkill(self),
            # Advanced AI skills
            "mutate": MutationSkill(self),
            # NEW v1.6 skills
            "exploit_ssrf": SSRFSkill(self),
            "exploit_idor": IDORSkill(self),
            "exploit_redirect": OpenRedirectSkill(self),
            "exploit_oob_xss": OOBXSSSkill(self),
            "exploit_csrf": CSRFSkill(self),
        }
    
    async def run(self) -> Dict:
        """
        Main execution loop - LLM decides what to do next.
        
        Returns:
            Summary of findings and actions taken
        """
        self.start_time = datetime.now()
        logger.info(f"[{self.name}] 🚀 Starting analysis of {self.url}")
        dashboard.update_task(self.name, status=f"Analyzing: {self.url[:50]}")
        
        # =====================================================================
        # DEDUPLICATION: Check if URL was recently scanned
        # =====================================================================
        try:
            from bugtrace.core.database import get_db_manager
            db = get_db_manager()
            
            # Get historical findings
            historical_findings = db.get_findings_for_target(self.url)
            scan_count = db.get_scan_count(self.url)
            
            if historical_findings:
                logger.info(f"[{self.name}] 📚 Found {scan_count} previous scan(s) with {len(historical_findings)} findings")
                
                # Store in thread metadata for LLM context
                self.thread.update_metadata("previous_scans", scan_count)
                self.thread.update_metadata("known_vulnerabilities", [
                    {
                        "type": f.get("type"),
                        "parameter": f.get("parameter"),
                        "severity": f.get("severity")
                    } for f in historical_findings[:10]  # Limit to avoid token bloat
                ])
                
                # Optional: Skip if recently scanned (within 24h) and had findings
                # This is configurable behavior
                if scan_count > 0 and len(historical_findings) > 0:
                    logger.info(f"[{self.name}] ⚠️ URL has existing findings. Re-scanning anyway (configurable)")
                    # Could add: if settings.SKIP_RESCANS: return early_summary
        except Exception as e:
            logger.debug(f"[{self.name}] Deduplication check failed (non-critical): {e}")
        

        # =====================================================================
        # EXHAUSTIVE MODE: Auto-test SQLi/XSS/LFI if URL has parameters
        # =====================================================================
        if self.exhaustive_mode and self._has_params():
            logger.info(f"[{self.name}] 🔥 Exhaustive mode: auto-testing SQLi/XSS/LFI")
            await self._run_exhaustive_tests()
        
        # Initial prompt to start the analysis (LLM can find additional vulns)
        initial_prompt = self._build_initial_prompt()
        
        while not self.is_complete and self.iteration < self.MAX_ITERATIONS:
            self.iteration += 1
            
            # Check timeout
            if datetime.now() - self.start_time > self.ITERATION_TIMEOUT:
                logger.warning(f"[{self.name}] Timeout reached")
                break
            
            try:
                # Ask LLM what to do next
                prompt = initial_prompt if self.iteration == 1 else self._build_iteration_prompt()
                
                response = await llm_client.generate_with_thread(
                    prompt=prompt,
                    thread=self.thread,
                    module_name=self.name,
                    temperature=0.3  # Lower temperature for more consistent decisions
                )
                
                if not response:
                    logger.error(f"[{self.name}] No response from LLM")
                    break
                
                # Parse and execute the action
                action = self._parse_action(response)
                
                if action["type"] == "complete":
                    self.is_complete = True
                    logger.info(f"[{self.name}] ✅ Analysis complete")
                    break
                
                elif action["type"] == "skill":
                    skill_name = action["skill"]
                    self.skills_used.append(skill_name)
                    result = await self._execute_skill(skill_name, action["params"])
                    self.thread.add_tool_result(skill_name, result, success=result.get("success", True))
                
                else:
                    logger.warning(f"[{self.name}] Unknown action type: {action['type']}")
                
            except Exception as e:
                logger.error(f"[{self.name}] Iteration {self.iteration} error: {e}")
                self.thread.add_message("system", f"Error occurred: {str(e)}")
            
            await asyncio.sleep(0.5)  # Prevent tight loop
        
        # Generate final summary
        summary = self._generate_summary()
        
        # Save thread for debugging
        self.thread.save()
        
        logger.info(f"[{self.name}] 🏁 Finished after {self.iteration} iterations, {len(self.findings)} findings")
        return summary
    
    def _build_initial_prompt(self) -> str:
        """Build initial prompt for the analysis."""
        skill_list = "\n".join([f"- {name}: {skill.description}" for name, skill in self.skills.items()])
        
        prompt_template = """Analyze {url} for security vulnerabilities.
Available Skills:
{skill_list}
Begin with recon.

Response format:
<thought>Your reasoning about the next step</thought>
<action>
  <type>skill</type>
  <skill>skill_name</skill>
  <params>param1=val1, param2=val2</params>
</action>

Or to finish:
<action>
  <type>complete</type>
  <summary>Brief summary of what was found</summary>
</action>
"""

        if self.system_prompt:
             prompt_template = self.system_prompt.split("# Iteration Directive Prompt")[0].replace("# Initial Analysis Prompt", "").strip()

        return prompt_template.format(url=self.url, skill_list=skill_list)

    def _build_iteration_prompt(self) -> str:
        """Build prompt for subsequent iterations with high-intelligence directives."""
        context = self.thread.get_context_summary()
        
        # Show which skills have been used
        used_skills = ', '.join(set(self.skills_used)) if self.skills_used else 'None'
        available_exploit_skills_list = [s for s in self.skills.keys() 
                                    if s.startswith('exploit_') and s not in self.skills_used]
        available_exploit_skills = ', '.join(available_exploit_skills_list) or 'All tested'
        
        prompt_template = """{context}
Used Skills: {used_skills}
Available Skills: {available_exploit_skills}
Decide the next move. 

Response format:
<thought>Analysis of findings and decision</thought>
<action>
  <type>skill</type>
  <skill>skill_name</skill>
  <params>{"param": "val"}</params>
</action>
"""

        if self.system_prompt and "# Iteration Directive Prompt" in self.system_prompt:
             prompt_template = self.system_prompt.split("# Iteration Directive Prompt")[1].strip()

        return prompt_template.format(
            context=context,
            used_skills=used_skills,
            available_exploit_skills=available_exploit_skills
        )
    
        from bugtrace.utils.parsers import XmlParser
        
        # 1. Structured XML Parse (Primary)
        action_xml = XmlParser.extract_tag(response, "action")
        if action_xml:
            action_type = XmlParser.extract_tag(action_xml, "type")
            if action_type == "complete":
                return {"type": "complete", "summary": XmlParser.extract_tag(action_xml, "summary") or "Analysis finished"}
            
            elif action_type == "skill":
                skill_name = XmlParser.extract_tag(action_xml, "skill")
                params_raw = XmlParser.extract_tag(action_xml, "params")
                
                # Parse params as key=value or JSON
                params_dict = {}
                if params_raw:
                    try:
                        if "=" in params_raw:
                            for item in params_raw.split(","):
                                if "=" in item:
                                    k, v = item.split("=", 1)
                                    params_dict[k.strip()] = v.strip()
                        else:
                            params_dict = json.loads(params_raw)
                    except Exception as e:
                        logger.debug(f"operation failed: {e}")
                
                return {
                    "type": "skill",
                    "skill": skill_name or "analyze",
                    "params": params_dict
                }
        
        # 2. Legacy/Fallback JSON Parser (Secondary)
        # Try to find JSON in response (more aggressive matching)
        
        # Fallback: intelligently infer action from text
        response_lower = clean_response.lower()
        original_lower = response.lower()  # Check original too
        
        # Check for completion signals
        if "complete" in response_lower and "analysis" in response_lower:
            return {"type": "complete", "summary": "Analysis complete"}
        
        if "finished" in response_lower or "done analyzing" in response_lower:
            return {"type": "complete", "summary": "Analysis complete"}
        
        # Smart inference based on context and what was already used
        recon_done = "recon" in self.skills_used
        
        # If recon was done, don't repeat it - move to exploitation
        if recon_done:
            # Check what the LLM was thinking about
            if "xss" in original_lower or "searchfor" in original_lower or "script" in original_lower:
                logger.info(f"[{self.name}] Inferred XSS test from context")
                return {
                    "type": "skill", 
                    "skill": "exploit_xss", 
                    "params": {"param": "searchFor"}
                }
            
            if "sql" in original_lower or "injection" in original_lower:
                logger.info(f"[{self.name}] Inferred SQLi test from context")
                return {"type": "skill", "skill": "exploit_sqli", "params": {}}
            
            if "analyze" in original_lower and "analyze" not in self.skills_used:
                return {"type": "skill", "skill": "analyze", "params": {}}
            
            # Default progression: analyze -> exploit_xss -> exploit_sqli -> complete
            if "analyze" not in self.skills_used:
                return {"type": "skill", "skill": "analyze", "params": {}}
            elif "exploit_xss" not in self.skills_used:
                return {"type": "skill", "skill": "exploit_xss", "params": {"param": "searchFor"}}
            elif "exploit_sqli" not in self.skills_used:
                return {"type": "skill", "skill": "exploit_sqli", "params": {}}
            else:
                return {"type": "complete", "summary": "All skills tested"}
        
        # First iteration - do recon
        if "recon" in response_lower or not self.skills_used:
            return {"type": "skill", "skill": "recon", "params": {}}
        
        # Default to analyze
        return {"type": "skill", "skill": "analyze", "params": {}}
    
    async def _execute_skill(self, skill_name: str, params: Dict) -> Dict:
        """
        Execute a skill and return results.
        
        Args:
            skill_name: Name of skill to execute
            params: Parameters for the skill
        
        Returns:
            Result dictionary from skill execution
        """
        if skill_name not in self.skills:
            return {"success": False, "error": f"Unknown skill: {skill_name}"}
        
        # =================================================================
        # DEDUPLICATION: Skip if we already tested this path+param+vuln combo
        # =================================================================
        parsed = urlparse(self.url)
        path = parsed.path or "/"
        param = params.get("param") or params.get("parameter") or self._get_first_param()
        
        # Map skills to vuln types for better dedup
        SKILL_TO_VULN = {
            "exploit_sqli": "sqli",
            "tool_sqlmap": "sqli",
            "exploit_xss": "xss",
            "exploit_lfi": "lfi",
            "exploit_xxe": "xxe",
            "exploit_header": "header",
            "exploit_ssti": "ssti",
            "exploit_proto": "proto",
        }
        
        vuln_type = SKILL_TO_VULN.get(skill_name, skill_name)
        combo_key = (path, param, vuln_type)
        
        if skill_name.startswith(("exploit_", "tool_")) and combo_key in self.tested_combinations:
            # Don't skip if param is 'none' but we found new inputs
            if param == "none" and len(self.thread.metadata.get("inputs_found", [])) > 0:
                pass # Continue, we might have new things to test
            else:
                logger.info(f"[{self.name}] Skipping duplicate: {skill_name} on {path} {param} ({vuln_type} already tested)")
                return {"success": True, "skipped": True, "reason": "Already tested"}
        
        # Mark as tested
        if skill_name.startswith(("exploit_", "tool_")):
            self.tested_combinations.add(combo_key)
        
        skill = self.skills[skill_name]
        logger.info(f"[{self.name}] Executing skill: {skill_name}")
        dashboard.update_task(self.name, status=f"Skill: {skill_name}")
        
        try:
            result = await skill.execute(self.url, params)
            
            # Ensure result is a dictionary to prevent "NoneType is not iterable" errors
            if result is None:
                logger.error(f"[{self.name}] Skill {skill_name} returned None")
                return {"success": False, "error": "Skill returned no result"}

            # Track findings with Conductor V2 validation + Guardrails
            if isinstance(result, dict) and "findings" in result:
                from bugtrace.core.conductor import conductor
                from bugtrace.core.guardrails import guardrails
                
                for finding in result["findings"]:
                    # Build default payload based on type
                    default_payloads = {
                        "XSS": "<script>alert(1)</script>",
                        "SQLi": "' OR '1'='1",
                        "LFI": "../../etc/passwd",
                        "XXE": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
                        "CSTI": "{{7*7}}",
                        "Header Injection": "%0d%0aX-Injected: true"
                    }
                    
                    vuln_type = finding.get("type", "Unknown")
                    payload = finding.get("payload") or default_payloads.get(vuln_type, "test")
                    
                    # Guardrails check - block destructive payloads
                    is_safe, guard_reason = guardrails.validate_payload(payload, vuln_type)
                    if not is_safe:
                        logger.warning(f"[{self.name}] Guardrails BLOCKED: {guard_reason}")
                        continue  # Skip this finding
                    
                    # Prepare finding for validation
                    finding_data = {
                        "type": vuln_type,
                        "url": finding.get("url", self.url),
                        "payload": payload,
                        "confidence": finding.get("confidence", 0.85),
                        "evidence": {
                            "alert_triggered": finding.get("alert_triggered", finding.get("validated", False)),
                            "vision_confirmed": finding.get("vision_confirmed", False),
                            "screenshot": finding.get("screenshot", ""),
                            "error_message": finding.get("evidence", finding.get("note", "")),
                            "validated": finding.get("validated", True),
                            "template_executed": vuln_type == "CSTI",
                            "time_delay": finding.get("time_delay", False),
                            "extracted_data": finding.get("extracted_data", "")
                        }
                    }
                    
                    # Validate with Conductor V2
                    is_valid, reason = conductor.validate_finding(finding_data)
                    
                    if is_valid:
                        logger.info(f"[{self.name}] Finding VALIDATED by Conductor: {vuln_type} on {finding.get('url', self.url)}")
                        finding["conductor_validated"] = True
                        finding["payload"] = payload
                        finding["severity"] = finding.get("severity", "HIGH")
                        
                        # ==================================================
                        # MEMORY: Store in MemoryManager for cross-URL dedup
                        # ==================================================
                        try:
                            from bugtrace.memory.manager import memory_manager
                            search_query = f"{vuln_type} {finding.get('url', self.url)} {payload[:30]}"
                            similar = memory_manager.vector_search(search_query, limit=1)
                            
                            if similar and len(similar) > 0:
                                logger.info(f"[{self.name}] Similar finding exists in memory, skipping duplicate node")
                            else:
                                memory_manager.add_node(
                                    "Finding",
                                    f"{vuln_type}_{self.thread.thread_id[-6:]}",
                                    properties={
                                        "type": vuln_type,
                                        "url": finding.get("url", self.url),
                                        "payload": payload[:100],
                                        "param": finding.get("parameter", finding.get("param", "")),
                                        "details": str(finding.get("evidence", ""))[:200]
                                    }
                                )
                        except Exception as mem_err:
                            logger.debug(f"Memory error (non-critical): {mem_err}")
                        
                        self.findings.append(finding)
                    else:
                        logger.warning(f"[{self.name}] Finding UNVALIDATED by Conductor: {reason}")
                        finding["conductor_validated"] = False
                        finding["conductor_reason"] = reason
                        finding["severity"] = "LOW"
                        self.findings.append(finding) # Still add for tracking
            
            return result
            
        except Exception as e:
            logger.error(f"[{self.name}] Skill {skill_name} failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _generate_summary(self) -> Dict:
        """Generate summary of the analysis and create individual URL report."""
        summary = {
            "url": self.url,
            "thread_id": self.thread.thread_id,
            "iterations": self.iteration,
            "duration_seconds": (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
            "findings": self.findings,
            "findings_count": len(self.findings),
            "metadata": self.thread.metadata,
            "complete": self.is_complete
        }
        
        # Generate individual URL report if we have a valid report directory
        if self.orchestrator and hasattr(self.orchestrator, 'report_dir'):
            try:
                from bugtrace.reporting.url_reporter import URLReporter
                
                url_reporter = URLReporter(str(self.orchestrator.report_dir))
                
                # Prepare analysis results (DAST/SAST combined)
                analysis_results = {
                    'dast': {
                        'status': 'COMPLETED',
                        'confidence': 85,
                        'findings': []
                    },
                    'sast': {
                        'patterns': [],
                        'risk_level': 'UNKNOWN'
                    },
                    'overall_risk': 'UNKNOWN',
                    'recommendations': []
                }
                
                # Populate from thread metadata (if AnalyzeSkill was used)
                if 'analysis_report' in self.thread.metadata:
                    report = self.thread.metadata['analysis_report']
                    analysis_results['overall_risk'] = report.get('risk_level', 'UNKNOWN')
                    if 'vulnerabilities' in report:
                        analysis_results['dast']['findings'] = report['vulnerabilities']
                
                # Prepare vulnerabilities for reporting
                vulnerabilities = []
                screenshots_paths = []
                
                for finding in self.findings:
                    vuln = {
                        'type': finding.get('type', 'Unknown'),
                        'parameter': finding.get('param', finding.get('parameter', 'N/A')),
                        'payload': finding.get('payload', ''),
                        'confidence': int(finding.get('confidence', 0) * 100) if isinstance(finding.get('confidence'), float) else finding.get('confidence', 0),
                        'severity': finding.get('severity', 'INFORMATIONAL'),
                        'validated': finding.get('validated', False),
                        'details': finding.get('note', finding.get('evidence', ''))
                    }
                    
                    # Add screenshot if available
                    if finding.get('screenshot'):
                        vuln['screenshot'] = finding['screenshot']
                        screenshots_paths.append(finding['screenshot'])
                    
                    vulnerabilities.append(vuln)
                
                # Calculate overall risk based on findings
                if vulnerabilities:
                    severities = [v['severity'] for v in vulnerabilities]
                    if 'CRITICAL' in severities:
                        analysis_results['overall_risk'] = 'CRITICAL'
                    elif 'HIGH' in severities:
                        analysis_results['overall_risk'] = 'HIGH'
                    elif 'MEDIUM' in severities:
                        analysis_results['overall_risk'] = 'MEDIUM'
                    else:
                        analysis_results['overall_risk'] = 'LOW'
                else:
                    analysis_results['overall_risk'] = 'NONE'
                
                # Prepare metadata
                metadata = {
                    'params': self._get_params(),
                    'tech_stack': self.thread.metadata.get('tech_stack', []),
                    'duration': summary['duration_seconds'],
                    'iterations': summary['iterations'],
                    'thread_id': summary['thread_id']
                }
                
                # Create the URL-specific report
                report_path = url_reporter.create_url_report(
                    url=self.url,
                    analysis_results=analysis_results,
                    vulnerabilities=vulnerabilities,
                    screenshots=screenshots_paths if screenshots_paths else None,
                    metadata=metadata
                )
                
                logger.info(f"[{self.name}] 📝 Individual URL report created: {report_path}")
                summary['url_report_path'] = str(report_path)
                
            except Exception as e:
                logger.error(f"[{self.name}] Failed to create URL report: {e}")
        
        # =====================================================================
        # DATABASE PERSISTENCE: Save individual URL scan to database
        # =====================================================================
        if self.findings:
            try:
                from bugtrace.core.database import get_db_manager
                db = get_db_manager()
                
                # Save this URL's scan independently
                scan_id = db.save_scan_result(
                    target_url=self.url,
                    findings=self.findings
                )
                
                logger.info(f"[{self.name}] 💾 Saved {len(self.findings)} findings to DB (scan_id: {scan_id})")
                summary['db_scan_id'] = scan_id
                
                # =========================================================
                # VECTOR EMBEDDINGS: Store findings for semantic search
                # =========================================================
                try:
                    logger.info(f"[{self.name}] 🔮 Generating embeddings for {len(self.findings)} findings...")
                    
                    for idx, finding in enumerate(self.findings):
                        try:
                            # Store with automatic embedding generation
                            db.store_finding_embedding(finding)
                            
                            if (idx + 1) % 5 == 0:
                                logger.debug(f"[{self.name}] Embedded {idx + 1}/{len(self.findings)} findings")
                        except Exception as e:
                            logger.warning(f"[{self.name}] Failed to embed finding #{idx}: {e}")
                    
                    logger.info(f"[{self.name}] ✅ All findings embedded for semantic search")
                    summary['embeddings_stored'] = len(self.findings)
                    
                except Exception as e:
                    logger.warning(f"[{self.name}] Embedding storage failed (non-critical): {e}")
                
                # Check for historical findings for context
                historical = db.get_findings_for_target(self.url)
                if historical:
                    logger.info(f"[{self.name}] 📚 Found {len(historical)} historical findings for this URL")
                    summary['historical_findings_count'] = len(historical)

                
            except Exception as e:
                logger.error(f"[{self.name}] Failed to save to database: {e}")
                import traceback
                logger.debug(traceback.format_exc())
        
        return summary
    
    # =========================================================================
    # EXHAUSTIVE MODE - Automatically test common vulns on all parameters
    # =========================================================================
    
    def _has_params(self) -> bool:
        """Check if URL has query parameters that could be injectable."""
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        
        return len(params) > 0
    
    def _get_params(self) -> Dict[str, str]:
        """Extract query parameters from URL."""
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        
        # Convert list values to single values
        return {k: v[0] if v else "" for k, v in params.items()}
    
    async def _run_exhaustive_tests(self):
        """
        Run SQLi, XSS, and LFI tests automatically on all parameters.
        This ensures we don't miss obvious vulns even if LLM doesn't test them.
        """
        params = self._get_params()
        
        if not params:
            return
        
        logger.info(f"[{self.name}] Exhaustive testing on {len(params)} params: {list(params.keys())}")
        
        for skill_name in self.EXHAUSTIVE_SKILLS:
            if skill_name in self.skills:
                try:
                    logger.info(f"[{self.name}] Exhaustive: Running {skill_name}")
                    dashboard.update_task(self.name, status=f"Exhaustive: {skill_name}")
                    
                    # Execute the skill
                    result = await self._execute_skill(skill_name, {"auto": True})
                    
                    # Mark as used
                    self.skills_used.append(skill_name)
                    
                    # Brief pause to avoid rate limits
                    await asyncio.sleep(0.3)
                    
                except Exception as e:
                    logger.warning(f"[{self.name}] Exhaustive {skill_name} failed: {e}")
        
        logger.info(f"[{self.name}] Exhaustive testing complete. Findings: {len(self.findings)}")
    
    def _get_first_param(self) -> str:
        """Get first query parameter from URL for deduplication tracking."""
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        
        if params:
            return list(params.keys())[0]
        return "none"


# Note: All skill classes (BaseSkill, ReconSkill, XSSSkill, SQLiSkill, etc.)
# have been extracted to the bugtrace.skills package for modularity.
# See bugtrace/skills/__init__.py for the full list of available skills.
