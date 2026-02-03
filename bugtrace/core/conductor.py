"""
Conductor V2: Anti-Hallucination System
Validates findings before emission using protocol files and validation rules.
"""
import os
import time
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
import html

from datetime import datetime
from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.tools.external import external_tools

logger = get_logger("core.conductor")


class ConductorV2:
    """
    Advanced Conductor with validation and anti-hallucination features.
    
    Features:
    - Protocol file management (security-rules, payloads, checklists, etc.)
    - Finding validation before emission
    - Payload validation (library + mutations)
    - False positive pattern detection
    - Agent-specific prompt generation
    - Context refresh mechanism (prevents drift)
    """
    
    PROTOCOL_DIR = "protocol"
    
    # Core protocol files
    FILES = {
        "context": "context.md",
        "tech_stack": "tech-stack.md",
        "security_rules": "security-rules.md",
        "payload_library": "payload-library.md",
        "validation_checklist": "validation-checklist.md",
        "fp_patterns": "false-positive-patterns.md"
    }
    
    # Agent-specific prompts
    AGENT_PROMPTS = {
        "recon": "agent-prompts/recon-agent.md",
        "exploit": "agent-prompts/exploit-agent.md",
        "skeptic": "agent-prompts/skeptic-agent.md"
    }
    
    def __init__(self):
        """Initialize Conductor V2 with validation capabilities."""
        self._ensure_protocol_exists()
        
        # Context cache
        self.context_cache: Dict[str, str] = {}
        
        # =========================================================
        # SHARED CONTEXT: Cross-agent communication (Phase 3 v1.5)
        # =========================================================
        self.shared_context: Dict[str, Any] = {
            "discovered_urls": [],
            "confirmed_vulns": [],
            "tested_params": [],
            "scan_metadata": {}
        }
        
        # Refresh mechanism (from config)
        self.last_refresh = time.time()
        self.refresh_interval = settings.CONDUCTOR_CONTEXT_REFRESH_INTERVAL
        
        # Validation configuration (from config)
        self.validation_enabled = not settings.CONDUCTOR_DISABLE_VALIDATION
        self.min_confidence = settings.CONDUCTOR_MIN_CONFIDENCE
        self.fp_detection_enabled = settings.CONDUCTOR_ENABLE_FP_DETECTION
        
        # Statistics
        self.stats = {
            "validations_run": 0,
            "findings_passed": 0,
            "findings_blocked": 0,
            "fp_blocks_by_pattern": {},
            "context_refreshes": 0
        }
        
        logger.info(f"Conductor V2 initialized (Anti-Hallucination Enhanced)")
        logger.info(f"Validation: {'ENABLED' if self.validation_enabled else 'DISABLED'}, Min Confidence: {self.min_confidence}, FP Detection: {'ON' if self.fp_detection_enabled else 'OFF'}")
    
    def _ensure_protocol_exists(self):
        """Create protocol directory and default files if missing."""
        if not os.path.exists(self.PROTOCOL_DIR):
            os.makedirs(self.PROTOCOL_DIR)
            logger.info(f"Created protocol directory: {self.PROTOCOL_DIR}")
        
        # Agent prompts directory
        prompts_dir = os.path.join(self.PROTOCOL_DIR, "agent-prompts")
        if not os.path.exists(prompts_dir):
            os.makedirs(prompts_dir)
            logger.info(f"Created agent prompts directory: {prompts_dir}")
    
    def _load_file(self, key: str) -> str:
        """Load protocol file content."""
        if key in self.FILES:
            filename = self.FILES[key]
        elif key in self.AGENT_PROMPTS:
            filename = self.AGENT_PROMPTS[key]
        else:
            logger.warning(f"Unknown protocol key: {key}")
            return ""
        
        path = os.path.join(self.PROTOCOL_DIR, filename)
        
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                logger.debug(f"Loaded protocol file: {key} ({len(content)} chars)")
                return content
            except Exception as e:
                logger.error(f"Error loading {path}: {e}", exc_info=True)
                return ""
        else:
            logger.warning(f"Protocol file not found: {path}")
            return ""
    
    def get_context(self, key: str, force_refresh: bool = False) -> str:
        """
        Retrieve protocol file content (cached).
        
        Args:
            key: Protocol file key (e.g., 'context', 'security_rules')
            force_refresh: Skip cache and reload from disk
        
        Returns:
            File content as string
        """
        if force_refresh or key not in self.context_cache:
            content = self._load_file(key)
            self.context_cache[key] = content
            return content
        
        return self.context_cache.get(key, "")
    
    def refresh_context(self):
        """
        Force reload of all protocol files (clears cache).
        Prevents context drift in long-running scans.
        """
        self.context_cache.clear()
        self.last_refresh = time.time()
        self.stats["context_refreshes"] += 1
        logger.info(f"Context refreshed (drift prevention) - Refresh #{self.stats['context_refreshes']}")
    
    def check_refresh_needed(self):
        """Auto-refresh context if interval elapsed."""
        if time.time() - self.last_refresh > self.refresh_interval:
            self.refresh_context()
    
    def get_agent_prompt(self, agent_name: str, task_context: Optional[Dict] = None) -> str:
        """
        Generate fresh, context-aware prompt for agent.
        
        Args:
            agent_name: Agent identifier ('recon', 'exploit', 'skeptic')
            task_context: Current task info (url, inputs_found, etc.)
        
        Returns:
            Complete agent prompt with rules and task context
        """
        self.check_refresh_needed()
        
        # Load agent-specific prompt
        agent_key = agent_name.lower().replace("agent", "").replace("-1", "").strip()
        base_prompt = self.get_context(agent_key, force_refresh=False)
        
        if not base_prompt:
            logger.warning(f"No agent prompt found for: {agent_name}")
            base_prompt = f"You are {agent_name}, a security testing agent."
        
        # Load security rules (critical review)
        security_rules = self.get_context("security_rules")
        
        # Task summary
        task_summary = ""
        if task_context:
            task_summary = f"\n\n## CURRENT TASK CONTEXT\n\n"
            for key, value in task_context.items():
                task_summary += f"- **{key}**: {value}\n"
        
        # Combine
        full_prompt = f"""
{base_prompt}

{task_summary}

## 🚨 CRITICAL RULES (RE-READ EVERY TIME)

{security_rules[:1000] if security_rules else "Follow security best practices."}

---

**Remember**: Validation is mandatory. Check `validation-checklist.md` before emitting events.
"""
        
        logger.debug(f"Generated prompt for {agent_name} ({len(full_prompt)} chars)")
        return full_prompt
    
    def _validate_xss_evidence(self, evidence: Dict) -> Tuple[bool, str]:
        """Validate XSS-specific evidence requirements."""
        if not evidence.get('alert_triggered') and not evidence.get('vision_confirmed'):
            return False, "XSS requires alert execution or vision confirmation proof"

        if not evidence.get('screenshot'):
            return False, "XSS requires screenshot proof"

        return True, ""

    def _validate_sqli_evidence(self, evidence: Dict) -> Tuple[bool, str]:
        """Validate SQLi-specific evidence requirements."""
        has_error = evidence.get('error_message')
        has_time = evidence.get('time_delay')
        has_data = evidence.get('extracted_data')

        if not (has_error or has_time or has_data):
            return False, "SQLi requires error/time/data proof"

        if evidence.get('status_code') in [403, 500] and not has_error:
            return False, "Only status code, no SQL error proof"

        return True, ""

    def _validate_evidence_by_type(self, vuln_type: str, evidence: Dict) -> Tuple[bool, str]:
        """Validate type-specific evidence requirements."""
        if vuln_type == "XSS":
            return self._validate_xss_evidence(evidence)

        if vuln_type == "SQLi":
            return self._validate_sqli_evidence(evidence)

        if vuln_type == "CSTI":
            return self._validate_csti_evidence(evidence)

        return True, ""

    def _validate_csti_evidence(self, evidence: Dict) -> Tuple[bool, str]:
        """Validate CSTI-specific evidence."""
        if not evidence.get('template_executed'):
            return False, "CSTI requires template execution proof"
        return True, ""

    def validate_finding(self, finding: Dict) -> Tuple[bool, str]:
        """Validate finding against anti-hallucination rules."""
        if not self.validation_enabled:
            logger.debug("Validation DISABLED - auto-passing finding")
            return True, "Validation bypassed (disabled in config)"

        self.stats["validations_run"] += 1

        vuln_type = finding.get('type', 'Unknown')
        confidence = finding.get('confidence', 0.0)
        evidence = finding.get('evidence', {})
        payload = finding.get('payload', '')

        # Rule 1: Confidence threshold
        if confidence < self.min_confidence:
            self.stats["findings_blocked"] += 1
            return False, f"Confidence {confidence:.2f} below threshold {self.min_confidence}"

        # Rule 2: Type-specific evidence requirements
        is_valid, error_msg = self._validate_evidence_by_type(vuln_type, evidence)
        if not is_valid:
            self.stats["findings_blocked"] += 1
            return False, error_msg

        # Rule 3: Payload validation
        if not self.validate_payload(payload, vuln_type):
            self.stats["findings_blocked"] += 1
            return False, f"Invalid payload: {payload[:50]}"

        # Rule 4: False positive check
        is_fp, fp_pattern = self.check_false_positive(finding)
        if is_fp:
            self.stats["findings_blocked"] += 1
            self.stats["fp_blocks_by_pattern"][fp_pattern] = \
                self.stats["fp_blocks_by_pattern"].get(fp_pattern, 0) + 1
            return False, f"Matches FP pattern: {fp_pattern}"

        # Passed all checks
        self.stats["findings_passed"] += 1
        logger.info(f"Finding VALIDATED: {vuln_type} (confidence: {confidence:.2f})")
        return True, "Validation passed"
    
    def _validate_basic_payload_rules(self, payload: str) -> Tuple[bool, str]:
        """Validate basic payload rules (length, conversational text)."""
        if not payload or len(payload) == 0:
            return False, "Empty payload"

        if len(payload) > 500:
            return False, f"Payload too long: {len(payload)} chars"

        conversational = ['here is', 'try this', 'you could', 'might work', 'consider']
        if any(phrase in payload.lower() for phrase in conversational):
            return False, f"Payload contains conversational text"

        return True, ""

    def _validate_xss_payload(self, payload: str) -> bool:
        """Validate XSS payload syntax."""
        if not any(c in payload for c in '<>\'"();'):
            logger.warning(f"XSS payload missing attack chars")
            return False

        if 'document.domain' not in payload and 'origin' not in payload:
            logger.warning(f"XSS payload missing domain proof")
            # Not fatal, mutation might have changed it

        return True

    def _validate_sqli_payload(self, payload: str) -> bool:
        """Validate SQLi payload syntax."""
        sql_indicators = ['SELECT', 'UNION', 'AND', 'OR', 'SLEEP', 'WAITFOR', '--', '#', ';']
        if not any(kw in payload.upper() for kw in sql_indicators):
            logger.warning(f"SQLi payload missing SQL syntax")
            return False

        if not any(c in payload for c in '\'"--#;'):
            logger.warning(f"SQLi payload missing quote/comment")
            return False

        return True

    def validate_payload(self, payload: str, vuln_type: str) -> bool:
        """Validate payload against library and syntax rules."""
        is_valid, error_msg = self._validate_basic_payload_rules(payload)
        if not is_valid:
            logger.warning(error_msg)
            return False

        if vuln_type == "XSS":
            return self._validate_xss_payload(payload)
        elif vuln_type == "SQLi":
            return self._validate_sqli_payload(payload)

        return True
    
    def _check_waf_block(self, status_code: int, body: str, headers: Dict) -> Tuple[bool, Optional[str]]:
        """Check for WAF block patterns."""
        if status_code not in [403, 406, 419, 429]:
            return False, None

        waf_keywords = ['modsecurity', 'cloudflare', 'incapsula', 'blocked', 'firewall']
        if any(kw in body for kw in waf_keywords):
            return True, "WAF_BLOCK"

        waf_headers = ['CF-RAY', 'X-WAF-Action', 'X-Akamai']
        if any(header in headers for header in waf_headers):
            return True, "WAF_BLOCK"

        return False, None

    def _check_generic_error(self, status_code: int, body: str) -> Tuple[bool, Optional[str]]:
        """Check for generic error patterns."""
        if status_code == 404:
            return True, "GENERIC_404"

        if status_code == 500:
            has_trace = any(kw in body for kw in ['traceback', 'exception', 'at line'])
            has_sql = any(kw in body for kw in ['sql', 'mysql', 'postgres', 'syntax error'])
            if not has_trace and not has_sql:
                return True, "GENERIC_500"

        return False, None

    def _check_captcha_or_rate_limit(self, body: str) -> Tuple[bool, Optional[str]]:
        """Check for CAPTCHA or rate limiting patterns."""
        captcha_keywords = ['recaptcha', 'hcaptcha', 'captcha', 'verify you are human']
        if any(kw in body for kw in captcha_keywords):
            return True, "CAPTCHA"

        rate_limit_keywords = ['too many requests', 'rate limit', 'slow down']
        if any(kw in body for kw in rate_limit_keywords):
            return True, "RATE_LIMIT"

        return False, None

    def _check_auth_required(self, status_code: int, body: str) -> Tuple[bool, Optional[str]]:
        """Check for auth required patterns."""
        if status_code not in [401, 403]:
            return False, None

        auth_keywords = ['login', 'sign in', 'unauthorized', 'authentication required']
        if any(kw in body for kw in auth_keywords):
            return True, "AUTH_REQUIRED"

        return False, None

    def check_false_positive(self, finding: Dict) -> Tuple[bool, Optional[str]]:
        """Check finding against known false positive patterns."""
        evidence = finding.get('evidence', {})
        response = evidence.get('response', {})

        if not response:
            return False, None

        status_code = response.get('status_code', 0)
        body = response.get('body', '').lower()
        headers = response.get('headers', {})

        # Check all FP patterns
        checks = [
            self._check_waf_block(status_code, body, headers),
            self._check_generic_error(status_code, body),
            self._check_captcha_or_rate_limit(body),
            self._check_auth_required(status_code, body)
        ]

        for is_fp, pattern in checks:
            if is_fp:
                return True, pattern

        return False, None
    
    async def audit_batch(self, findings: List[Dict]) -> List[Dict]:
        """
        Phase 5: Validation (Auditor Role).
        
        Review a batch of findings from the Exploitation Phase (Phase 4).
        Applies strict anti-hallucination rules and evidence verification.
        
        Args:
            findings: List of raw findings from Specialist Agents.
            
        Returns:
            List of VALIDATED findings that passed the audit.
        """
        if not findings:
            logger.info("[Conductor] Audit batch is empty.")
            return []
            
        logger.info(f"[Conductor] Auditing batch of {len(findings)} findings...")
        
        validated_findings = []
        rejected_count = 0
        
        for finding in findings:
            # 1. Structural Validation
            is_valid_format, fmt_error = self._validate_payload_format(finding)
            if not is_valid_format:
                logger.warning(f"[Conductor] REJECTED (Format): {fmt_error}")
                rejected_count += 1
                continue

            # 2. Logic/Evidence Validation
            is_valid_logic, logic_error = self.validate_finding(finding)
            if is_valid_logic:
                validated_findings.append(finding)
                # Share confirmed finding in context
                self.share_context("confirmed_vulns", finding)
            else:
                logger.warning(f"[Conductor] REJECTED (Logic): {logic_error} | Finding: {finding.get('type')} at {finding.get('parameter')}")
                rejected_count += 1
                
        logger.info(f"[Conductor] Audit Complete: {len(validated_findings)} Passed, {rejected_count} Rejected.")
        return validated_findings



    def get_full_system_prompt(self, agent_type: str = "general") -> str:
        """
        Combine all protocol files into master system prompt (legacy support).
        
        Returns:
            Combined context string
        """
        context = self.get_context("context") or ""
        stack = self.get_context("tech_stack") or ""
        rules = self.get_context("security_rules") or ""
        
        return f"{context}\n\n{stack}\n\n## Security Rules\n{rules[:500]}"
    
    def get_statistics(self) -> Dict:
        """Return validation statistics for monitoring."""
        return {
            **self.stats,
            "validation_pass_rate": (
                self.stats["findings_passed"] / self.stats["validations_run"]
                if self.stats["validations_run"] > 0 else 0.0
            ),
            "last_refresh": datetime.fromtimestamp(self.last_refresh).isoformat()
        }
    
    # =========================================================
    # CONTEXT SHARING: Methods for cross-agent communication
    # =========================================================
    
    def share_context(self, key: str, value: Any) -> None:
        """
        Share context data between agents.
        
        Args:
            key: Context key (e.g., 'discovered_urls', 'confirmed_vulns')
            value: Value to share (will be appended if key is a list)
        """
        if key in self.shared_context and isinstance(self.shared_context[key], list):
            if isinstance(value, list):
                self.shared_context[key].extend(value)
            else:
                self.shared_context[key].append(value)
        else:
            self.shared_context[key] = value
    
    def get_shared_context(self, key: str = None) -> Any:
        """
        Get shared context data.
        
        Args:
            key: Specific key to retrieve, or None for all context
            
        Returns:
            Context value or full context dict
        """
        if key is None:
            return self.shared_context.copy()
        return self.shared_context.get(key)
    
    def _validate_payload_format(self, finding_dict: Dict) -> Tuple[bool, str]:
        """
        Pre-flight validation to reject conversational payloads.
        
        Returns:
            (is_valid, error_message)
        """
        payload = finding_dict.get("payload", "")
        vuln_type = finding_dict.get("type", "UNKNOWN")
        
        # Special case: IDOR and some vulns use "N/A" or descriptive text legitimately
        if payload in ["N/A", "", None]:
            return True, ""
        
        payload = str(payload)
        
        # Forbidden patterns (conversational markers)
        conversational_patterns = [
            r"^(Inject|Use|Try|Attempt|Test for|Increment|Decrement|Set|Access|Exploit|Navigate|Check|Verify|Submit)",
            r"\(e\.g\.,",  # Examples in parentheses
            r"to (verify|exfiltrate|access|bypass|leak|confirm|test|execute)", 
            r"(such as|Alternatively|progress to|Start with|for instance)",
            r"(or use|or try|or attempt)",  # Multiple options
            r"&lt;",       # HTML escaped characters (hallucination sign)
            r"&gt;",
            r"&quot;",
            r"payload (could|should|must) be",
            r"strategy:",
            r"logic:"
        ]
        
        import re
        for pattern in conversational_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                # Only strictly block if it's long enough to be a sentence (heuristics)
                # But handoff says REJECT IMMEDIATELY.
                error = f"REJECTED: Conversational payload detected for {vuln_type}. Pattern matched: '{pattern}'. Payload: '{payload[:100]}...'"
                return False, error
        
        return True, ""

    def get_context_summary(self) -> str:
        """Get a text summary of current context for agent prompts."""
        summary = []
        if self.shared_context.get("discovered_urls"):
            summary.append(f"URLs discovered: {len(self.shared_context['discovered_urls'])}")
        if self.shared_context.get("confirmed_vulns"):
            summary.append(f"Confirmed vulns: {len(self.shared_context['confirmed_vulns'])}")
        if self.shared_context.get("tested_params"):
            summary.append(f"Tested params: {len(self.shared_context['tested_params'])}")
        return " | ".join(summary) if summary else "No shared context yet"

    # =========================================================
    # INTEGRITY VERIFICATION: Cross-phase coherence checks
    # =========================================================

    def verify_integrity(self, phase: str, expected: Dict, actual: Dict) -> bool:
        """
        Verify coherence between pipeline phases.

        Detects data loss, hallucinations, and pipeline anomalies by comparing
        expected inputs vs actual outputs at phase boundaries.

        Args:
            phase: 'discovery', 'strategy', 'exploitation'
            expected: Expected data (e.g., {'urls_count': 5})
            actual: Actual data found (e.g., {'dast_reports_count': 4, 'errors': 1})

        Returns:
            True if integrity check passes, False otherwise
        """
        logger.info(f"[Conductor] Verifying integrity for Phase: {phase}")

        if phase == "discovery":
            # Rule: If N URLs entered, N reports should exist (or errors logged)
            urls_in = expected.get('urls_count', 0)
            reports_out = actual.get('dast_reports_count', 0)
            errors = actual.get('errors', 0)

            accounted = reports_out + errors
            if accounted < urls_in:
                missing = urls_in - accounted
                logger.error(
                    f"[Conductor] INTEGRITY FAIL (Discovery): "
                    f"Missing {missing} DAST reports. "
                    f"In: {urls_in}, Reports: {reports_out}, Errors: {errors}"
                )
                self.stats["integrity_failures"] = self.stats.get("integrity_failures", 0) + 1
                return False

        elif phase == "strategy":
            # Rule: If raw findings exist, WET queue should have items (unless all filtered)
            raw_findings = expected.get('raw_findings_count', 0)
            wet_items = actual.get('wet_queue_count', 0)

            # 100% filtration is suspicious but not always wrong
            if raw_findings > 0 and wet_items == 0:
                logger.warning(
                    f"[Conductor] INTEGRITY WARN (Strategy): "
                    f"100% filtration rate. Raw: {raw_findings}, WET: {wet_items}. "
                    f"Is ThinkingAgent working correctly?"
                )
                # Warning only, not failure - some scans legitimately have no exploitable findings

            # Sanity check: WET items should never exceed raw findings
            if wet_items > raw_findings:
                logger.error(
                    f"[Conductor] INTEGRITY FAIL (Strategy): "
                    f"WET items ({wet_items}) > raw findings ({raw_findings}). "
                    f"ThinkingAgent may be duplicating data!"
                )
                self.stats["integrity_failures"] = self.stats.get("integrity_failures", 0) + 1
                return False

        elif phase == "exploitation":
            # Rule: DRY items must be <= WET items (can't create findings from nothing)
            wet_in = expected.get('wet_processed', 0)
            dry_out = actual.get('dry_generated', 0)

            if dry_out > wet_in:
                logger.error(
                    f"[Conductor] INTEGRITY FAIL (Exploitation): "
                    f"Hallucination detected! DRY items ({dry_out}) > WET inputs ({wet_in}). "
                    f"Specialists are inventing data!"
                )
                self.stats["integrity_failures"] = self.stats.get("integrity_failures", 0) + 1
                return False

        else:
            logger.warning(f"[Conductor] Unknown phase for integrity check: {phase}")
            return True

        logger.info(f"[Conductor] Integrity Check PASSED for {phase}")
        self.stats["integrity_passes"] = self.stats.get("integrity_passes", 0) + 1
        return True


# Singleton instance
conductor = ConductorV2()
