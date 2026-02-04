"""
Conductor V2: Pipeline Health Monitor & Checkpoint Manager

REFACTORED: Validation logic moved to specialists (self-validation).
Conductor now only handles:
- Protocol file management
- Shared context for cross-agent communication
- Pipeline integrity verification (phase coherence)
- Agent prompt generation
- UI callback routing (TUI integration)
"""
import os
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional
from datetime import datetime
from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

if TYPE_CHECKING:
    from bugtrace.core.ui.tui.workers import UICallback

logger = get_logger("core.conductor")


class ConductorV2:
    """
    Pipeline Health Monitor & Checkpoint Manager.

    REFACTORED (2026-02-04): Validation logic moved to specialists.
    Each specialist agent now validates its own findings via BaseAgent.emit_finding()

    Remaining Features:
    - Protocol file management (context, tech-stack, security-rules)
    - Shared context for cross-agent communication
    - Pipeline integrity verification (anti-hallucination for data flow)
    - Agent prompt generation (legacy support)
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
    
    def __init__(self, ui_callback: Optional["UICallback"] = None):
        """Initialize Conductor V2 as pipeline health monitor.

        Args:
            ui_callback: Optional UICallback for TUI integration.
                         If provided, UI updates are routed via callbacks.
                         If None, uses legacy dashboard (backward compatible).
        """
        self._ensure_protocol_exists()

        # UI callback for TUI integration (Phase 2)
        self.ui_callback: Optional["UICallback"] = ui_callback

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

        # Statistics (simplified - no validation stats)
        self.stats = {
            "context_refreshes": 0,
            "integrity_passes": 0,
            "integrity_failures": 0
        }

        logger.info("Conductor V2 initialized (Checkpoint Manager Mode)")
    
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

    # =========================================================
    # NOTE: Validation methods REMOVED (2026-02-04)
    # Specialists now self-validate via BaseAgent.emit_finding()
    # =========================================================

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
        """Return health statistics for monitoring."""
        return {
            **self.stats,
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

    # =========================================================
    # UI CALLBACK METHODS: For TUI integration (Phase 2)
    # =========================================================

    def set_ui_callback(self, callback: Optional["UICallback"]) -> None:
        """Set the UI callback for TUI integration.

        Args:
            callback: UICallback instance or None to disable.
        """
        self.ui_callback = callback
        if callback:
            logger.info("UI callback registered for TUI integration")

    def notify_phase_change(
        self, phase: str, progress: float, status: str = ""
    ) -> None:
        """Notify UI of a pipeline phase change.

        Routes to ui_callback if set, otherwise falls back to legacy dashboard.

        Args:
            phase: Current phase name.
            progress: Progress percentage (0.0 to 1.0).
            status: Optional status message.
        """
        if self.ui_callback:
            self.ui_callback.on_phase_change(phase, progress, status)
        else:
            # Legacy fallback - import here to avoid circular imports
            try:
                from bugtrace.core.ui import dashboard
                dashboard.set_status(phase, status)
            except ImportError:
                pass

    def notify_agent_update(
        self,
        agent: str,
        status: str,
        queue: int = 0,
        processed: int = 0,
        vulns: int = 0,
        **kwargs,
    ) -> None:
        """Notify UI of an agent status update.

        Routes to ui_callback if set, otherwise falls back to legacy dashboard.

        Args:
            agent: Name of the agent.
            status: Current status.
            queue: Items in queue.
            processed: Items processed.
            vulns: Vulnerabilities found.
        """
        if self.ui_callback:
            self.ui_callback.on_agent_update(
                agent, status, queue=queue, processed=processed, vulns=vulns, **kwargs
            )
        else:
            # Legacy fallback
            try:
                from bugtrace.core.ui import dashboard
                dashboard.update_task(agent, status=status)
            except ImportError:
                pass

    def notify_finding(
        self,
        finding_type: str,
        details: str,
        severity: str,
        param: Optional[str] = None,
        payload: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Notify UI of a new vulnerability finding.

        Routes to ui_callback if set, otherwise logs the finding.

        Args:
            finding_type: Type of vulnerability.
            details: Description of the finding.
            severity: Severity level.
            param: Optional vulnerable parameter.
            payload: Optional triggering payload.
        """
        if self.ui_callback:
            self.ui_callback.on_finding(
                finding_type, details, severity, param=param, payload=payload, **kwargs
            )
        else:
            # Legacy fallback - just log
            logger.info(
                f"[{severity.upper()}] {finding_type}: {details} "
                f"(param={param}, payload={payload[:30] if payload else 'N/A'}...)"
            )

    def notify_log(self, level: str, message: str) -> None:
        """Notify UI of a log message.

        Args:
            level: Log level.
            message: Log message.
        """
        if self.ui_callback:
            self.ui_callback.on_log(level, message)
        # Always log to standard logger as well
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(message)

    def notify_metrics(
        self,
        cpu: float = 0,
        ram: float = 0,
        req_rate: float = 0,
        urls_discovered: int = 0,
        urls_analyzed: int = 0,
        **kwargs,
    ) -> None:
        """Notify UI of system metrics update.

        Args:
            cpu: CPU usage percentage.
            ram: RAM usage percentage.
            req_rate: Request rate (req/s).
            urls_discovered: Total URLs discovered.
            urls_analyzed: Total URLs analyzed.
        """
        if self.ui_callback:
            self.ui_callback.on_metrics(
                cpu=cpu,
                ram=ram,
                req_rate=req_rate,
                urls_discovered=urls_discovered,
                urls_analyzed=urls_analyzed,
                **kwargs,
            )

    def notify_complete(self, total_findings: int, duration: float) -> None:
        """Notify UI that the scan is complete.

        Args:
            total_findings: Total vulnerabilities found.
            duration: Scan duration in seconds.
        """
        if self.ui_callback:
            self.ui_callback.on_complete(total_findings, duration)
        else:
            logger.info(
                f"Scan complete: {total_findings} findings in {duration:.1f}s"
            )


# Singleton instance (without callback for backward compatibility)
conductor = ConductorV2()
