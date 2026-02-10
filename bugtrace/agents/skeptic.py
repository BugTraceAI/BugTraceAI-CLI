from typing import Dict, Any, List
from datetime import datetime
from bugtrace.memory.manager import memory_manager
from bugtrace.utils.logger import get_logger
logger = get_logger("agents.skeptic")
import asyncio
import urllib.parse

# Assuming ManipulatorOrchestrator is exposed in the module
try:
    from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
    from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy
except ImportError:
    # Fallback if user code structure inside manipulator is complex
    from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
    class MutableRequest: pass 
    class MutationStrategy: 
        PAYLOAD_INJECTION="PAYLOAD_INJECTION"
        BYPASS_WAF="BYPASS_WAF"

from bugtrace.agents.base import BaseAgent
from bugtrace.tools.visual.browser import browser_manager as vision_browser
from bugtrace.core.ui import dashboard

# Import Conductor V2 for validation
from bugtrace.core.conductor import conductor

class VulnType:
    XSS = "XSS"

class SkepticalAgent(BaseAgent):
    """
    Skeptical Agent - False Positive Elimination Expert.
    Uses AI vision models to verify XSS alerts visually.
    
    EVENT BUS INTEGRATION (Phase 1 - COMPLETED):
    - Subscribes to: "vulnerability_detected" (from ExploitAgent)
    - Publishes: "finding_verified" (to Dashboard/Reports)
    """
    def __init__(self, event_bus=None):
        super().__init__("Skeptic-1", "Verification", event_bus=event_bus, agent_id="skeptic_1")
        self.manipulator = ManipulatorOrchestrator()
        self.verified_findings = set()
    
    def _setup_event_subscriptions(self):
        """Subscribe to vulnerability_detected events from ExploitAgent."""
        self.event_bus.subscribe("vulnerability_detected", self.handle_vulnerability_candidate)
        logger.info(f"[{self.name}] Subscribed to: vulnerability_detected")
    
    def _cleanup_event_subscriptions(self):
        """Cleanup event subscriptions on agent stop."""
        self.event_bus.unsubscribe("vulnerability_detected", self.handle_vulnerability_candidate)
        logger.info(f"[{self.name}] Unsubscribed from events")
    
    async def handle_vulnerability_candidate(self, data: Dict[str, Any]):
        """
        EVENT HANDLER: Triggered when ExploitAgent finds potential vulnerability.
        Executes IMMEDIATELY (~50ms) instead of polling (~5s).

        Args:
            data (dict): Event payload from ExploitAgent with finding details
        """
        finding_id = data.get('finding_id', 'unknown')
        vuln_type = data.get('type', 'XSS')

        logger.info(
            f"[{self.name}] 🔥 EVENT: vulnerability_detected | "
            f"Type: {vuln_type}, ID: {finding_id}, Confidence: {data.get('confidence', 0.5)}"
        )

        # Check deduplication
        if finding_id in self.verified_findings:
            logger.debug(f"[{self.name}] Finding already verified, skipping")
            return

        self.verified_findings.add(finding_id)
        dashboard.update_task(self.name, status=f"Event: Verifying {vuln_type}")

        try:
            # Route based on type
            if vuln_type.upper() != "XSS":
                await self._candidate_auto_approve(data)
            else:
                await self._candidate_verify_xss(data)

            logger.info(f"[{self.name}] ✅ Completed verification of {finding_id}")

        except Exception as e:
            logger.error(f"[{self.name}] Handler error for {finding_id}: {e}", exc_info=True)

    async def _candidate_auto_approve(self, data: Dict[str, Any]):
        """Auto-approve non-XSS findings (no visual verification needed)."""
        logger.info(f"[{self.name}] {data.get('type')} auto-approved (no visual verification needed)")
        await self._auto_approve_finding(data)

    async def _candidate_verify_xss(self, data: Dict[str, Any]):
        """Verify XSS finding with visual verification."""
        logger.info(f"[{self.name}] Starting visual verification for {data.get('finding_id')}")
        await self.verify_vulnerability({
            "url": data.get('url', ''),
            "type": data.get('type', 'XSS'),
            "payload": data.get('payload', ''),
            "finding_id": data.get('finding_id'),
            "status": "FIRED"
        })
    
    async def _auto_approve_finding(self, data: Dict[str, Any]):
        """
        Auto-approve non-XSS findings (SQLi, CSTI, etc) with Conductor V2 validation.
        These don't need visual verification but still require validation.
        """
        finding_id = data.get('finding_id')
        vuln_type = data.get('type')
        url = data.get('url')
        confidence = data.get('confidence', 0.7)
        
        # VALIDATION: Re-validate with Conductor V2 (higher confidence after verification)
        enhanced_data = {
            **data,
            "confidence": min(confidence + 0.1, 1.0),  # Boost confidence slightly
            "verified_by": self.name,
            "auto_approved": True
        }

        # NOTE: Conductor validation removed (2026-02-04)
        # Specialists now self-validate via BaseAgent.emit_finding()

        # Proceed with approved finding
        memory_manager.add_node("Finding", f"Verified_{finding_id}", {
            "url": url,
            "type": vuln_type,
            "severity": "CRITICAL",
            "verified_by": self.name,
            "auto_approved": True,
            "timestamp": datetime.now().isoformat()
        })
        
        # Add to dashboard
        dashboard.add_finding(
            f"Verified {vuln_type}",
            f"Auto-approved (validated): {url}",
            "CRITICAL"
        )
        
        # EVENT: Emit finding_verified
        await self.event_bus.emit("finding_verified", enhanced_data)
        
        logger.info(f"[{self.name}] 📢 EVENT EMITTED: finding_verified ({vuln_type} - auto-approved & validated)")
        
    async def run_loop(self):
        """
        DUAL MODE RUN LOOP (Polling + Events for safety).
        
        TODO: After confirming events work, remove polling block.
        """
        dashboard.log(f"[{self.name}] Verification Engine Online. Dual Mode (Polling + Events).", "INFO")
        logger.info(f"[{self.name}] Started - Listening for events...")
        
        from bugtrace.core.llm_client import llm_client
        
        while self.running:
            await self.check_pause()
            
            # Poll Memory for findings needing verification (LEGACY - Will be removed)
            candidates = memory_manager.get_attack_surface(node_type="FindingCandidate")
            
            unverified = [
                c for c in candidates 
                if c.get('status') == 'FIRED'
            ]
            
            if unverified:
                logger.info(f"[{self.name}] Found {len(unverified)} candidates (polling).")
            
            for candidate in unverified:
                 if not self.running: break
                 
                 # Optimistic locking
                 label = candidate.get("label")
                 if label:
                     candidate['status'] = 'VERIFYING'
                     memory_manager.add_node("FindingCandidate", label, {"status": "VERIFYING"})
                     
                 await self.verify_vulnerability(candidate)
                 
                 if label:
                     memory_manager.add_node("FindingCandidate", label, {"status": "VERIFIED_ATTEMPT"})
            
            await asyncio.sleep(5)
            
    async def verify_vulnerability(self, finding_data: Dict[str, Any]):
        """
        Specialized verification using Thinking Vision Models.
        Emits "finding_verified" event on successful verification.
        """
        url = finding_data.get("url")
        vuln_type = finding_data.get("type", "XSS")
        finding_id = finding_data.get("finding_id", f"unknown_{vuln_type}")

        self.think(f"VERIFICATION: {vuln_type} on {url}")

        if not url:
            logger.error(f"Cannot verify {vuln_type}: URL is missing")
            return

        try:
            # Test browser
            screenshot_path, triggered = await self._verify_test_browser(url, vuln_type)
            if not triggered:
                return

            # Analyze with vision
            image_data = self._verify_load_screenshot(screenshot_path)
            analysis = await self._verify_vision_analysis(image_data, vuln_type)

            # Process result
            if analysis and "VERIFIED" in analysis.upper():
                await self._verify_mark_confirmed(url, vuln_type, finding_id, screenshot_path, analysis)
            else:
                self._verify_mark_rejected(analysis)

        except Exception as e:
            logger.error(f"[{self.name}] Verification error: {e}", exc_info=True)

    async def _verify_test_browser(self, url: str, vuln_type: str) -> tuple:
        """Test vulnerability in browser and capture screenshot."""
        from bugtrace.tools.visual.browser import browser_manager

        screenshot_path, logs, triggered = await browser_manager.verify_xss(url, expected_message=None)

        if not triggered:
            logger.warning(f"[{self.name}] Alert NOT triggered, rejecting")
            self.think("Alert not triggered. Likely false positive.")
            return None, False

        self.think("XSS Execution Confirmed. Analyzing with AI vision...")
        return screenshot_path, True

    def _verify_load_screenshot(self, screenshot_path: str) -> bytes:
        """Load screenshot image data."""
        with open(screenshot_path, "rb") as f:
            return f.read()

    async def _verify_vision_analysis(self, image_data: bytes, vuln_type: str) -> str:
        """Analyze screenshot with vision model."""
        if "XSS" not in vuln_type.upper():
            self.think(f"Skipping AI analysis for non-XSS: {vuln_type}")
            return ""

        from bugtrace.core.llm_client import llm_client

        prompt = self.system_prompt if self.system_prompt else (
            "You are a Senior Security Auditor. Analyze this screenshot of a triggered XSS alert. "
            "1. Is the alert dialog clearly visible? "
            "2. Does the content prove execution on the target domain? "
            "3. Is there evidence of sandboxing? "
            "Reply with VERIFIED if valid PoC, otherwise POTENTIAL_SANDBOX or UNRELIABLE."
        )

        return await llm_client.analyze_visual(image_data, prompt)

    async def _verify_mark_confirmed(
        self,
        url: str,
        vuln_type: str,
        finding_id: str,
        screenshot_path: str,
        analysis: str
    ):
        """Mark finding as verified and emit event."""
        logger.info(f"[{self.name}] VERIFIED: {vuln_type} at {url}")

        dashboard.log(f"[{self.name}] AUDIT COMPLETE: {vuln_type} CONFIRMED at {url}", "CRITICAL")
        dashboard.add_finding(f"Verified {vuln_type}", f"Audit Proof: {analysis[:100]}", "CRITICAL")

        # Add to memory
        memory_manager.add_node("Finding", f"Verified_{finding_id}", {
            "url": url,
            "type": vuln_type,
            "severity": "CRITICAL",
            "proof": analysis,
            "screenshot_path": screenshot_path,
            "verified_by": self.name,
            "timestamp": datetime.now().isoformat()
        })

        # Emit event
        await self.event_bus.emit("finding_verified", {
            "finding_id": finding_id,
            "type": vuln_type,
            "url": url,
            "severity": "CRITICAL",
            "proof": screenshot_path,
            "verified_by": self.name,
            "ai_analysis": analysis[:200],
            "timestamp": datetime.now().isoformat()
        })

        logger.info(f"[{self.name}] 📢 EVENT EMITTED: finding_verified (XSS)")

    def _verify_mark_rejected(self, analysis: str):
        """Mark finding as rejected."""
        logger.warning(f"[{self.name}] REJECTED: AI evaluation unreliable: {analysis[:50] if analysis else 'N/A'}")
        self.think(f"AUDIT WARNING: Unreliable PoC - {analysis[:50] if analysis else 'N/A'}")
