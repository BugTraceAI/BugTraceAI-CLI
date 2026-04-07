"""
Chain Discovery Agent

Thin orchestrator for exploitation chain discovery.
Delegates pure logic to core.py, uses LLM and event bus for I/O.

Extracted from chain_discovery_agent.py for modularity.
"""

import asyncio
import json
import networkx as nx
from typing import List, Dict, Set, Optional, Any, Tuple
from pathlib import Path
from datetime import datetime
from loguru import logger

from bugtrace.agents.base import BaseAgent
from bugtrace.core.event_bus import EventType

from bugtrace.agents.chain_discovery.core import (
    VULN_TYPE_MAP,
    load_chain_templates,
    infer_severity,
    convert_specialist_finding,
    make_vuln_node_id,
    build_node_attributes,
    build_chain_from_template,
    find_matching_templates,
    step_execute_and_validate,
    step_build_error,
    build_chain_report,
    build_exploit_prompt,
    build_poc_prompt,
    visualize_graph,
)


class ChainDiscoveryAgent(BaseAgent):
    """
    Discovers and exploits multi-step vulnerability chains.

    Uses NetworkX graph to model:
    - Nodes: Vulnerabilities, Resources, States
    - Edges: Exploitation paths, Dependencies
    - Weights: Difficulty, Impact, Likelihood
    """

    def __init__(self, event_bus=None):
        super().__init__(
            "ChainDiscoveryAgent",
            "Exploitation Chain Analyst",
            event_bus,
            agent_id="chain_discovery",
        )

        # Exploitation graph
        self.exploit_graph = nx.DiGraph()

        # Track state
        self.discovered_vulns: List[Dict] = []
        self.discovered_chains: List[List[Dict]] = []
        self.exploited_chains: List[Dict] = []

        # Lock for thread-safe state modification (v2.6 fix: prevent race conditions)
        self._state_lock = asyncio.Lock()

        # Known chain patterns (templates)
        self.chain_templates = load_chain_templates()

    # =====================================================================
    # EVENT SUBSCRIPTIONS
    # =====================================================================

    def _setup_event_subscriptions(self):
        """Subscribe to vulnerability discovery events."""
        if self.event_bus:
            # Legacy subscriptions (backward compatibility)
            self.event_bus.subscribe("vulnerability_detected", self.handle_vulnerability)
            self.event_bus.subscribe("finding_verified", self.handle_verified_finding)

            # New Phase 20: Subscribe to specialist vulnerability_detected events
            self.event_bus.subscribe(
                EventType.VULNERABILITY_DETECTED.value,
                self.handle_specialist_finding,
            )

            logger.info(f"[{self.name}] Subscribed to vulnerability events (including specialist findings)")

    # =====================================================================
    # EVENT HANDLERS
    # =====================================================================

    async def handle_vulnerability(self, data: Dict[str, Any]):  # I/O
        """Triggered when any agent finds a vulnerability (legacy handler)."""
        vuln = data.get("vulnerability", {})

        # Skip if this looks like a specialist finding (avoid duplicates)
        if data.get("specialist"):
            return  # Let handle_specialist_finding process it

        # Protect state with lock (v2.6 fix: prevent race conditions)
        async with self._state_lock:
            self.discovered_vulns.append(vuln)
            self.think(f"New vulnerability: {vuln.get('type')} - analyzing chains...")

            # Add to graph
            await self._add_vulnerability_to_graph(vuln)

        # Look for exploitable chains OUTSIDE lock (v2.6 fix: prevent deadlock)
        await self._analyze_chains()

    async def handle_specialist_finding(self, data: Dict[str, Any]):  # I/O
        """
        Handle vulnerability_detected events from specialist agents.

        These come from Phase 20 specialists (XSS, SQLi, CSTI, LFI, IDOR,
        RCE, SSRF, XXE, JWT, OpenRedirect, PrototypePollution) after they
        confirm vulnerabilities from queue processing.
        """
        specialist = data.get("specialist", "unknown")
        finding = data.get("finding", {})
        status = data.get("status", "PENDING_VALIDATION")

        # Only process confirmed findings
        if status not in ["VALIDATED_CONFIRMED", "PENDING_VALIDATION"]:
            logger.debug(f"[{self.name}] Skipping unconfirmed finding from {specialist}")
            return

        # Convert to internal vulnerability format (PURE)
        vuln = convert_specialist_finding(specialist, finding, status)

        if vuln:
            # Protect state with lock (v2.6 fix: prevent race conditions)
            async with self._state_lock:
                self.discovered_vulns.append(vuln)
                self.think(f"New {specialist} vulnerability: analyzing chains...")

                # Add to graph
                await self._add_vulnerability_to_graph(vuln)

            # Analyze chains OUTSIDE lock (v2.6 fix: prevent deadlock)
            await self._analyze_chains()

    async def handle_verified_finding(self, data: Dict[str, Any]):  # I/O
        """Triggered when SkepticalAgent verifies a finding."""
        finding = data.get("finding", {})

        # Update graph with confirmed exploitability
        for node_id, node_data in self.exploit_graph.nodes(data=True):
            if node_data.get("url") == finding.get("url") and node_data.get("type") == finding.get("type"):
                self.exploit_graph.nodes[node_id]["verified"] = True
                self.exploit_graph.nodes[node_id]["confidence"] = finding.get("confidence", 1.0)
                break

    # =====================================================================
    # RUN LOOP
    # =====================================================================

    async def run_loop(self):  # I/O
        """Main agent loop."""
        from bugtrace.core.ui import dashboard

        dashboard.current_agent = self.name
        self.think("Chain Discovery Agent initialized...")

        while self.running:
            await asyncio.sleep(2)

            # Periodically analyze for new chains
            if len(self.discovered_vulns) >= 2:
                await self._analyze_chains()

    # =====================================================================
    # GRAPH MANAGEMENT (I/O - mutates graph)
    # =====================================================================

    async def _add_vulnerability_to_graph(self, vuln: Dict):  # I/O
        """Add vulnerability as a node in the exploitation graph."""
        vuln_id = make_vuln_node_id(vuln, len(self.exploit_graph.nodes))
        attrs = build_node_attributes(vuln)
        self.exploit_graph.add_node(vuln_id, **attrs)
        logger.debug(f"Added {vuln_id} to exploitation graph")

    # =====================================================================
    # CHAIN ANALYSIS (I/O - uses dashboard, graph, LLM)
    # =====================================================================

    async def _analyze_chains(self):  # I/O
        """
        Analyze current vulnerabilities for exploitable chains.

        Algorithm:
        1. For each chain template, check if we have matching vulns
        2. Use LLM to predict likelihood of chain success
        3. Auto-attempt exploitation if confidence > threshold
        """
        from bugtrace.core.ui import dashboard

        self.think("Analyzing exploitation chains...")
        logger.debug(f"[{self.name}] Starting chain analysis with {len(self.exploit_graph.nodes)} vulns")

        # Get current vulnerability types
        discovered_types = set(
            data["type"] for _, data in self.exploit_graph.nodes(data=True)
        )

        # Find matching templates (PURE)
        matching = find_matching_templates(self.chain_templates, discovered_types)

        for template in matching:
            dashboard.log(
                f"CHAIN DETECTED: {template['name']} ({template['severity']})",
                "CRITICAL",
            )

            # Build the chain (PURE)
            graph_nodes = list(self.exploit_graph.nodes(data=True))
            chain = build_chain_from_template(template, graph_nodes)

            if not chain:
                continue

            self.discovered_chains.append(chain)

            # Attempt automatic exploitation if likelihood threshold met
            # Use create_task to run in background (v2.6 fix: prevent blocking event loop)
            if template["likelihood"] > 0.6:
                asyncio.create_task(self._attempt_chain_exploitation(chain, template))

    # =====================================================================
    # CHAIN EXPLOITATION (I/O - uses LLM, dashboard, event bus)
    # =====================================================================

    async def _attempt_chain_exploitation(self, chain: List[Dict], template: Dict):  # I/O
        """
        Automatically attempt to exploit the discovered chain.
        This is automatic multi-step exploitation!
        """
        from bugtrace.core.ui import dashboard

        self.think(f"Attempting automatic exploitation: {template['name']}")
        dashboard.log(f"AUTO-EXPLOIT: Attempting {template['name']}...", "CRITICAL")

        # Execute chain steps
        exploit_log, success = await self._chain_execute_steps(chain, template)

        # Report results
        await self._chain_report_results(success, template, chain, exploit_log)

    async def _chain_execute_steps(self, chain: List[Dict], template: Dict) -> Tuple[List[Dict], bool]:  # I/O
        """Execute all steps in exploitation chain."""
        from bugtrace.core.ui import dashboard

        exploit_log = []
        success = True

        for i, step in enumerate(chain):
            step_name = step.get("step")

            # Skip if step not discovered yet
            if step.get("status") == "pending_discovery":
                dashboard.log(f"  Step {i+1}/{len(chain)}: {step_name} - Not yet discovered", "WARNING")
                success = False
                break

            # Attempt exploitation
            dashboard.log(f"  Step {i+1}/{len(chain)}: Exploiting {step_name}...", "INFO")

            result = await self._exploit_step(step, template)
            exploit_log.append(result)

            if not result.get("success"):
                dashboard.log(f"  Step {i+1} failed: {result.get('error')}", "ERROR")
                success = False
                break

            dashboard.log(f"  Step {i+1} success!", "SUCCESS")
            await asyncio.sleep(1)  # Rate limiting

        return exploit_log, success

    async def _exploit_step(self, step: Dict, template: Dict) -> Dict:  # I/O
        """Execute a single step in the exploitation chain."""
        step_name = step.get("step")
        url = step.get("url")
        payload = step.get("payload")

        try:
            # Get exploitation guidance from LLM
            guidance = await self._get_llm_guidance(template, step_name, url, payload)
            # Execute and return result (PURE)
            return step_execute_and_validate(step_name, guidance)
        except Exception as e:
            logger.error(f"Step exploitation failed: {e}", exc_info=True)
            return step_build_error(step_name, e)

    async def _get_llm_guidance(self, template: Dict, step_name: str, url: str, payload: str) -> Dict:  # I/O
        """Get LLM guidance for exploitation step."""
        from bugtrace.core.llm_client import llm_client

        prompt = build_exploit_prompt(template, step_name, url, payload)

        try:
            response = await asyncio.wait_for(
                llm_client.generate(prompt, "ChainExploiter"),
                timeout=30.0,
            )
            return json.loads(response)
        except asyncio.TimeoutError:
            logger.warning(f"[{self.name}] LLM timeout for chain step: {step_name}")
            return {"action": "timeout", "error": "LLM response timeout"}

    async def _chain_report_results(
        self, success: bool, template: Dict, chain: List[Dict], exploit_log: List[Dict]
    ):  # I/O
        """Report chain exploitation results."""
        from bugtrace.core.ui import dashboard

        if success:
            dashboard.log(
                f"CHAIN EXPLOITED: {template['name']} - FULL IMPACT ACHIEVED!",
                "CRITICAL",
            )
            await self._report_chain_exploitation(template, chain, exploit_log)
        else:
            dashboard.log(
                f"Partial chain: {template['name']} - {sum(1 for s in exploit_log if s.get('success'))}/{len(chain)} steps",
                "WARNING",
            )

    async def _report_chain_exploitation(
        self, template: Dict, chain: List[Dict], exploit_log: List[Dict]
    ):  # I/O
        """Generate comprehensive chain exploitation report."""
        from bugtrace.core.ui import dashboard

        # Generate PoC script via LLM
        poc_script = await self._generate_poc_script(template, chain, exploit_log)

        # Build report (PURE)
        report = build_chain_report(template, chain, exploit_log, poc_script)

        # Emit chain exploitation event
        if self.event_bus:
            await self.event_bus.emit("chain_exploited", {
                "agent": self.name,
                "chain": report,
            })

        # Save to file
        report_path = Path(f"reports/chains/chain_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2))

        dashboard.log(f"  Chain report saved: {report_path}", "INFO")

    async def _generate_poc_script(
        self, template: Dict, chain: List[Dict], exploit_log: List[Dict]
    ) -> str:  # I/O
        """Generate Python PoC script for the exploitation chain."""
        from bugtrace.core.llm_client import llm_client

        prompt = build_poc_prompt(template, chain, exploit_log)

        try:
            poc_script = await llm_client.generate(prompt, "PoCGenerator")
            return poc_script
        except Exception as e:
            logger.debug(f"operation failed: {e}")
            return "# PoC generation failed"

    # =====================================================================
    # PUBLIC API
    # =====================================================================

    def visualize_graph(self) -> str:
        """Generate Mermaid diagram of exploitation graph.

        Returns:
            Mermaid diagram string
        """
        graph_nodes = list(self.exploit_graph.nodes(data=True))
        return visualize_graph(graph_nodes, self.discovered_chains)
