"""Recon/hunter ops and remaining medium helpers.

Shell mixin; hard max 2000 LOC, prefer ~800-1500.
"""

from __future__ import annotations

import asyncio
import json
import hashlib
import re
import signal
import sys
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from shutil import move, rmtree
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import httpx
from loguru import logger
from rich.live import Live

from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.event_bus import event_bus
from bugtrace.core.http_manager import http_manager
from bugtrace.core.state_manager import get_state_manager
from bugtrace.core.pipeline import PipelineLifecycle, PipelinePhase, PipelineState
from bugtrace.core.phase_semaphores import (
    phase_semaphores, ScanPhase,
    get_exploitation_semaphore, get_analysis_semaphore, get_validation_semaphore,
    get_reporting_semaphore,
)
from bugtrace.core.batch_metrics import batch_metrics, reset_batch_metrics

# Agents / tools referenced by orchestrator shell methods
from bugtrace.agents.base import BaseAgent
from bugtrace.agents.nuclei_agent import NucleiAgent
from bugtrace.agents.gospider_agent import GoSpiderAgent
from bugtrace.agents.analysis_agent import DASTySASTAgent
from bugtrace.agents.xss import XSSAgent
from bugtrace.agents.csti_agent import CSTIAgent
from bugtrace.agents.sqlmap_agent import SQLMapAgent
from bugtrace.agents.jwt_agent import JWTAgent
from bugtrace.agents.fileupload_agent import FileUploadAgent
from bugtrace.agents.asset_discovery_agent import AssetDiscoveryAgent
from bugtrace.agents.api_security_agent import APISecurityAgent
from bugtrace.agents.openredirect_agent import OpenRedirectAgent
from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
from bugtrace.agents.reattack import ReAttackAgent
from bugtrace.utils.token_scanner import find_jwts
from bugtrace.core.conductor import conductor
from bugtrace.core.verbose_events import create_emitter, install_ui_bridge
from bugtrace.core.surface import (
    ControlModel, ProbeObservation, build_control_model, differs_from_control,
    drop_insecure_duplicate_origins, names_a_resource,
)



class TeamReconDispatchMixin:
    """Specialist dispatch and classification."""

    async def _dispatch_specialists(self, vulnerabilities: list, url: str, dashboard, process_result) -> dict:
        """Analyze vulnerabilities and dispatch appropriate specialist agents."""
        specialist_dispatches = set()
        params_map = {}
        idor_params = []

        parsed_url = urlparse(url)
        current_qs = parse_qs(parsed_url.query)

        for vuln in vulnerabilities:
            await self._process_vulnerability(
                vuln, url, dashboard, specialist_dispatches, params_map,
                idor_params, current_qs, process_result
            )

        # FIX (2026-02-04): Tech-based auto-dispatch for CSTI
        # If Angular/Vue detected, always dispatch CSTIAgent even without explicit CSTI finding
        self._auto_dispatch_csti_if_needed(specialist_dispatches, params_map, current_qs, dashboard)

        # Deterministic auto-dispatch for XXE: probe whether the endpoint actually PROCESSES XML
        # (catches JS-triggered XML POST endpoints that GET-based analysis never sees as XML).
        await self._auto_dispatch_xxe_if_needed(specialist_dispatches, params_map, url)

        return {
            "specialist_dispatches": specialist_dispatches,
            "params_map": params_map,
            "idor_params": idor_params,
            "parsed_url": parsed_url,
            "current_qs": current_qs
        }
    def _auto_dispatch_csti_if_needed(self, specialist_dispatches: set, params_map: dict, current_qs: dict, dashboard):
        """
        Auto-dispatch CSTIAgent if Angular/Vue is detected in tech_profile.

        FIX (2026-02-04): CSTIAgent wasn't running because DASTySAST LLM classified
        Angular template injection as "XSS" instead of "CSTI". Now we auto-dispatch
        CSTIAgent whenever Angular or Vue is detected, regardless of finding types.
        """
        if "CSTI_AGENT" in specialist_dispatches:
            return  # Already dispatched

        # Check tech_profile for Angular/Vue frameworks
        frameworks = getattr(self, 'tech_profile', {}).get('frameworks', [])
        frameworks_lower = [f.lower() for f in frameworks]

        csti_frameworks = ['angular', 'angularjs', 'vue', 'vuejs', 'vue.js']
        detected_csti_framework = None

        for fw in csti_frameworks:
            if any(fw in f for f in frameworks_lower):
                detected_csti_framework = fw
                break

        if detected_csti_framework:
            specialist_dispatches.add("CSTI_AGENT")
            logger.info(f"🔧 Auto-dispatch: CSTI_AGENT (detected {detected_csti_framework} in tech_profile)")

            # Add all URL params to CSTI_AGENT for probing
            if "CSTI_AGENT" not in params_map:
                params_map["CSTI_AGENT"] = set()
            for param in current_qs.keys():
                params_map["CSTI_AGENT"].add(param)
    async def _auto_dispatch_xxe_if_needed(self, specialist_dispatches: set, params_map: dict, url: str):
        """Auto-dispatch XXEAgent when a URL that DID surface DAST findings also processes XML.
        (POST-only XML endpoints with no GET-visible findings are handled by _process_url Phase 2b.)"""
        if "XXE_AGENT" in specialist_dispatches:
            return
        if await self._is_xml_endpoint(url):
            specialist_dispatches.add("XXE_AGENT")
            params_map.setdefault("XXE_AGENT", set()).add("post_body")
            logger.info(f"🔧 Auto-dispatch: XXE_AGENT (endpoint processes XML: {url.split('?')[0]})")
    async def _process_vulnerability(
        self,
        vuln: dict,
        url: str,
        dashboard,
        specialist_dispatches: set,
        params_map: dict,
        idor_params: list,
        current_qs: dict,
        process_result
    ):
        """Process a single vulnerability and update dispatch info."""
        specialist_type = await self._decide_specialist(vuln)
        logger.info(f"🤖 Dispatcher chose: {specialist_type} for {vuln.get('parameter')}")
        specialist_dispatches.add(specialist_type)

        param = vuln.get("parameter")
        if param and str(param).lower() not in ["none", "unknown", "null"]:
            self._categorize_parameter(param, specialist_type, params_map, idor_params, current_qs)

        if specialist_type == "HEADER_INJECTION":
            self._process_header_injection(vuln, url, param, process_result)
    def _process_header_injection(self, vuln: dict, url: str, param: str, process_result):
        """Process header injection finding."""
        res = {
            "findings": [{
                "type": vuln.get("type", "Header Injection"),
                "url": url,
                "parameter": param,
                "evidence": vuln.get("reasoning") or "Header Injection detected via CRLF probe",
                "payload": vuln.get("payload") or "%0d%0aX-Injected: true",
                "validated": True,
                "severity": "MEDIUM"
            }]
        }
        process_result(res)
    async def _build_agent_tasks(self, dispatch_info: dict, url: str, url_dir: Path, process_result) -> list:
        """Build list of specialist agent tasks based on dispatch decisions."""
        agent_tasks = []
        specialist_dispatches = dispatch_info["specialist_dispatches"]
        params_map = dispatch_info["params_map"]
        idor_params = dispatch_info["idor_params"]
        parsed_url = dispatch_info["parsed_url"]
        current_qs = dispatch_info["current_qs"]

        agent_tasks.extend(await self._build_xss_task(specialist_dispatches, params_map, url, url_dir, process_result))
        agent_tasks.extend(await self._build_sql_task(specialist_dispatches, params_map, url, url_dir, parsed_url, current_qs, process_result))
        agent_tasks.extend(await self._build_csti_task(specialist_dispatches, params_map, url, url_dir, process_result))
        agent_tasks.extend(await self._build_other_tasks(specialist_dispatches, params_map, idor_params, url, url_dir, process_result))

        return agent_tasks
    async def _build_xss_task(self, specialist_dispatches: set, params_map: dict, url: str, url_dir: Path, process_result) -> list:
        """Build XSS agent task."""
        from bugtrace.core.team.orchestrator import run_agent_with_semaphore
        if "XSS_AGENT" not in specialist_dispatches:
            return []

        p_list = list(params_map.get("XSS_AGENT", [])) or None
        xss_agent = XSSAgent(url, params=p_list, report_dir=url_dir)
        return [run_agent_with_semaphore(self.url_semaphore, xss_agent, process_result)]
    async def _build_sql_task(self, specialist_dispatches: set, params_map: dict, url: str, url_dir: Path, parsed_url, current_qs: dict, process_result) -> list:
        """Build SQL agent task."""
        from bugtrace.core.team.orchestrator import run_agent_with_semaphore
        url_has_params = bool(parsed_url.query)
        if "SQL_AGENT" not in specialist_dispatches and not url_has_params:
            return []

        p_list = list(params_map.get("SQL_AGENT", []))
        if not p_list and url_has_params:
            p_list = list(current_qs.keys())
        sql_agent = SQLMapAgent(url, p_list or None, url_dir)
        return [run_agent_with_semaphore(self.url_semaphore, sql_agent, process_result)]
    async def _build_csti_task(self, specialist_dispatches: set, params_map: dict, url: str, url_dir: Path, process_result) -> list:
        """Build CSTI agent task."""
        from bugtrace.core.team.orchestrator import run_agent_with_semaphore
        if "CSTI_AGENT" not in specialist_dispatches:
            return []

        p_list = list(params_map.get("CSTI_AGENT", [])) or None
        csti_agent = CSTIAgent(url, params=[{"parameter": p} for p in p_list] if p_list else None, report_dir=url_dir)
        return [run_agent_with_semaphore(self.url_semaphore, csti_agent, process_result)]
    async def _execute_agents(self, agent_tasks: list, dashboard) -> bool:
        """Execute agent tasks with stop request handling."""
        if not agent_tasks:
            return True

        logger.info(f"[TeamOrchestrator] Executing {len(agent_tasks)} agents in parallel (max {settings.MAX_CONCURRENT_URL_AGENTS} concurrent)")
        pending = {asyncio.ensure_future(t) for t in agent_tasks}

        while pending:
            done, pending = await asyncio.wait(pending, timeout=0.5, return_when=asyncio.FIRST_COMPLETED)
            # Pause checkpoint: block here while paused
            _ctx = getattr(self, '_scan_context', None)
            if _ctx is not None:
                await _ctx.wait_if_paused()
            if dashboard.stop_requested or self._stop_event.is_set():
                logger.warning("🛑 Stop requested. Cancelling running agents...")
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.wait(pending, timeout=5)
                return False
        return True
    async def _run_dast_analysis(self, url: str, url_dir: Path, dashboard) -> list:
        """Run DAST analysis and return vulnerabilities."""
        if dashboard.stop_requested or self._stop_event.is_set():
            return []

        dast = DASTySASTAgent(url, self.tech_profile, url_dir, state_manager=self.state_manager, scan_context=str(self.scan_id))
        analysis_result = await dast.run()

        return analysis_result.get("vulnerabilities", [])
    async def _orchestrate_specialists(
        self, vulnerabilities: list, url: str, url_dir: Path, seen_keys: set, dashboard
    ) -> Optional[list]:
        """Orchestrate specialist agents for found vulnerabilities."""
        logger.info(f"🧠 Orchestrator deciding on {len(vulnerabilities)} potential vulnerabilities...")

        all_validated_findings = []
        process_result = self._create_finding_processor(seen_keys, all_validated_findings, dashboard)
        dispatch_info = await self._dispatch_specialists(vulnerabilities, url, dashboard, process_result)
        agent_tasks = await self._build_agent_tasks(dispatch_info, url, url_dir, process_result)

        if agent_tasks:
            continue_scan = await self._execute_agents(agent_tasks, dashboard)
            if not continue_scan:
                return None  # Signal scan stopped

        return all_validated_findings
    def _load_nuclei_routing_rules(self) -> dict:
        """Load nuclei routing JSON (cached on concrete class). Path via pure package_paths."""
        from bugtrace.core.nuclei_routing_policy import load_nuclei_routing_config

        cache_holder = type(self)
        if getattr(cache_holder, "_nuclei_routing_cache", None) is not None:
            return cache_holder._nuclei_routing_cache

        cfg = load_nuclei_routing_config()
        cache_holder._nuclei_routing_cache = cfg
        n_rules = len(cfg.get("rules") or [])
        if n_rules:
            logger.debug(f"Loaded {n_rules} nuclei routing rules")
        else:
            logger.warning(
                "Nuclei routing rules empty — misconfigs will fall back to MISSING_SECURITY_HEADER"
            )
        return cfg

    def _match_nuclei_routing_rule(self, routing_config: dict, tags_set: set, template_id: str) -> dict:
        """Pure owner: nuclei_routing_policy.match_nuclei_routing_rule."""
        from bugtrace.core.nuclei_routing_policy import match_nuclei_routing_rule

        return match_nuclei_routing_rule(routing_config, set(tags_set or set()), template_id or "")
    async def _decide_specialist(self, vuln: dict) -> str:
        """Uses LLM to classify vulnerability and select best specialist agent."""
        from bugtrace.core.llm_client import llm_client

        # Fast path for obvious classifications
        fast_path_result = self._try_fast_path_classification(vuln)
        if fast_path_result:
            return fast_path_result

        # LLM-based classification
        prompt = self._build_dispatcher_prompt(vuln)

        try:
            decision = await llm_client.generate(prompt, module_name="Dispatcher", max_tokens=100)
            chosen_agent = self._extract_agent_from_decision(decision, vuln)
            return chosen_agent
        except Exception as e:
            logger.error(f"Dispatcher LLM failed: {e}", exc_info=True)
            return self._fallback_classification(vuln)
    def _try_fast_path_classification(self, vuln: dict) -> Optional[str]:
        """Try fast-path classification for obvious vulnerability types."""
        v_type = str(vuln.get("type", "")).upper()

        if "XSS" in v_type: return "XSS_AGENT"
        if "SQL" in v_type: return "SQL_AGENT"
        if "CSTI" in v_type or "TEMPLATE" in v_type or "SSTI" in v_type: return "CSTI_AGENT"
        if "SSRF" in v_type or "SERVER-SIDE REQUEST" in v_type: return "SSRF_AGENT"
        if "XXE" in v_type or "XML" in v_type: return "XXE_AGENT"
        if "LFI" in v_type or "PATH TRAVERSAL" in v_type or "LOCAL FILE" in v_type: return "LFI_AGENT"
        if "RCE" in v_type or "COMMAND" in v_type or "REMOTE CODE" in v_type: return "RCE_AGENT"
        if "UPLOAD" in v_type or "FILES" in v_type: return "FILE_UPLOAD_AGENT"
        if "JWT" in v_type or "TOKEN" in v_type: return "JWT_AGENT"
        if "REDIRECT" in v_type or "OPEN REDIRECT" in v_type or "URL REDIRECT" in v_type: return "OPENREDIRECT_AGENT"
        if "PROTOTYPE" in v_type or "POLLUTION" in v_type or "PROTO POLLUTION" in v_type or "__PROTO__" in v_type: return "PROTOTYPE_POLLUTION_AGENT"
        if "IDOR" in v_type or "INSECURE DIRECT" in v_type: return "IDOR_AGENT"

        return None
    def _build_dispatcher_prompt(self, vuln: dict) -> str:
        """Build prompt for LLM dispatcher."""
        return f"""
        Act as a Security Dispatcher.
        Analyze this potential vulnerability finding and assign the correct Specialist Agent.

        FINDING: {vuln}

        AVAILABLE AGENTS:
        - XSS_AGENT (Cross-Site Scripting, HTML injection)
        - SQL_AGENT (SQL Injection, Database errors)
        - CSTI_AGENT (Client-Side Template Injection, SSTI, {{{{7*7}}}} indicators)
        - XXE_AGENT (XML External Entity, XML parsing)
        - PROTO_AGENT (Prototype Pollution, JS Object injection)
        - JWT_AGENT (JSON Web Token vulnerabilities, alg: none, weak secrets)
        - HEADER_INJECTION (CRLF, Response Splitting)
        - FILE_UPLOAD_AGENT (Unrestricted file upload, RCE via shell)
        - IDOR_AGENT (Insecure Direct Object Reference, Parameter Tampering)
        - SSRF_AGENT (Server-Side Request Forgery, internal network access)
        - LFI_AGENT (Local File Inclusion, path traversal)
        - RCE_AGENT (Remote Code Execution, command injection)
        - OPENREDIRECT_AGENT (Open Redirect, URL redirection to untrusted site)
        - PROTOTYPE_POLLUTION_AGENT (Prototype Pollution, __proto__ injection, object manipulation)
        - IGNORE (If low confidence or not relevant)

        Return ONLY the Agent Name using XML format:
        <thought>Reasoning for selection</thought>
        <agent>AGENT_NAME</agent>
        """
    def _extract_agent_from_decision(self, decision: str, vuln: dict) -> str:
        """Extract agent name from LLM decision."""
        from bugtrace.utils.parsers import XmlParser

        chosen_agent = XmlParser.extract_tag(decision, "agent")

        if chosen_agent:
            chosen_agent = chosen_agent.strip().replace("`", "").upper()
            valid_agents = [
                "XSS_AGENT", "SQL_AGENT", "XXE_AGENT", "SSRF_AGENT", "LFI_AGENT",
                "RCE_AGENT", "PROTO_AGENT", "HEADER_INJECTION", "IDOR_AGENT",
                "JWT_AGENT", "FILE_UPLOAD_AGENT", "OPENREDIRECT_AGENT",
                "PROTOTYPE_POLLUTION_AGENT", "IGNORE"
            ]

            for valid in valid_agents:
                if valid in chosen_agent:
                    return valid

        # JWT keyword fallback
        v_type_lower = str(vuln.get("type", "")).lower()
        if "jwt" in v_type_lower or "auth token" in v_type_lower:
            return "JWT_AGENT"

        # Text-based heuristic fallback
        if decision:
            valid_agents = ["XSS_AGENT", "SQL_AGENT", "XXE_AGENT", "PROTO_AGENT", "HEADER_INJECTION", "IDOR_AGENT", "IGNORE"]
            for agent in valid_agents:
                if agent in decision and "NOT" not in decision:
                    return agent

        return "IGNORE"
    def _fallback_classification(self, vuln: dict) -> str:
        """Fallback classification when LLM fails."""
        v_type = str(vuln.get("type", "")).upper()
        if "XML" in v_type: return "XXE_AGENT"
        if "PROTO" in v_type: return "PROTO_AGENT"
        if "HEADER" in v_type: return "HEADER_INJECTION"
        return "IGNORE"
    def _extract_attack_chains(self, response: str) -> list:
        """Extract attack chains from LLM response."""
        from bugtrace.utils.parsers import XmlParser

        chain_contents = XmlParser.extract_list(response, "chain")
        chains = []

        for cc in chain_contents:
            chains.append({
                "name": XmlParser.extract_tag(cc, "name") or "Unnamed Chain",
                "vulnerabilities": XmlParser.extract_tag(cc, "vulnerabilities") or "",
                "impact": XmlParser.extract_tag(cc, "impact") or "High"
            })

        return chains
