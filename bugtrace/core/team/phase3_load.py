"""Phase-3 strategy shell.

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



async def load_phase3_findings(agent, dashboard, analysis_json_dir: Path) -> list:
    """
    Execute Phase 3: STRATEGY - Batch processing of DAST and AuthDiscovery findings.

    Reads:
    1. DAST findings from analysis_json_dir (numbered JSON files)
    2. AuthDiscovery findings from recon/auth_discovery/ (JWTs, cookies)

    Passes to ThinkingAgent for deduplication, classification, prioritization,
    and queue distribution.

    Args:
        dashboard: UI dashboard
        analysis_json_dir: Directory containing numbered JSON reports from DAST

    Returns:
        Total number of findings processed
    """
    import json

    logger.info(f"Reading JSON files from {analysis_json_dir}")

    # Find all JSON files (numbered format: 1.json, 2.json, etc.)
    json_files = sorted(analysis_json_dir.glob("*.json"))

    if not json_files:
        logger.warning(f"No JSON files found in {analysis_json_dir}")

    logger.info(f"Found {len(json_files)} DAST JSON files to process")

    # Load all findings from DAST JSON files
    all_findings = []
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            findings = data.get("vulnerabilities", [])

            # Attach metadata for traceability
            for finding in findings:
                finding["_source_file"] = str(json_file)
                finding["_scan_context"] = agent.scan_context
                # Attach report_files reference (v2.1.0 payload preservation)
                finding["_report_files"] = {
                    "json": str(json_file),
                    "markdown": str(json_file.with_suffix(".md"))
                }

            all_findings.extend(findings)
            logger.debug(f"Loaded {len(findings)} findings from {json_file.name}")

        except Exception as e:
            logger.error(f"Failed to read {json_file}: {e}")
            continue

    logger.info(f"Loaded {len(all_findings)} DAST findings from {len(json_files)} files")

    # NEW: Load AuthDiscovery findings from recon/auth_discovery/
    auth_discovery_dir = agent.scan_dir / "recon" / "auth_discovery"
    if auth_discovery_dir.exists():
        auth_findings = await agent._load_auth_discovery_findings(auth_discovery_dir)
        if auth_findings:
            all_findings.extend(auth_findings)
            logger.info(f"Loaded {len(auth_findings)} AuthDiscovery findings")
            logger.info(f"🔑 Loaded {len(auth_findings)} authentication artifacts")

            # Track in batch metrics for integrity check
            batch_metrics.add_auth_findings(len(auth_findings))

    logger.info(f"Total {len(all_findings)} findings ready for processing")

    # FIX (2026-02-06): Auto-dispatch CSTIAgent if Angular/Vue detected in tech_profile
    # This ensures CSTIAgent runs even if DASTySAST didn't flag CSTI (LLM non-determinism)
    csti_frameworks = ['angular', 'angularjs', 'vue', 'vuejs', 'vue.js']
    detected_frameworks = agent.tech_profile.get('frameworks', [])
    frameworks_lower = [f.lower() for f in detected_frameworks]

    detected_csti_framework = None
    for fw in csti_frameworks:
        if any(fw in f for f in frameworks_lower):
            detected_csti_framework = fw
            break

    if detected_csti_framework:
        # Deduplicate: only inject for params NOT already in CSTI findings
        existing_csti_params = set()
        for f in all_findings:
            ftype = f.get('type', '').upper()
            if ftype in ['CSTI', 'CLIENT-SIDE TEMPLATE INJECTION', 'TEMPLATE INJECTION']:
                existing_csti_params.add(f.get('parameter', ''))

        # Cap total auto-dispatch to 15 to avoid flooding CSTI queue with noise.
        # Only observed query parameters are scheduling evidence. Framework
        # detection alone must never invent an injectable parameter.
        MAX_CSTI_AUTO_DISPATCH = 15
        injected_count = 0
        seen_url_paths = set()

        # --- PRIORITY 1: SPA routes from urls_to_scan ---
        # SPA routes (e.g., /blog, /products) are discovered by common endpoint
        # discovery but aren't in recon/urls.txt (GoSpider can't crawl SPAs).
        # CSTIAgent's _discover_csti_params() will find JS-extracted params
        # (like URLSearchParams) that aren't in HTML forms.
        spa_urls = sorted(getattr(agent, 'urls_to_scan', []))
        for scan_url in spa_urls:
            if injected_count >= MAX_CSTI_AUTO_DISPATCH:
                break
            parsed_su = urlparse(scan_url)
            url_path = parsed_su.path.rstrip("/")
            # Only non-API pages (SPA routes where Angular/Vue renders)
            if "/api/" in url_path or url_path in seen_url_paths:
                continue
            if not url_path or url_path == "/":
                continue
            su_params = parse_qs(parsed_su.query)
            if not su_params:
                continue
            seen_url_paths.add(url_path)
            spa_param = list(su_params.keys())[0]
            synthetic_csti = {
                "type": "CSTI",
                "parameter": spa_param,
                "url": scan_url,
                "severity": "Info",
                "fp_confidence": 0.0,
                "confidence_score": 0.0,
                "votes": 0,
                "skeptical_score": 0,
                "reasoning": f"Probe job: observed query parameter on a {detected_csti_framework.upper()} page.",
                "payload": "",
                "evidence": f"tech_profile.frameworks contains: {detected_frameworks}",
                "template_engine": detected_csti_framework,
                "_source_file": "auto_dispatch_spa",
                "_scan_context": agent.scan_context,
                "_auto_dispatched": True
            }
            all_findings.append(synthetic_csti)
            injected_count += 1
            logger.debug(f"[Auto-Dispatch] CSTI SPA route: {url_path} (param: {spa_param})")

        # --- PRIORITY 2: Recon URLs from GoSpider ---
        # Dispatch CSTI for unique recon URL paths (not per-param).
        # CSTIAgent's _discover_csti_params() finds all params on each URL autonomously.
        # Injecting per-URL instead of per-param prevents LLM dedup from merging them all.
        urls_file = getattr(agent, 'report_dir', None)
        if urls_file:
            urls_file = urls_file / "recon" / "urls.txt"
        if urls_file and urls_file.exists():
            for line in urls_file.read_text().splitlines():
                if injected_count >= MAX_CSTI_AUTO_DISPATCH:
                    break
                line = line.strip()
                if not line:
                    continue
                parsed_url = urlparse(line)
                url_path = parsed_url.path.rstrip("/")
                if url_path in seen_url_paths or not parsed_url.query:
                    continue
                # Skip API endpoints — CSTI only works on pages where Angular/Vue renders HTML
                if "/api/" in url_path:
                    continue
                seen_url_paths.add(url_path)
                first_param = list(parse_qs(parsed_url.query).keys())[0]
                if first_param in existing_csti_params:
                    continue
                synthetic_csti = {
                    "type": "CSTI",
                    "parameter": first_param,
                    "url": line,
                    "severity": "Info",
                    "fp_confidence": 0.0,
                    "confidence_score": 0.0,
                    "votes": 0,
                    "skeptical_score": 0,
                    "reasoning": f"Probe job: observed query parameter on a {detected_csti_framework.upper()} page.",
                    "payload": "",
                    "evidence": f"tech_profile.frameworks contains: {detected_frameworks}",
                    "template_engine": detected_csti_framework,
                    "_source_file": "auto_dispatch_recon",
                    "_scan_context": agent.scan_context,
                    "_auto_dispatched": True
                }
                all_findings.append(synthetic_csti)
                injected_count += 1
                logger.debug(f"[Auto-Dispatch] CSTI recon URL: {url_path} (param: {first_param})")

        if injected_count > 0:
            agent._v.emit("strategy.auto_dispatch", {
                "specialist": "CSTI", "count": injected_count,
                "framework": detected_csti_framework,
            })
            logger.info(f"[Auto-Dispatch] Injected {injected_count} synthetic CSTI findings with real params (detected: {detected_csti_framework})")
            logger.info(f"Auto-dispatch: {injected_count} CSTI findings injected ({detected_csti_framework.upper()} detected)")

    # Auto-dispatch XXEAgent for XML-processing endpoints (target-agnostic).
    # The live V3 pipeline's DAST is GET-only, so a POST-only XML endpoint — e.g. a
    # <form action="/catalog/product/stock"> that accepts application/xml — never
    # surfaces a DAST finding and XXE is never dispatched. Harvest candidate endpoints
    # (form actions + same-origin path literals from crawled pages) and confirm each
    # with the deterministic _is_xml_endpoint probe: only an endpoint that actually
    # names an XML parse failure passes, so broad candidate harvesting carries no
    # false-positive risk. The XXE agent then confirms in-band (file:///etc/passwd →
    # root:x:0:0 reflected) or OOB. Mirrors the CSTI auto-dispatch above.
    existing_xxe_urls = {
        (f.get("url", "") or "").split("?")[0]
        for f in all_findings
        if "xxe" in (f.get("type", "") or "").lower() or "xml external" in (f.get("type", "") or "").lower()
    }
    try:
        xml_candidates = await agent._harvest_xml_endpoint_candidates()
    except Exception as e:
        logger.debug(f"[Auto-Dispatch] XXE candidate harvest failed: {e}")
        xml_candidates = []
    MAX_XXE_PROBES = 40
    xxe_injected = 0
    for cand in xml_candidates[:MAX_XXE_PROBES]:
        base = cand.split("?")[0]
        if base in existing_xxe_urls:
            continue
        try:
            is_xml = await agent._is_xml_endpoint(cand)
        except Exception:
            is_xml = False
        if not is_xml:
            continue
        existing_xxe_urls.add(base)
        all_findings.append({
            "type": "XXE",
            "parameter": "post_body",
            "url": base,
            "method": "POST",
            "severity": "High",
            "fp_confidence": 0.9,
            "confidence_score": 0.9,
            "votes": 5,
            "skeptical_score": 8,
            "reasoning": f"Auto-dispatch: endpoint processes XML (POST application/xml → XML parse error). XXE candidate '{base}'.",
            "payload": "",
            "evidence": "Deterministic XML-endpoint probe: malformed application/xml body returned an XML parsing-error signal.",
            "_source_file": "auto_dispatch_xxe",
            "_scan_context": agent.scan_context,
            "_auto_dispatched": True,
        })
        xxe_injected += 1
        logger.info(f"🔧 Auto-dispatch XXE: XML-processing endpoint {base}")
    if xxe_injected > 0:
        agent._v.emit("strategy.auto_dispatch", {"specialist": "XXE", "count": xxe_injected})
        logger.info(f"[Auto-Dispatch] Injected {xxe_injected} synthetic XXE findings (XML-processing endpoints)")

    # Auto-dispatch SSTI for template-related admin/API endpoints.
    # DASTySAST often filters server-side SSTI as FP (low fp_confidence).
    # CSTIAgent handles both client-side (CSTI) and server-side (SSTI) template injection.
    ssti_path_keywords = {"template", "email-preview", "render", "preview", "email"}
    ssti_injected_urls = set()
    existing_csti_urls = {f.get("url", "") for f in all_findings if "csti" in f.get("type", "").lower() or "ssti" in f.get("type", "").lower()}

    recon_file_ssti = getattr(agent, 'report_dir', None)
    if recon_file_ssti:
        recon_file_ssti = recon_file_ssti / "recon" / "urls.txt"
    if recon_file_ssti and recon_file_ssti.exists():
        for line in recon_file_ssti.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            path_lower = urlparse(line).path.lower()
            if any(kw in path_lower for kw in ssti_path_keywords):
                base_url = line.split("?")[0]
                if base_url not in ssti_injected_urls and base_url not in existing_csti_urls:
                    all_findings.append({
                        "type": "CSTI",
                        "parameter": "body",
                        "url": base_url,
                        "severity": "High",
                        "fp_confidence": 0.9,
                        "confidence_score": 0.9,
                        "votes": 5,
                        "skeptical_score": 8,
                        "reasoning": f"Auto-dispatch: SSTI-likely path '{path_lower}' detected in recon URL.",
                        "payload": "",
                        "evidence": f"Path contains template keyword: {path_lower}",
                        "template_engine": "jinja2",
                        "_source_file": "auto_dispatch_ssti",
                        "_scan_context": agent.scan_context,
                        "_auto_dispatched": True
                    })
                    ssti_injected_urls.add(base_url)
                    logger.info(f"[Auto-Dispatch] SSTI from recon URL: {base_url}")

    # Also check urls_to_scan for SSTI-likely paths
    for url in getattr(agent, 'urls_to_scan', []):
        path_lower = urlparse(url).path.lower()
        if any(kw in path_lower for kw in ssti_path_keywords):
            base_url = url.split("?")[0]
            if base_url not in ssti_injected_urls and base_url not in existing_csti_urls:
                all_findings.append({
                    "type": "CSTI",
                    "parameter": "body",
                    "url": base_url,
                    "severity": "High",
                    "fp_confidence": 0.9,
                    "confidence_score": 0.9,
                    "votes": 5,
                    "skeptical_score": 8,
                    "reasoning": f"Auto-dispatch: SSTI-likely path '{path_lower}' detected.",
                    "payload": "",
                    "evidence": f"Path contains template keyword: {path_lower}",
                    "template_engine": "jinja2",
                    "_source_file": "auto_dispatch_ssti",
                    "_scan_context": agent.scan_context,
                    "_auto_dispatched": True
                })
                ssti_injected_urls.add(base_url)
                logger.info(f"[Auto-Dispatch] SSTI from scanned URL: {base_url}")

    if ssti_injected_urls:
        logger.info(f"Auto-dispatch: {len(ssti_injected_urls)} SSTI target(s) injected")

    # Auto-dispatch LFI for file/path/download parameters.
    # DASTySAST sometimes rejects path traversal findings (score 0/10) when the
    # endpoint response contains metadata or safe-looking error messages.
    # LFIAgent must always test parameters named file/path/filename/download.
    lfi_param_keywords = {"file", "path", "filename", "filepath", "document", "download", "dir", "include", "page", "template"}
    lfi_injected = set()
    existing_lfi_urls_params = {
        (f.get("url", "").split("?")[0], f.get("parameter", ""))
        for f in all_findings
        if "lfi" in f.get("type", "").lower() or "path" in f.get("type", "").lower() or "traversal" in f.get("type", "").lower()
    }

    recon_file_lfi = getattr(agent, 'report_dir', None)
    if recon_file_lfi:
        recon_file_lfi = recon_file_lfi / "recon" / "urls.txt"
    if recon_file_lfi and recon_file_lfi.exists():
        for line in recon_file_lfi.read_text().splitlines():
            line = line.strip()
            if not line or "?" not in line:
                continue
            parsed_lfi = urlparse(line)
            query_params = parse_qs(parsed_lfi.query)
            for param_name in query_params:
                if param_name.lower() in lfi_param_keywords:
                    base_url = line.split("?")[0]
                    key = (base_url, param_name)
                    if key not in existing_lfi_urls_params and key not in lfi_injected:
                        all_findings.append({
                            "type": "LFI",
                            "parameter": param_name,
                            "url": line,
                            "severity": "High",
                            "fp_confidence": 0.85,
                            "confidence_score": 0.85,
                            "votes": 5,
                            "skeptical_score": 7,
                            "reasoning": f"Auto-dispatch: param '{param_name}' is a common path traversal vector.",
                            "payload": "",
                            "evidence": f"URL param '{param_name}' in recon URL: {line}",
                            "_source_file": "auto_dispatch_lfi",
                            "_scan_context": agent.scan_context,
                            "_auto_dispatched": True
                        })
                        lfi_injected.add(key)

    if lfi_injected:
        logger.info(f"[Auto-Dispatch] LFI: {len(lfi_injected)} path-traversal target(s) injected")
        logger.info(f"Auto-dispatch: {len(lfi_injected)} LFI target(s) injected")

    # FIX (2026-02-08): Auto-dispatch SQLiAgent when reflecting params exist but no SQLi finding
    # SQLi is the most common web vuln - if DASTySAST found ANY parameter, SQLi should be tested.
    # Previous scans found SQLi on ginandjuice.shop but LLM non-determinism caused it to be missed.
    has_sqli = any(
        'sqli' in f.get('type', '').lower() or 'sql' in f.get('type', '').lower()
        for f in all_findings
    )
    has_any_param_finding = any(
        f.get('parameter') and f.get('parameter') not in ('', 'General DOM', 'DOM', 'DOM/Body')
        for f in all_findings
    )

    if not has_sqli and has_any_param_finding:
        # FIX (2026-02-10): Use real reflecting param, not "_auto_dispatch"
        first_real_sqli = next(
            (f for f in all_findings
             if f.get('parameter') and f['parameter'] not in (
                 '', '_auto_dispatch', 'auto_dispatch',
                 'General DOM', 'DOM', 'DOM/Body',
             )),
            None
        )
        sqli_param = first_real_sqli["parameter"] if first_real_sqli else "_auto_dispatch"
        sqli_url = first_real_sqli.get("url", agent.target) if first_real_sqli else agent.target

        synthetic_sqli = {
            "type": "SQLi",
            "parameter": sqli_param,
            "url": sqli_url,
            "severity": "High",
            "fp_confidence": 0.9,
            "confidence_score": 0.9,
            "votes": 5,
            "skeptical_score": 8,
            "reasoning": "Auto-dispatch: Reflecting parameters detected by DASTySAST. SQLiAgent will perform autonomous SQL injection testing on all discovered parameters.",
            "payload": "",
            "evidence": "Auto-dispatched because DASTySAST found reflecting parameters but no SQLi classification",
            "_source_file": "auto_dispatch",
            "_scan_context": agent.scan_context,
            "_auto_dispatched": True
        }
        all_findings.append(synthetic_sqli)
        agent._v.emit("strategy.auto_dispatch", {"specialist": "SQLi", "param": sqli_param})
        logger.info(f"[Auto-Dispatch] Added synthetic SQLi finding: param='{sqli_param}' (reflecting params detected)")
        logger.info(f"Auto-dispatch: SQLi finding injected for param='{sqli_param}'")

    # Gap 2 Fix: Auto-dispatch HeaderInjectionAgent when header reflection detected or params exist
    # CRLF/Header Injection is often missed because DASTySAST only checks body reflection.
    # HeaderInjectionAgent has autonomous _discover_header_params() - just needs the trigger.
    has_header_injection = any(
        'header' in f.get('type', '').lower() or 'crlf' in f.get('type', '').lower()
        for f in all_findings
    )
    has_header_reflection = any(
        f.get('header_reflection') or f.get('context') == 'response_header'
        for f in all_findings
    )

    if not has_header_injection and (has_header_reflection or has_any_param_finding):
        # FIX (2026-02-10): Use real reflecting param
        hi_real = next(
            (f for f in all_findings
             if f.get('parameter') and f['parameter'] not in (
                 '', '_auto_dispatch', 'auto_dispatch',
                 'General DOM', 'DOM', 'DOM/Body',
             )),
            None
        )
        synthetic_header = {
            "type": "Header Injection",
            "parameter": hi_real["parameter"] if hi_real else "_auto_dispatch",
            "url": hi_real.get("url", agent.target) if hi_real else agent.target,
            "severity": "High",
            "fp_confidence": 0.9,
            "confidence_score": 0.9,
            "votes": 5,
            "skeptical_score": 8,
            "reasoning": "Auto-dispatch: " + (
                "Probe marker reflected in response headers (CRLF candidate)"
                if has_header_reflection
                else "Reflecting parameters detected. HeaderInjectionAgent will test for CRLF/response splitting."
            ),
            "payload": "",
            "evidence": "Header reflection detected" if has_header_reflection else "Auto-dispatched for parameter coverage",
            "_source_file": "auto_dispatch",
            "_scan_context": agent.scan_context,
            "_auto_dispatched": True
        }
        all_findings.append(synthetic_header)
        logger.info(f"[Auto-Dispatch] Added synthetic Header Injection finding (header_reflection={has_header_reflection})")
        logger.info(f"🔧 Auto-dispatch: Header Injection finding injected")

    return all_findings

