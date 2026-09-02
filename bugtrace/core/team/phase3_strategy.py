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
from bugtrace.core.specialist_route_policy import classify_vuln_type



from bugtrace.core.team.phase3_load import load_phase3_findings

async def run_phase_3_strategy(agent, dashboard, analysis_json_dir: Path) -> int:
    all_findings = await load_phase3_findings(agent, dashboard, analysis_json_dir)
    # Local to this function (not returned by load_phase3_findings) — needed by
    # PP / SSRF auto-dispatch blocks below that were split across dual modules.
    has_any_param_finding = any(
        f.get("parameter")
        and f.get("parameter") not in ("", "General DOM", "DOM", "DOM/Body")
        for f in all_findings
    )
    # Auto-dispatch XSSAgent when no XSS finding from DASTySAST.
    # XSSAgent handles DOM XSS (Phase B.2) which requires Playwright.
    # DOM XSS can exist even without reflected params (e.g., jQuery href sinks).
    has_xss = any(
        classify_vuln_type(f.get("type", "")) == "xss"
        for f in all_findings
    )
    if not has_xss:
        first_url = agent.target
        for f in all_findings:
            if f.get("url"):
                first_url = f["url"]
                break
        synthetic_xss = {
            "type": "XSS",
            "parameter": "auto_dispatch",
            "url": first_url,
            "severity": "High",
            "fp_confidence": 0.9,
            "confidence_score": 0.9,
            "votes": 5,
            "skeptical_score": 8,
            "reasoning": "Auto-dispatch: XSSAgent will perform autonomous XSS testing including DOM XSS detection via Playwright.",
            "payload": "",
            "evidence": "Auto-dispatched for DOM XSS coverage (Phase B.2)",
            "_source_file": "auto_dispatch",
            "_scan_context": agent.scan_context,
            "_auto_dispatched": True
        }
        all_findings.append(synthetic_xss)
        logger.info("[Auto-Dispatch] Added synthetic XSS finding for DOM XSS coverage")
        logger.info("🔧 Auto-dispatch: XSS finding injected (DOM XSS coverage)")

    # Auto-dispatch OpenRedirectAgent when recon URLs contain redirect-like params.
    # Open redirects are commonly missed because DASTySAST focuses on reflection,
    # not redirect behavior. OpenRedirectAgent tests actual HTTP redirect responses.
    has_openredirect = any(
        'redirect' in f.get("type", "").lower() or 'open redirect' in f.get("type", "").lower()
        for f in all_findings
    )
    if not has_openredirect:
        redirect_param_names = {
            "url", "redirect", "redirect_url", "redirect_uri", "return",
            "return_url", "return_to", "next", "goto", "dest", "destination",
            "continue", "redir", "target", "forward", "out", "view", "ref",
        }
        urls_file = getattr(agent, 'report_dir', None)
        if urls_file:
            urls_file = urls_file / "recon" / "urls.txt"
        redirect_url = None
        redirect_param = None
        # Search recon/urls.txt (GoSpider output)
        if urls_file and urls_file.exists():
            for line in urls_file.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                parsed_redir = urlparse(line)
                for p in parse_qs(parsed_redir.query).keys():
                    if p.lower() in redirect_param_names:
                        redirect_url = line
                        redirect_param = p
                        break
                if redirect_url:
                    break
        # Also search urls_to_scan (includes common endpoint discoveries)
        if not redirect_url:
            for line in getattr(agent, 'urls_to_scan', []):
                parsed_redir = urlparse(line)
                for p in parse_qs(parsed_redir.query).keys():
                    if p.lower() in redirect_param_names:
                        redirect_url = line
                        redirect_param = p
                        break
                if redirect_url:
                    break
        if redirect_url and redirect_param:
            synthetic_redir = {
                "type": "Open Redirect",
                "parameter": redirect_param,
                "url": redirect_url,
                "severity": "Medium",
                "fp_confidence": 0.9,
                "confidence_score": 0.9,
                "votes": 5,
                "skeptical_score": 7,
                "reasoning": f"Auto-dispatch: URL parameter '{redirect_param}' suggests redirect behavior. OpenRedirectAgent will test for open redirect.",
                "payload": "",
                "evidence": f"Recon URL contains redirect-like parameter: {redirect_param}",
                "_source_file": "auto_dispatch",
                "_scan_context": agent.scan_context,
                "_auto_dispatched": True
            }
            all_findings.append(synthetic_redir)
            logger.info(f"[Auto-Dispatch] Added synthetic Open Redirect finding: param='{redirect_param}' on {redirect_url}")
            logger.info(f"Auto-dispatch: Open Redirect finding injected for param='{redirect_param}'")

    # FIX (2026-02-16): Auto-dispatch IDORAgent for recon URLs with numeric path segments.
    # DASTySAST LLM is non-deterministic about classifying /api/reviews/1, /api/orders/1 as IDOR.
    # IDORAgent has autonomous _discover_idor_params() — just needs the trigger URL.
    # Scan recon URLs for numeric path segments and inject synthetic IDOR findings.
    has_idor = any(
        'idor' in f.get('type', '').lower()
        or 'insecure direct object' in f.get('type', '').lower()
        or 'broken access' in f.get('type', '').lower()
        for f in all_findings
    )
    idor_urls_file = getattr(agent, 'report_dir', None)
    if idor_urls_file:
        idor_urls_file = idor_urls_file / "recon" / "urls.txt"
    if idor_urls_file and idor_urls_file.exists():
        import re
        numeric_path_re = re.compile(r'/\d+(?:/|$|\?)')
        existing_idor_urls = set()
        if has_idor:
            existing_idor_urls = {
                urlparse(f.get('url', '')).path.rstrip('/')
                for f in all_findings
                if 'idor' in f.get('type', '').lower()
                or 'insecure direct object' in f.get('type', '').lower()
            }
        seen_idor_bases = set()
        idor_injected = 0
        for line in idor_urls_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            parsed_idor = urlparse(line)
            path = parsed_idor.path.rstrip('/')
            if not numeric_path_re.search(path):
                continue
            # Deduplicate by base path (strip the numeric segment to get the resource type)
            # e.g., /api/reviews/1 and /api/reviews/2 → base = /api/reviews
            base_path = re.sub(r'/\d+(?=/|$)', '', path)
            if base_path in seen_idor_bases:
                continue
            seen_idor_bases.add(base_path)
            if path in existing_idor_urls:
                continue
            synthetic_idor = {
                "type": "IDOR",
                "parameter": "URL Path (/{id})",
                "url": line.split('?')[0],  # Strip query params, keep path with ID
                "severity": "High",
                "fp_confidence": 0.9,
                "confidence_score": 0.9,
                "votes": 5,
                "skeptical_score": 8,
                "reasoning": f"Auto-dispatch: Numeric path segment detected in '{path}'. IDORAgent will test for authorization bypass.",
                "payload": "",
                "evidence": f"Recon URL contains numeric path ID: {path}",
                "_source_file": "auto_dispatch_idor_recon",
                "_scan_context": agent.scan_context,
                "_auto_dispatched": True
            }
            all_findings.append(synthetic_idor)
            idor_injected += 1
            logger.debug(f"[Auto-Dispatch] IDOR recon URL: {path} (base: {base_path})")
        # Also check urls_to_scan (includes Endpoint Discovery URLs not in urls.txt)
        for url in getattr(agent, 'urls_to_scan', []):
            parsed_idor = urlparse(url)
            path = parsed_idor.path.rstrip('/')
            if not numeric_path_re.search(path):
                continue
            base_path = re.sub(r'/\d+(?=/|$)', '', path)
            if base_path in seen_idor_bases:
                continue
            seen_idor_bases.add(base_path)
            if path in existing_idor_urls:
                continue
            all_findings.append({
                "type": "IDOR",
                "parameter": "URL Path (/{id})",
                "url": url.split('?')[0],
                "severity": "High",
                "fp_confidence": 0.9,
                "confidence_score": 0.9,
                "votes": 5,
                "skeptical_score": 8,
                "reasoning": f"Auto-dispatch: Numeric path segment in '{path}' (from endpoint discovery).",
                "payload": "",
                "evidence": f"Endpoint discovery URL with numeric path ID: {path}",
                "_source_file": "auto_dispatch_idor_endpoint",
                "_scan_context": agent.scan_context,
                "_auto_dispatched": True
            })
            idor_injected += 1

        if idor_injected > 0:
            agent._v.emit("strategy.auto_dispatch", {"specialist": "IDOR", "count": idor_injected})
            logger.info(f"[Auto-Dispatch] Injected {idor_injected} synthetic IDOR findings from recon URLs with numeric paths")
            logger.info(f"Auto-dispatch: {idor_injected} IDOR findings injected (numeric path IDs)")

    # Auto-dispatch PrototypePollutionAgent when JS frameworks detected and reflecting params exist.
    # PP is common in AngularJS/React apps but DASTySAST pre-filters PP findings as FP (low skeptical).
    has_pp = any(
        'prototype' in f.get('type', '').lower() or 'pollution' in f.get('type', '').lower()
        for f in all_findings
    )
    has_js_framework = any(
        fw_name in f.lower()
        for f in getattr(agent, 'tech_profile', {}).get('frameworks', [])
        for fw_name in ('angular', 'react', 'vue', 'jquery', 'backbone', 'ember')
    )
    if not has_pp and has_any_param_finding and has_js_framework:
        pp_param_finding = next(
            (f for f in all_findings
             if f.get('parameter') and f['parameter'] not in (
                 '', '_auto_dispatch', 'auto_dispatch',
                 'General DOM', 'DOM', 'DOM/Body',
             )),
            None
        )
        pp_param = pp_param_finding["parameter"] if pp_param_finding else "_auto_dispatch"
        # Always use scan target for PP — it's a client-side vuln that needs real pages, not API endpoints.
        pp_url = agent.target

        synthetic_pp = {
            "type": "Prototype Pollution",
            "parameter": pp_param,
            "url": pp_url,
            "severity": "High",
            "fp_confidence": 0.9,
            "confidence_score": 0.9,
            "votes": 5,
            "skeptical_score": 8,
            "probe_validated": True,
            "reasoning": f"Auto-dispatch: JS framework detected, testing {pp_param} for prototype pollution",
            "description": f"Potential Prototype Pollution in parameter '{pp_param}' (JS framework detected)",
            "_source_file": "auto_dispatch_prototype_pollution",
            "_scan_context": agent.scan_context,
            "_auto_dispatched": True
        }
        all_findings.append(synthetic_pp)
        agent._v.emit("strategy.auto_dispatch", {"specialist": "PROTOTYPE_POLLUTION", "count": 1})
        logger.info(f"[Auto-Dispatch] Added synthetic Prototype Pollution finding: param='{pp_param}' (JS framework detected)")
        logger.info(f"Auto-dispatch: Prototype Pollution (JS framework detected)")

    # Auto-dispatch LFIAgent when file-like parameters found in recon URLs.
    # LFI is commonly missed by DASTySAST when params look benign (e.g., "file", "page").
    has_lfi = any(
        'lfi' in f.get('type', '').lower()
        or 'file inclusion' in f.get('type', '').lower()
        or 'path traversal' in f.get('type', '').lower()
        or 'directory traversal' in f.get('type', '').lower()
        for f in all_findings
    )
    if not has_lfi:
        lfi_param_names = {
            "file", "path", "dir", "page", "include", "template",
            "doc", "filename", "download", "filepath", "document",
            "folder", "root", "pg", "style", "pdf", "img", "image",
        }
        lfi_url = None
        lfi_param = None
        recon_file = getattr(agent, 'report_dir', None)
        if recon_file:
            recon_file = recon_file / "recon" / "urls.txt"
        if recon_file and recon_file.exists():
            for line in recon_file.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                parsed_lfi = urlparse(line)
                for p in parse_qs(parsed_lfi.query).keys():
                    if p.lower() in lfi_param_names:
                        lfi_url = line
                        lfi_param = p
                        break
                if lfi_url:
                    break
        if lfi_url and lfi_param:
            synthetic_lfi = {
                "type": "LFI",
                "parameter": lfi_param,
                "url": lfi_url,
                "severity": "High",
                "fp_confidence": 0.9,
                "confidence_score": 0.9,
                "votes": 5,
                "skeptical_score": 8,
                "reasoning": f"Auto-dispatch: File-like parameter '{lfi_param}' found. LFIAgent will test for path traversal.",
                "payload": "",
                "evidence": f"Recon URL contains file-like parameter: {lfi_param}",
                "_source_file": "auto_dispatch_lfi",
                "_scan_context": agent.scan_context,
                "_auto_dispatched": True
            }
            all_findings.append(synthetic_lfi)
            logger.info(f"[Auto-Dispatch] Added synthetic LFI finding: param='{lfi_param}' on {lfi_url}")
            logger.info(f"Auto-dispatch: LFI finding injected for param='{lfi_param}'")

    # Auto-dispatch RCEAgent when command-like parameters found in recon URLs.
    # RCE auto-dispatch: Always scan for command-like params in recon URLs AND findings.
    # Even if DASTySAST found "RCE" from a debug page, the real cmd endpoint may be elsewhere.
    rce_param_names = {
        "cmd", "command", "exec", "execute", "run", "shell",
        "ping", "code", "func", "arg", "process",
    }
    rce_injected_urls = set()

    # Scan recon URLs for command-like params
    recon_file_rce = getattr(agent, 'report_dir', None)
    if recon_file_rce:
        recon_file_rce = recon_file_rce / "recon" / "urls.txt"
    if recon_file_rce and recon_file_rce.exists():
        for line in recon_file_rce.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            parsed_rce = urlparse(line)
            for p in parse_qs(parsed_rce.query).keys():
                if p.lower() in rce_param_names and line not in rce_injected_urls:
                    all_findings.append({
                        "type": "RCE",
                        "parameter": p,
                        "url": line,
                        "severity": "Critical",
                        "fp_confidence": 0.9,
                        "confidence_score": 0.9,
                        "votes": 5,
                        "skeptical_score": 8,
                        "reasoning": f"Auto-dispatch: Command-like parameter '{p}' found in recon URL.",
                        "payload": "",
                        "evidence": f"Recon URL contains command-like parameter: {p}",
                        "_source_file": "auto_dispatch_rce",
                        "_scan_context": agent.scan_context,
                        "_auto_dispatched": True
                    })
                    rce_injected_urls.add(line)
                    logger.info(f"[Auto-Dispatch] RCE from recon URL: param='{p}' on {line}")

    # Also scan DASTySAST findings for cmd-like params pointing to specific endpoints
    for f in all_findings:
        f_url = f.get("url", "")
        f_param = f.get("parameter", "")
        if f_url and f_param and f_param.lower() in rce_param_names and f_url not in rce_injected_urls:
            # Only inject if finding URL is not already an RCE auto-dispatch
            if not f.get("_auto_dispatched"):
                all_findings.append({
                    "type": "RCE",
                    "parameter": f_param,
                    "url": f_url,
                    "severity": "Critical",
                    "fp_confidence": 0.9,
                    "confidence_score": 0.9,
                    "votes": 5,
                    "skeptical_score": 8,
                    "reasoning": f"Auto-dispatch: DASTySAST found command-like parameter '{f_param}'.",
                    "payload": f.get("payload", ""),
                    "evidence": f.get("evidence", f"DAST finding with cmd-like param: {f_param}"),
                    "_source_file": "auto_dispatch_rce_from_dast",
                    "_scan_context": agent.scan_context,
                    "_auto_dispatched": True
                })
                rce_injected_urls.add(f_url)

    if rce_injected_urls:
        logger.info(f"Auto-dispatch: {len(rce_injected_urls)} RCE target(s) injected")

    # Auto-dispatch SSRFAgent when URL-accepting parameters found in recon URLs.
    # SSRF params (callback, webhook, import) differ from open redirect params.
    has_ssrf = any(
        'ssrf' in f.get('type', '').lower()
        or 'server-side request' in f.get('type', '').lower()
        or 'server side request' in f.get('type', '').lower()
        for f in all_findings
    )
    if not has_ssrf:
        ssrf_param_names = {
            "callback", "webhook", "import", "import_url", "fetch",
            "src", "source", "feed", "rss", "proxy", "api_url",
            "load_url", "remote", "endpoint", "request", "image_url",
            "avatar", "icon_url",
        }
        ssrf_url = None
        ssrf_param = None
        recon_file_ssrf = getattr(agent, 'report_dir', None)
        if recon_file_ssrf:
            recon_file_ssrf = recon_file_ssrf / "recon" / "urls.txt"
        if recon_file_ssrf and recon_file_ssrf.exists():
            for line in recon_file_ssrf.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                parsed_ssrf = urlparse(line)
                for p in parse_qs(parsed_ssrf.query).keys():
                    if p.lower() in ssrf_param_names:
                        ssrf_url = line
                        ssrf_param = p
                        break
                if ssrf_url:
                    break
        # Fallback: if no SSRF-specific param found but target has API endpoints,
        # dispatch SSRF with any URL-like param (url param already handled by OR)
        if not ssrf_url and has_any_param_finding:
            for f in all_findings:
                p = f.get('parameter', '').lower()
                if p in ('url', 'uri', 'href', 'link'):
                    ssrf_url = f.get('url', agent.target)
                    ssrf_param = f.get('parameter', 'url')
                    break
        if ssrf_url and ssrf_param:
            synthetic_ssrf = {
                "type": "SSRF",
                "parameter": ssrf_param,
                "url": ssrf_url,
                "severity": "High",
                "fp_confidence": 0.9,
                "confidence_score": 0.9,
                "votes": 5,
                "skeptical_score": 8,
                "reasoning": f"Auto-dispatch: URL-accepting parameter '{ssrf_param}' found. SSRFAgent will test for server-side request forgery.",
                "payload": "",
                "evidence": f"Recon URL contains URL-accepting parameter: {ssrf_param}",
                "_source_file": "auto_dispatch_ssrf",
                "_scan_context": agent.scan_context,
                "_auto_dispatched": True
            }
            all_findings.append(synthetic_ssrf)
            logger.info(f"[Auto-Dispatch] Added synthetic SSRF finding: param='{ssrf_param}' on {ssrf_url}")
            logger.info(f"Auto-dispatch: SSRF finding injected for param='{ssrf_param}'")

    # ===== Auto-dispatch MassAssignmentAgent for PUT/PATCH/POST endpoints =====
    # Mass assignment tests all writable endpoints — doesn't depend on DASTySAST detecting it
    mass_assign_urls = set()
    for f in all_findings:
        f_url = f.get("url", "")
        if f_url and any(kw in f_url.lower() for kw in [
            "/user", "/profile", "/account", "/register", "/settings",
            "/preferences", "/checkout", "/order", "/admin",
            "/api/user", "/api/auth", "/api/admin"
        ]):
            mass_assign_urls.add(f_url)

    # Also add from recon URLs
    for url in agent.urls_to_scan:
        if any(kw in url.lower() for kw in [
            "/user", "/profile", "/account", "/register", "/settings",
            "/preferences", "/checkout", "/order"
        ]):
            mass_assign_urls.add(url)

    if mass_assign_urls:
        ma_injected = 0
        for ma_url in mass_assign_urls:
            synthetic_ma = {
                "type": "Mass Assignment",
                "parameter": "auto_dispatch",
                "url": ma_url,
                "severity": "High",
                "fp_confidence": 0.9,
                "confidence_score": 0.9,
                "votes": 5,
                "skeptical_score": 8,
                "probe_validated": True,
                "reasoning": f"Auto-dispatch: Writable endpoint detected. MassAssignmentAgent will test for parameter pollution.",
                "payload": "",
                "evidence": f"Endpoint may accept additional fields: {ma_url}",
                "_source_file": "auto_dispatch_mass_assignment",
                "_scan_context": agent.scan_context,
                "_auto_dispatched": True
            }
            all_findings.append(synthetic_ma)
            ma_injected += 1
        if ma_injected > 0:
            agent._v.emit("strategy.auto_dispatch", {"specialist": "MASS_ASSIGNMENT", "count": ma_injected})
            logger.info(f"[Auto-Dispatch] Injected {ma_injected} mass assignment findings for writable endpoints")
            logger.info(f"Auto-dispatch: {ma_injected} mass assignment targets injected")

    # ===== BAC Detection: pure filter + decide; shell owns HTTP =====
    from bugtrace.core.bac_policy import (
        filter_admin_urls,
        origin_of,
        decide_bac_from_probe,
    )

    admin_bac_findings = []
    admin_urls_to_check = filter_admin_urls(agent.urls_to_scan)
    if admin_urls_to_check:
        import aiohttp as _aiohttp
        # Per-origin catch-all "shell" signature. Pure ``decide_bac_from_probe``
        # applies SPA FP rules; shell only fetches admin + junk control path.
        shell_sig: Dict[str, tuple] = {}

        async def _catch_all_signature(session, origin: str) -> tuple:
            if origin in shell_sig:
                return shell_sig[origin]
            sig = (None, -1)
            try:
                async with session.get(f"{origin}/__btai_nonexistent_control__") as jr:
                    jbody = await jr.text()
                    sig = (jr.status, len(jbody))
            except Exception:
                pass
            shell_sig[origin] = sig
            return sig

        try:
            async with _aiohttp.ClientSession(timeout=_aiohttp.ClientTimeout(total=5)) as bac_session:
                for admin_url in admin_urls_to_check:
                    try:
                        async with bac_session.get(admin_url) as resp:
                            body = await resp.text()
                            ctype = resp.headers.get("content-type", "")
                            junk_status, junk_len = None, -1
                            if "json" not in ctype.lower():
                                origin = origin_of(admin_url)
                                if origin:
                                    junk_status, junk_len = await _catch_all_signature(
                                        bac_session, origin
                                    )
                            finding = decide_bac_from_probe(
                                admin_url,
                                status_code=resp.status,
                                body=body,
                                content_type=ctype,
                                junk_status=junk_status,
                                junk_body_len=junk_len if junk_len is not None else -1,
                            )
                            if finding is None and resp.status == 200 and "json" not in ctype.lower():
                                logger.debug(
                                    f"[BAC] SPA-shell FP or empty skipped: {admin_url}"
                                )
                            if finding:
                                admin_bac_findings.append(finding)
                    except Exception:
                        continue
        except Exception as bac_err:
            logger.debug(f"BAC detection error: {bac_err}")

    if admin_bac_findings:
        # Write BAC findings directly to results (pre-validated)
        try:
            results_dir = agent.report_dir / "specialists" / "results"
            results_dir.mkdir(parents=True, exist_ok=True)
            bac_path = results_dir / "bac_detection_results.json"
            import json as json_mod
            bac_path.write_text(json_mod.dumps({
                "agent": "BACDetector",
                "timestamp": datetime.now().isoformat(),
                "scan_context": agent.scan_context,
                "phase_a": {"wet_count": len(admin_bac_findings), "dry_count": len(admin_bac_findings)},
                "phase_b": {"validated_count": len(admin_bac_findings), "total_findings": len(admin_bac_findings)},
                "findings": admin_bac_findings
            }, indent=2))
            logger.info(f"[BAC] Detected {len(admin_bac_findings)} admin endpoints accessible without auth")
            dashboard.log(f"BAC: {len(admin_bac_findings)} admin endpoints accessible without authentication", "WARNING")
        except Exception as bac_write_err:
            logger.warning(f"Failed to write BAC results: {bac_write_err}")

    # Inject Nuclei misconfigs: pure partition → shell write / enqueue
    misconfigs = agent.tech_profile.get("misconfigurations", [])
    if misconfigs:
        from bugtrace.core.nuclei_routing_policy import partition_nuclei_misconfigs

        routing_rules = agent._load_nuclei_routing_rules()
        partitioned = partition_nuclei_misconfigs(
            misconfigs,
            routing_rules,
            target=agent.target,
            scan_context=agent.scan_context,
        )
        all_findings.extend(partitioned["route"])
        pre_validated_misconfigs = partitioned["classify"]

        # Write pre-validated misconfigs directly to results (bypass specialist queue)
        if pre_validated_misconfigs:
            try:
                results_dir = agent.report_dir / "specialists" / "results"
                results_dir.mkdir(parents=True, exist_ok=True)
                misconfig_path = results_dir / "nuclei_misconfig_results.json"
                import json as json_mod
                misconfig_path.write_text(json_mod.dumps({
                    "agent": "NucleiMisconfigValidator",
                    "timestamp": datetime.now().isoformat(),
                    "scan_context": agent.scan_context,
                    "phase_a": {"wet_count": len(pre_validated_misconfigs), "dry_count": len(pre_validated_misconfigs)},
                    "phase_b": {"validated_count": len(pre_validated_misconfigs), "total_findings": len(pre_validated_misconfigs)},
                    "findings": pre_validated_misconfigs
                }, indent=2))
                logger.info(f"[Nuclei] Wrote {len(pre_validated_misconfigs)} pre-validated misconfigs to {misconfig_path}")
            except Exception as mc_err:
                logger.warning(f"Failed to write misconfig results: {mc_err}")

        agent._v.emit("strategy.nuclei_injected", {"count": len(misconfigs)})
        logger.info(
            f"[Nuclei] Processed {len(misconfigs)} misconfiguration findings "
            f"({len(pre_validated_misconfigs)} pre-validated, "
            f"{len(partitioned['route'])} routed, {partitioned['skipped']} skipped)"
        )
        logger.info(f"Nuclei: {len(misconfigs)} security misconfigurations detected")

    logger.info(f"Processing {len(all_findings)} findings...")

    # Pass to ThinkingAgent for batch processing
    processed_count = 0
    if agent.thinking_agent and hasattr(agent.thinking_agent, 'process_batch_from_list'):
        processed_count = await agent.thinking_agent.process_batch_from_list(
            all_findings,
            scan_context=agent.scan_context
        )
        logger.info(f"ThinkingAgent processed {processed_count} findings")
    else:
        logger.warning("ThinkingAgent does not support batch processing from list")

    # Flush any remaining batch buffer
    if agent.thinking_agent and hasattr(agent.thinking_agent, 'flush_batch'):
        flushed = await agent.thinking_agent.flush_batch()
        logger.info(f"Flushed {flushed} buffered findings")

    # Log statistics
    if agent.thinking_agent and hasattr(agent.thinking_agent, 'log_batch_summary'):
        agent.thinking_agent.log_batch_summary()

    dashboard.log(
        f"Strategy phase complete: {processed_count} findings distributed to queues",
        "INFO"
    )

    # Update dashboard with deduplication metrics
    if agent.thinking_agent and hasattr(agent.thinking_agent, 'get_stats'):
        stats = agent.thinking_agent.get_stats()
        dashboard.set_progress_metrics(
            findings_before_dedup=stats.get('total_findings', len(all_findings)),
            findings_after_dedup=stats.get('unique_findings', processed_count),
            findings_distributed=stats.get('distributed', processed_count),
            dedup_effectiveness=stats.get('dedup_rate', 0.0) * 100,  # Convert to percentage
            scan_id=agent.scan_id
        )

    return processed_count

