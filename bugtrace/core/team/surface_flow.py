"""URL surface, discovery, and dedup shell.

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


class TeamSurfaceMixin:
    def _create_url_folders(self, report_dir: Path, urls_scanned: list) -> dict:
        """Create folders for each scanned URL."""
        url_folders = {}
        for u in urls_scanned:
            safe_name = u.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")
            safe_name = safe_name[:100]
            folder = report_dir / safe_name
            folder.mkdir(exist_ok=True)
            url_folders[u] = folder
        return url_folders

    @staticmethod
    def _url_fingerprint(url: str) -> str:
        """Pure owner: surface_url_policy.url_fingerprint."""
        from bugtrace.core.surface_url_policy import url_fingerprint as _fp

        return _fp(url)

    @staticmethod
    def _superset_param_dedup(urls: list) -> tuple:
        """Pure owner: surface_url_policy.superset_param_dedup."""
        from bugtrace.core.surface_url_policy import superset_param_dedup as _dedup

        return _dedup(urls)

    def _normalize_urls(self, urls_to_scan: list) -> list:
        """Deduplicate, normalize, and prioritize URLs.

        Two-layer deduplication:
        1. Fingerprint dedup: canonical path + sorted param_names (ignoring values)
        2. Superset param grouping: collapse URLs where one has a superset of params

        Outputs two files:
        - recon/urls.txt       → raw GoSpider output (audit trail)
        - recon/urls_clean.txt → post-dedup URLs (what DASTySAST processes)

        Always ensures self.target is first in the list.
        """
        from bugtrace.core.batch_metrics import batch_metrics

        raw_count = len(urls_to_scan)

        # Save raw URLs FIRST (before any dedup) — audit trail
        urls_file_raw = self.scan_dir / "recon" / "urls.txt"
        if urls_file_raw.parent.exists():
            with open(urls_file_raw, "w") as f:
                f.write("\n".join(urls_to_scan))
            logger.info(f"[URL Dedup] Saved {raw_count} raw URLs to urls.txt")

        # === Layer 1: Fingerprint Dedup (canonical path + param names) ===
        target_fp = self._url_fingerprint(self.target)
        seen_fingerprints = {target_fp}
        normalized_list = [self.target]
        has_parameterized = '?' in self.target or '=' in self.target
        fingerprint_groups = defaultdict(list)
        fingerprint_groups[target_fp].append(self.target)

        for u in urls_to_scan:
            if '?' in u or '=' in u:
                has_parameterized = True

            fp = self._url_fingerprint(u)
            fingerprint_groups[fp].append(u)
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                normalized_list.append(u)

        layer1_count = len(normalized_list)
        logger.info(f"[URL Dedup] Layer 1 (fingerprint): {raw_count} → {layer1_count} URLs")

        # Log significant groups (3+ URLs collapsed into 1)
        for fp, group in fingerprint_groups.items():
            if len(group) >= 3:
                logger.info(f"[URL Dedup]   Group ({len(group)} URLs): {fp[:80]}")

        # === Layer 2: Superset Param Grouping ===
        deduplicated_list, superset_log = self._superset_param_dedup(normalized_list)
        layer2_count = len(deduplicated_list)

        if layer1_count != layer2_count:
            logger.info(f"[URL Dedup] Layer 2 (superset): {layer1_count} → {layer2_count} URLs")
            for base_key, info in superset_log.items():
                logger.info(f"[URL Dedup]   {base_key[:60]}: kept {len(info['kept'])}, collapsed {info['collapsed_count']}")

        # === Dedup Summary ===
        total_collapsed = raw_count - layer2_count
        reduction_pct = (total_collapsed / raw_count * 100) if raw_count > 0 else 0.0
        logger.info(
            f"[URL Dedup] TOTAL: {raw_count} raw → {layer2_count} unique "
            f"({reduction_pct:.0f}% reduction, {total_collapsed} collapsed)"
        )

        # Record in batch_metrics
        largest_group = max((len(g) for g in fingerprint_groups.values()), default=0)
        batch_metrics.record_url_dedup(raw_count, layer1_count, layer2_count, reduction_pct, largest_group)

        urls_to_scan = deduplicated_list

        # ========== DROP PLAIN-HTTP TWINS ==========
        # Recon routinely keeps both http://host and https://host. The HTTP one is the
        # same site, but it is actively harmful: on any target that redirects HTTP to
        # HTTPS (i.e. almost all of them) every request to that origin is answered by the
        # redirect rather than by the application, so the whole origin becomes a source of
        # confident-looking noise — and it makes the scan do everything twice.
        pre_scheme_count = len(urls_to_scan)
        urls_to_scan = drop_insecure_duplicate_origins(urls_to_scan)
        if len(urls_to_scan) < pre_scheme_count:
            logger.info(
                f"[Origin Normalization] Dropped {pre_scheme_count - len(urls_to_scan)} "
                f"plain-HTTP URLs whose host is already reachable over HTTPS"
            )

        # Prioritize URLs (high-value targets first)
        if settings.URL_PRIORITIZATION_ENABLED:
            urls_to_scan = self._prioritize_urls(urls_to_scan)
        else:
            for u in urls_to_scan:
                logger.info(f">> To Scan: {u}")

        # Enforce strict MAX_URLS limit (Final Safety Net)
        if len(urls_to_scan) > self.max_urls:
            logger.info(f"Enforcing MAX_URLS={self.max_urls}: Trimming {len(urls_to_scan)} -> {self.max_urls} URLs")
            urls_to_scan = urls_to_scan[:self.max_urls]

        # Always ensure user-provided target is first (may have been removed by superset dedup)
        target_norm = self.target.rstrip('/')
        found = False
        for i, u in enumerate(urls_to_scan):
            if u.rstrip('/') == target_norm:
                if i > 0:
                    urls_to_scan.insert(0, urls_to_scan.pop(i))
                    logger.info(f"[Priority] Moved user target to position 1: {self.target}")
                found = True
                break
        if not found:
            urls_to_scan.insert(0, self.target)
            logger.info(f"[Priority] Re-inserted user target at position 1: {self.target}")

        self.url_queue = urls_to_scan
        self._save_checkpoint()

        # Save deduplicated URLs to urls_clean.txt — source of truth for Phase 2
        urls_file_clean = self.scan_dir / "recon" / "urls_clean.txt"
        if urls_file_clean.parent.exists():
            with open(urls_file_clean, "w") as f:
                f.write("\n".join(urls_to_scan))
            logger.info(f"[URL Dedup] Saved {len(urls_to_scan)} clean URLs to urls_clean.txt")

        return urls_to_scan

    async def _enrich_api_detail_endpoints(self, urls: list) -> list:
        """Discover API detail endpoints from list endpoints.

        When GoSpider finds /api/forum/threads (returns JSON array),
        this method extracts IDs and generates detail URLs like
        /api/forum/threads/1 so specialists can test path parameter injection.

        Also discovers sub-resource URLs from response fields
        (e.g., image_url, file fields that hint at additional endpoints).
        """
        api_list_urls = [u for u in urls if "/api/" in u and not re.search(r'/:\w+', u)]
        if not api_list_urls:
            return urls

        new_urls = []
        existing = set(urls)

        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
            for url in api_list_urls:
                try:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        continue
                    content_type = resp.headers.get("content-type", "")
                    if "json" not in content_type:
                        continue

                    data = resp.json()

                    # Case 1: JSON array of objects with id fields
                    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                        first_item = data[0]
                        # Extract the first usable ID
                        id_val = first_item.get("id") or first_item.get("_id")
                        if id_val is not None:
                            detail_url = f"{url.rstrip('/')}/{id_val}"
                            if detail_url not in existing:
                                new_urls.append(detail_url)
                                existing.add(detail_url)

                            # Check for sub-resource hints (file, image fields)
                            base_origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                            for key in first_item:
                                key_lower = key.lower()
                                if any(hint in key_lower for hint in ["image", "file", "avatar", "photo", "attachment"]):
                                    val = first_item[key]
                                    # Handle array of objects with url field: [{"url": "/api/..."}]
                                    sub_urls = []
                                    if isinstance(val, list):
                                        for item in val:
                                            if isinstance(item, dict):
                                                sub_url = item.get("url") or item.get("src") or item.get("href")
                                                if sub_url:
                                                    sub_urls.append(sub_url)
                                    elif isinstance(val, str) and val.startswith(("/", "http")):
                                        sub_urls.append(val)

                                    for sub_url in sub_urls:
                                        abs_url = sub_url if sub_url.startswith("http") else f"{base_origin}{sub_url}"
                                        if abs_url not in existing:
                                            new_urls.append(abs_url)
                                            existing.add(abs_url)

                    # Case 2: Paginated response {items: [...], total: N}
                    elif isinstance(data, dict):
                        items = data.get("items") or data.get("results") or data.get("data")
                        if isinstance(items, list) and len(items) > 0 and isinstance(items[0], dict):
                            first_item = items[0]
                            id_val = first_item.get("id") or first_item.get("_id")
                            if id_val is not None:
                                detail_url = f"{url.rstrip('/')}/{id_val}"
                                if detail_url not in existing:
                                    new_urls.append(detail_url)
                                    existing.add(detail_url)

                except Exception as e:
                    logger.debug(f"[API Enrichment] Failed to enrich {url}: {e}")
                    continue

        if new_urls:
            logger.info(f"[API Enrichment] Discovered {len(new_urls)} detail endpoints: {new_urls}")
            urls.extend(new_urls)
        else:
            logger.debug("[API Enrichment] No new detail endpoints discovered")

        return urls

    async def _discover_common_vuln_endpoints(self, urls: list) -> list:
        """Probe for common vulnerability endpoints not found by crawling.

        Some endpoints (e.g., /api/redirect, /api/admin, /api/debug) are never
        linked from any page but are common attack surfaces. This method probes
        a short list of well-known RESOURCE NAMES and keeps only the ones whose
        response DIFFERS from a guaranteed-nonexistent control path on the same prefix.

        Existence is never inferred from a status code. A target that redirects HTTP to
        HTTPS answers 301 for every path — including paths that do not exist — and a
        soft-404 target answers 200 for every path, so any status-based rule accepts
        endpoints that are not there and floods the scan with confident-looking phantoms.
        Matching words in the body ("not found") is no better: it is a signature list, so
        it breaks on non-English targets, on SPAs and on CDN interstitials.

        The differential is what generalises — the target itself defines what "nothing
        here" looks like. When that definition cannot be established (an unstable or
        rate-limited target), this method FAILS CLOSED and discovers nothing: guessing
        endpoints is a bonus, never the core of a scan. See bugtrace.core.surface.
        """
        # Extract base origins from existing URLs
        origins = set()
        api_prefixes = set()
        for url in urls:
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            origins.add(origin)
            # Detect API prefix patterns (e.g., /api/, /v1/, /api/v1/)
            path = parsed.path
            if "/api/" in path:
                api_prefix = path[:path.index("/api/") + 5]
                api_prefixes.add(f"{origin}{api_prefix}")

        if not api_prefixes:
            # No API endpoints found, try default /api/ prefix
            for origin in origins:
                api_prefixes.add(f"{origin}/api/")

        # Load endpoints from external data files (not hardcoded), keeping only entries
        # that name a resource — never one target's parameters or payloads.
        COMMON_ENDPOINTS = self._load_endpoint_names("common_endpoints.txt")
        SPA_ROUTES = self._load_endpoint_names("spa_routes.txt")

        new_urls = []
        existing = set(urls)

        # follow_redirects=True: a redirect is not an answer. Comparing the FINAL response
        # is what lets the differential see the application instead of the edge.
        async with httpx.AsyncClient(timeout=5, verify=False, follow_redirects=True) as client:

            async def observe(url: str) -> Optional[ProbeObservation]:
                """# I/O — one request, reduced to the fields the pure predicates need."""
                try:
                    resp = await client.get(url)
                    return ProbeObservation(resp.status_code, resp.text, urlparse(url).path)
                except Exception:
                    return None

            async def control_for(base: str) -> Optional[ControlModel]:
                """# I/O — model this origin's "nothing here" response, or None if unknowable.

                Three nonexistent siblings of deliberately different path lengths. The two
                extremes measure how much body each path byte adds (targets echo the
                requested path back, often in a form no literal search would find), and the
                middle one is held out to check the model actually predicts. When it does
                not — jitter, A/B tests, rate limiting kicking in — there is no trustworthy
                verdict and the caller must not guess.
                """
                token = uuid.uuid4().hex
                short = await observe(f"{base.rstrip('/')}/{token[:8]}")
                middle = await observe(f"{base.rstrip('/')}/{uuid.uuid4().hex}")
                long = await observe(f"{base.rstrip('/')}/{uuid.uuid4().hex}{uuid.uuid4().hex}")
                if short is None or middle is None or long is None:
                    return None
                return build_control_model(short, middle, long)

            async def probe_all(base: str, entries: List[str], label: str) -> None:
                """# I/O — probe `entries` under `base`, keeping only what differs."""
                control = await control_for(base)
                if control is None:
                    logger.info(
                        f"[Endpoint Discovery] Skipping {label} on {base}: this origin's "
                        f"not-found response could not be modelled (unreachable, rate-limited "
                        f"or inconsistent) — refusing to guess"
                    )
                    return
                logger.debug(
                    f"[Endpoint Discovery] {base} not-found model: status={control.status} "
                    f"base={control.base_length}b path-echo slope={control.slope:.2f}"
                )
                for entry in entries:
                    probe_url = f"{base.rstrip('/')}/{entry}"
                    if probe_url in existing:
                        continue
                    observation = await observe(probe_url)
                    if observation is None or not differs_from_control(observation, control):
                        continue
                    new_urls.append(probe_url)
                    existing.add(probe_url)
                    logger.info(
                        f"[Endpoint Discovery] Found {label}: {probe_url} "
                        f"(status: {observation.status}, differs from this origin's catch-all)"
                    )

            for prefix in api_prefixes:
                await probe_all(prefix, COMMON_ENDPOINTS, "endpoint")

            # SPA/content routes are probed against the origin, not the API prefix
            for origin in origins:
                await probe_all(origin, SPA_ROUTES, "SPA route")

        if new_urls:
            logger.info(f"[Endpoint Discovery] Discovered {len(new_urls)} common endpoints: {new_urls}")
            urls.extend(new_urls)
        else:
            logger.debug("[Endpoint Discovery] No new common endpoints discovered")

        return urls

    async def _infer_api_from_frontend_routes(self, urls: list) -> list:
        """Infer API endpoints from SPA frontend routes.

        Modern SPAs (React/Vue/Angular) serve identical HTML for all frontend
        routes — the actual data comes from backend API calls. When the crawler
        finds a route like /forum/thread/1, this method generates candidate API
        URLs (/api/forum/thread/1, /api/forum/threads/1, etc.) and probes them.

        This is critical because specialists testing SPA routes get the same
        static HTML regardless of payload, making vulnerability detection
        impossible. The real attack surface is the API endpoint.
        """
        existing = set(urls)
        new_urls = []

        # Collect API prefixes from already-known API URLs
        api_prefixes = set()
        origins = set()
        for url in urls:
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            origins.add(origin)
            if "/api/" in parsed.path:
                prefix_end = parsed.path.index("/api/") + 5
                api_prefixes.add(f"{origin}{parsed.path[:prefix_end]}")

        if not api_prefixes:
            for origin in origins:
                api_prefixes.add(f"{origin}/api/")

        # Identify frontend routes with dynamic path segments (IDs or :param placeholders)
        frontend_candidates = []
        for url in urls:
            parsed = urlparse(url)
            if "/api/" in parsed.path:
                continue  # Already an API URL
            segments = [s for s in parsed.path.strip("/").split("/") if s]
            if len(segments) < 2:
                continue
            for i, seg in enumerate(segments):
                # Detect: numeric IDs, :param placeholders, {param}, UUIDs, hex hashes
                is_dynamic = (
                    re.match(r'^\d+$', seg)
                    or seg.startswith(":")  # Express-style :id, :slug
                    or (seg.startswith("{") and seg.endswith("}"))  # {id}
                    or re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-', seg, re.I)
                    or (re.match(r'^[0-9a-f]{6,}$', seg, re.I) and len(seg) >= 8)
                )
                if is_dynamic and i > 0:
                    frontend_candidates.append((url, parsed, segments, i))
                    break  # One dynamic segment per URL is enough

        if not frontend_candidates:
            return urls

        async with httpx.AsyncClient(timeout=5, verify=False, follow_redirects=True) as client:
            for orig_url, parsed, segments, id_idx in frontend_candidates:
                origin = f"{parsed.scheme}://{parsed.netloc}"
                raw_id = segments[id_idx]  # Could be ":id", "{id}", or "123"
                # For probing, use a real ID; for URL list, keep placeholder
                probe_id = "1"
                if re.match(r'^\d+$', raw_id):
                    probe_id = raw_id
                path_before_id = segments[:id_idx]

                # Generate candidate API paths (probe_url, display_url) pairs
                candidates = []  # (probe_path, final_path)
                for prefix in api_prefixes:
                    p = prefix.rstrip("/")
                    # Pattern 1: Direct — /api/forum/thread/1
                    base = f"{p}/{'/'.join(path_before_id)}"
                    # Always use resolved probe_id in final URL (never keep :id templates)
                    candidates.append((f"{base}/{probe_id}", f"{base}/{probe_id}"))
                    # Pattern 2: Pluralize last segment — /api/forum/threads/1
                    if path_before_id:
                        last = path_before_id[-1]
                        if not last.endswith("s"):
                            parts = list(path_before_id)
                            parts[-1] = last + "s"
                            base_p = f"{p}/{'/'.join(parts)}"
                            candidates.append((f"{base_p}/{probe_id}", f"{base_p}/{probe_id}"))
                    # Pattern 3: Just last segment(s) + ID — /api/threads/1
                    if len(path_before_id) >= 2:
                        base_s = f"{p}/{path_before_id[-1]}"
                        candidates.append((f"{base_s}/{probe_id}", f"{base_s}/{probe_id}"))
                        if not path_before_id[-1].endswith("s"):
                            base_sp = f"{p}/{path_before_id[-1]}s"
                            candidates.append((f"{base_sp}/{probe_id}", f"{base_sp}/{probe_id}"))

                for probe_url, final_url in candidates:
                    if final_url in existing:
                        continue
                    try:
                        resp = await client.get(probe_url)
                        if resp.status_code in (404, 405, 502, 503):
                            continue
                        ct = resp.headers.get("content-type", "")
                        # API endpoints return JSON, not HTML
                        if "json" in ct or "xml" in ct:
                            if final_url not in existing:
                                new_urls.append(final_url)
                                existing.add(final_url)
                                logger.info(
                                    f"[SPA→API] Inferred: {orig_url} → {final_url} "
                                    f"(status: {resp.status_code})"
                                )
                    except Exception:
                        continue

        if new_urls:
            logger.info(f"[SPA→API] Discovered {len(new_urls)} API endpoints from {len(frontend_candidates)} frontend routes")
            urls.extend(new_urls)

        return urls

    def _dedup_url_patterns(self, urls: List[str]) -> List[str]:
        """Collapse identical path patterns. Pure owner: surface_url_policy."""
        from bugtrace.core.surface_url_policy import dedup_url_patterns as _dedup

        deduped, removed = _dedup(urls)
        if removed > 0:
            logger.info(
                f"[URL Pattern Dedup] {len(urls)} → {len(deduped)} URLs "
                f"({removed} pattern duplicates removed)"
            )
        else:
            logger.info(
                f"[URL Pattern Dedup] {len(urls)} URLs, no pattern duplicates found"
            )
        return deduped

    def _prioritize_urls(self, urls: list) -> list:
        """Prioritize URLs by risk score (high-value targets first)."""
        from bugtrace.core.url_prioritizer import prioritize_urls

        # Parse custom paths/params from settings
        custom_paths = [p.strip() for p in settings.URL_PRIORITIZATION_CUSTOM_PATHS.split(',') if p.strip()]
        custom_params = [p.strip() for p in settings.URL_PRIORITIZATION_CUSTOM_PARAMS.split(',') if p.strip()]

        scored_urls = prioritize_urls(urls, custom_paths, custom_params)

        if settings.URL_PRIORITIZATION_LOG_SCORES:
            logger.info(f"[Priority] URL prioritization complete:")
            for i, (url, score) in enumerate(scored_urls[:10], 1):
                logger.info(f"  {i:2d}. [score={score:3d}] {url[:70]}")
            if len(scored_urls) > 10:
                logger.info(f"  ... and {len(scored_urls) - 10} more URLs")

        return [url for url, score in scored_urls]

    def _create_url_directory(self, url: str, analysis_dir: Path) -> Path:
        """Create unique directory for URL analysis outputs."""
        safe_base = url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")[:40]
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        safe_url_name = f"{safe_base}_{url_hash}"
        url_dir = analysis_dir / f"url_{safe_url_name}"
        url_dir.mkdir(exist_ok=True)
        return url_dir

    async def _is_xml_endpoint(self, url: str) -> bool:
        """Deterministic, target-agnostic probe: does this endpoint PROCESS XML? POST a deliberately
        MALFORMED XML body as application/xml — an XML-processing endpoint names the parse failure
        in its response ("XML parsing error", "could not be parsed from XML", "not well-formed", …);
        a JSON/HTML endpoint does not. Catches JS-triggered POST-only XML endpoints (e.g. a
        "check stock" button) that GET-based analysis never sees. No per-target paths/schemas."""
        # team.py has NO module-level import of these names — referencing them bare here
        # raised NameError that the except-clause below silently swallowed, so this probe
        # ALWAYS returned False. Import locally so the probe actually runs.
        from bugtrace.core.http_orchestrator import orchestrator, DestinationType
        import aiohttp
        base = url.split("?")[0]
        low = base.lower()
        if low.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                         ".woff", ".woff2", ".ttf", ".map", ".pdf", ".zip")):
            return False
        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                async with session.post(
                    base, data="<bt_xxe_probe",  # deliberately malformed XML
                    headers={"Content-Type": "application/xml"},
                    timeout=aiohttp.ClientTimeout(total=5), ssl=False,
                    allow_redirects=False,  # a redirect (e.g. -> /login) is not XML processing
                ) as resp:
                    if resp.status in (301, 302, 303, 307, 308, 404, 405):
                        return False
                    body = (await resp.text())[:3000].lower()
        except Exception:
            return False
        xml_signals = ("xml", "not well-formed", "not well formed", "doctype", "external entity",
                       "premature end", "parse", "parsing", "malformed", "<!entity")
        return any(s in body for s in xml_signals)

    async def _harvest_xml_endpoint_candidates(self) -> list:
        """Collect candidate endpoints to probe for XML processing. Target-agnostic:
        the crawl set PLUS same-origin endpoints referenced in crawled pages' HTML —
        form `action` URLs and quoted absolute-path literals (fetch/XHR/router targets).
        The live V3 pipeline's DAST is GET-only, so a POST-only XML endpoint (e.g. a
        <form action="/catalog/product/stock"> that accepts application/xml, invoked by
        a JS "check stock" button) never surfaces a finding. The deterministic
        _is_xml_endpoint probe is the downstream FILTER, so over-broad harvesting here is
        safe — non-XML candidates simply fail the probe. Form actions are returned first
        (highest signal) so they win the probe budget over noisy JS path literals."""
        import re as _re
        from urllib.parse import urljoin
        from bugtrace.core.http_orchestrator import orchestrator as _orch, DestinationType as _DT
        import aiohttp as _aiohttp

        parsed_t = urlparse(self.target)
        origin = f"{parsed_t.scheme}://{parsed_t.netloc}"
        crawl, actions, literals = [], [], []
        seen = set()
        _STATIC = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                   ".woff", ".woff2", ".ttf", ".map", ".pdf", ".zip", ".json",
                   ".xml", ".txt", ".mp4", ".webp")

        def _add(bucket, u):
            if not u:
                return
            u = u.split("#")[0]
            pu = urlparse(u)
            if pu.netloc and pu.netloc != parsed_t.netloc:
                return  # same-origin only
            base = u.split("?")[0]
            if base.lower().endswith(_STATIC):
                return
            if base in seen:
                return
            seen.add(base)
            bucket.append(base)

        # 1) crawl set — probe the base path of every discovered URL
        for u in getattr(self, "urls_to_scan", []) or []:
            _add(crawl, u)

        # 2) harvest endpoints referenced in crawled pages' HTML (form actions + path literals)
        action_re = _re.compile(r'''\baction\s*=\s*["']([^"'\s>]+)["']''', _re.IGNORECASE)
        path_re = _re.compile(r'''["'](/[A-Za-z0-9_\-./]{2,120})["']''')
        pages = [self.target] + list(getattr(self, "urls_to_scan", []) or [])
        seen_pages, fetched = set(), 0
        for page in pages:
            if fetched >= 12:
                break
            pkey = page.split("#")[0]
            if pkey in seen_pages:
                continue
            seen_pages.add(pkey)
            try:
                async with _orch.session(_DT.TARGET) as s:
                    async with s.get(page, timeout=_aiohttp.ClientTimeout(total=8),
                                     ssl=False, allow_redirects=True) as r:
                        ctype = (r.headers.get("Content-Type", "") or "").lower()
                        if "html" not in ctype and "xml" not in ctype:
                            continue
                        html = (await r.text())[:400000]
            except Exception:
                continue
            fetched += 1
            for m in action_re.findall(html):
                _add(actions, urljoin(page, m))
            for m in path_re.findall(html):
                _add(literals, urljoin(origin + "/", m.lstrip("/")))

        # Order: crawl set → form actions → JS path literals (highest signal first).
        return crawl + actions + literals

    def _categorize_parameter(
        self,
        param: str,
        specialist_type: str,
        params_map: dict,
        idor_params: list,
        current_qs: dict
    ):
        """Categorize parameter for specialist agent."""
        if specialist_type == "IDOR_AGENT":
            original_val = current_qs.get(param, ["1"])[0]
            idor_params.append({"parameter": param, "original_value": original_val})
        else:
            if specialist_type not in params_map:
                params_map[specialist_type] = set()
            params_map[specialist_type].add(param)

    async def _build_other_tasks(self, specialist_dispatches: set, params_map: dict, idor_params: list, url: str, url_dir: Path, process_result) -> list:
        """Build other specialist agent tasks."""
        from bugtrace.core.team.orchestrator import run_agent_with_semaphore
        tasks = []

        if "XXE_AGENT" in specialist_dispatches:
            from bugtrace.agents.xxe_agent import XXEAgent
            p_list = list(params_map.get("XXE_AGENT", [])) or None
            xxe_agent = XXEAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, xxe_agent, process_result))

        if "SSRF_AGENT" in specialist_dispatches:
            from bugtrace.agents.ssrf_agent import SSRFAgent
            p_list = list(params_map.get("SSRF_AGENT", [])) or None
            ssrf_agent = SSRFAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, ssrf_agent, process_result))

        if "LFI_AGENT" in specialist_dispatches:
            from bugtrace.agents.lfi_agent import LFIAgent
            p_list = list(params_map.get("LFI_AGENT", [])) or None
            lfi_agent = LFIAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, lfi_agent, process_result))

        if "RCE_AGENT" in specialist_dispatches:
            from bugtrace.agents.rce_agent import RCEAgent
            p_list = list(params_map.get("RCE_AGENT", [])) or None
            rce_agent = RCEAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, rce_agent, process_result))

        if "PROTO_AGENT" in specialist_dispatches:
            from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
            p_list = list(params_map.get("PROTO_AGENT", [])) or None
            proto_agent = PrototypePollutionAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, proto_agent, process_result))

        if "FILE_UPLOAD_AGENT" in specialist_dispatches:
            from bugtrace.agents.fileupload_agent import FileUploadAgent
            upload_agent = FileUploadAgent(url)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, upload_agent, process_result))

        if "JWT_AGENT" in specialist_dispatches:
            tasks.append(run_agent_with_semaphore(self.url_semaphore, self.jwt_agent, process_result))

        if "IDOR_AGENT" in specialist_dispatches:
            from bugtrace.agents.idor_agent import IDORAgent
            idor_agent = IDORAgent(url, params=idor_params, report_dir=url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, idor_agent, process_result))

        if "OPENREDIRECT_AGENT" in specialist_dispatches:
            from bugtrace.agents.openredirect_agent import OpenRedirectAgent
            p_list = list(params_map.get("OPENREDIRECT_AGENT", [])) or None
            openredirect_agent = OpenRedirectAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, openredirect_agent, process_result))

        if "PROTOTYPE_POLLUTION_AGENT" in specialist_dispatches:
            from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
            p_list = list(params_map.get("PROTOTYPE_POLLUTION_AGENT", [])) or None
            pp_agent = PrototypePollutionAgent(url, p_list, url_dir)
            tasks.append(run_agent_with_semaphore(self.url_semaphore, pp_agent, process_result))

        return tasks

    async def _process_url(self, url: str, url_index: int, total_urls: int, analysis_dir: Path, dashboard) -> list:
        """Process a single URL for vulnerabilities."""
        if url in self.processed_urls:
            logger.info(f"⏩ Skipping already processed URL: {url[:60]}")
            return []

        self._log_url_processing(url, url_index, total_urls, dashboard)

        # Pause checkpoint + stop check
        _ctx = getattr(self, '_scan_context', None)
        if _ctx is not None:
            await _ctx.wait_if_paused()
        if dashboard.stop_requested or self._stop_event.is_set():
            return []

        all_validated_findings = []
        seen_keys = set()
        url_dir = self._create_url_directory(url, analysis_dir)

        # Phase 1: DAST Analysis
        vulnerabilities = await self._run_dast_analysis(url, url_dir, dashboard)

        if dashboard.stop_requested or self._stop_event.is_set():
            return []

        # Phase 2: Specialist Dispatch & Execution
        if vulnerabilities:
            all_validated_findings = await self._orchestrate_specialists(
                vulnerabilities, url, url_dir, seen_keys, dashboard
            )

            if all_validated_findings is None:  # Scan stopped
                return []

        # Phase 2b: XXE on POST-only XML endpoints invisible to GET-based DAST. A "check stock"-style
        # XML endpoint returns 405 on GET, so DAST surfaces nothing and the orchestration above is
        # skipped — probe it directly and run the XXE agent if it actually parses XML.
        if not vulnerabilities and not (dashboard.stop_requested or self._stop_event.is_set()):
            if await self._is_xml_endpoint(url):
                logger.info(f"🔧 XML endpoint (no GET-visible vuln): dispatching XXE on {url[:60]}")
                pr = self._create_finding_processor(seen_keys, all_validated_findings, dashboard)
                xtasks = await self._build_other_tasks({"XXE_AGENT"}, {"XXE_AGENT": {"post_body"}}, [], url, url_dir, pr)
                if xtasks:
                    await self._execute_agents(xtasks, dashboard)

        logger.info(f"🎯 Intelligent dispatch complete for {url[:50]}")

        # Phase 3: Persistence
        self._persist_findings(all_validated_findings, url)

        return all_validated_findings

    def _log_url_processing(self, url: str, url_index: int, total_urls: int, dashboard) -> None:
        """Log URL processing start."""
        logger.info(f"🚀 Processing URL {url_index+1}/{total_urls}: {url[:60]}")
        dashboard.update_task("Orchestrator", status=f"Processing {url[:40]}")

