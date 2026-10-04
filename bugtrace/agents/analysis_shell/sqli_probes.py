"""SQLi/cookie/reflection probes.

Shell mixin; hard max 2000 LOC.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.llm_client import llm_client
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.utils.logger import get_logger

logger = get_logger(__name__)


def _analysis_orchestrator():
    """Resolve the legacy facade's patched orchestrator at call time."""
    from bugtrace.agents.analysis_agent import orchestrator as legacy_orchestrator

    return legacy_orchestrator


class AnalysisSqliProbesMixin:
    async def _check_sqli_probes(self) -> Dict:
        """
        Active SQLi probe: Send basic payloads to detect error-based SQL injection.
        Uses three detection methods:
        1. SQL error messages in response body
        2. Status code differential (500 on ' but 200 on '' = classic SQLi)
        3. Time-based blind SQLi (SLEEP payload)

        Also discovers params from HTML <a> tags to expand attack surface coverage.
        """
        self._v.emit("discovery.sqli_probe.started", {"url": self.url})
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        # SQL error patterns for major databases
        SQL_ERRORS = [
            # MySQL
            "you have an error in your sql syntax",
            "mysql_fetch", "mysql_num_rows", "mysql_query",
            "warning: mysql",
            # PostgreSQL
            "postgresql.*error", "pg_query", "pg_exec",
            "unterminated quoted string",
            # MSSQL
            "microsoft sql server", "mssql_query",
            "unclosed quotation mark",
            # Oracle
            "ora-00933", "ora-00921", "ora-01756",
            "oracle.*driver", "oracle.*error",
            # SQLite
            "sqlite3.operationalerror", "sqlite_error",
            "unrecognized token",
            # Generic
            "sql syntax.*mysql", "valid sql statement",
            "sqlstate", "odbc.*driver",
        ]

        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            # Also extract params from HTML <a> tags (catches nav links like ?category=)
            html = getattr(self, '_analysis_html', "")
            link_targets = self._extract_link_sqli_targets(html) if html else {}

            if not params and not link_targets:
                return {"vulnerabilities": []}

            findings = []
            tested_params = set()  # Track tested params to avoid duplicates

            # Use orchestrator for lifecycle-tracked connections
            async with _analysis_orchestrator().session(DestinationType.TARGET) as session:
                # === Phase 1: Test params from current URL ===
                for param_name in params:
                    tested_params.add(param_name)

                    # Test: Single quote should break SQL, double quote should escape
                    test_params_single = {k: v[0] if v else "" for k, v in params.items()}
                    test_params_single[param_name] = "'"

                    test_params_double = {k: v[0] if v else "" for k, v in params.items()}
                    test_params_double[param_name] = "''"

                    url_single = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params_single), parsed.fragment
                    ))
                    url_double = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params_double), parsed.fragment
                    ))

                    try:
                        async with session.get(url_single, ssl=False) as resp_single:
                            status_single = resp_single.status
                            body_single = await resp_single.text()

                        async with session.get(url_double, ssl=False) as resp_double:
                            status_double = resp_double.status

                        # Detection Method 1: Status code differential
                        # If ' gives 500 but '' gives 200 = classic SQLi pattern
                        if status_single >= 500 and status_double < 400:
                            logger.info(f"[SQLi Probe] Status differential in {param_name}: '={status_single}, ''={status_double}")
                            findings.append({
                                "type": "SQLi",
                                "vulnerability": "SQL Injection (Error-based)",
                                "parameter": param_name,
                                "payload": "'",
                                "confidence": 0.9,
                                "severity": "Critical",
                                "probe_validated": True,  # Active test confirmed - don't override scores
                                "fp_confidence": 0.85,
                                "skeptical_score": 8,
                                "votes": 5,  # Boost votes for probe findings (counts as expert validation)
                                "evidence": f"Status code differential: single quote (') returns {status_single}, escaped quote ('') returns {status_double}",
                                "description": f"Error-based SQL injection detected in parameter '{param_name}'. Single quote causes server error (500) while escaped quote works normally, indicating SQL query breakage.",
                                "reproduction": f"[PROBE-VALIDATED] curl -s -o /dev/null -w '%{{http_code}}' '{url_single}' # Returns {status_single}"
                            })
                            continue  # Found SQLi, next param

                        # Detection Method 2: SQL error messages in body
                        body_lower = body_single.lower()
                        for error_pattern in SQL_ERRORS:
                            if error_pattern in body_lower:
                                logger.info(f"[SQLi Probe] Found SQL error '{error_pattern}' in {param_name}")
                                findings.append({
                                    "type": "SQLi",
                                    "vulnerability": "SQL Injection (Error-based)",
                                    "parameter": param_name,
                                    "payload": "'",
                                    "confidence": 0.95,
                                    "severity": "Critical",
                                    "probe_validated": True,  # Active test confirmed - don't override scores
                                    "fp_confidence": 0.9,
                                    "skeptical_score": 9,
                                    "votes": 5,  # Boost votes for probe findings (counts as expert validation)
                                    "evidence": f"SQL error detected: '{error_pattern}' in response",
                                    "description": f"Error-based SQL injection detected in parameter '{param_name}'. Database error message exposed in response.",
                                    "reproduction": f"[PROBE-VALIDATED] curl '{url_single}' | grep -i 'error\\|sql'"
                                })
                                break

                        # Detection Method 3: Time-based Blind SQLi
                        # Only if error-based didn't find anything
                        if not any(f.get("parameter") == param_name for f in findings):
                            import time
                            # Test with SLEEP payload (MySQL/MariaDB style, works on many DBs)
                            sleep_payloads = [
                                ("' AND SLEEP(3)--", "mysql"),
                                ("'; SELECT pg_sleep(3);--", "postgresql"),
                            ]

                            for sleep_payload, db_type in sleep_payloads:
                                test_params_sleep = {k: v[0] if v else "" for k, v in params.items()}
                                original_value = test_params_sleep.get(param_name, "")
                                test_params_sleep[param_name] = f"{original_value}{sleep_payload}"

                                url_sleep = urlunparse((
                                    parsed.scheme, parsed.netloc, parsed.path,
                                    parsed.params, urlencode(test_params_sleep), parsed.fragment
                                ))

                                try:
                                    start_time = time.time()
                                    async with session.get(url_sleep, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp_sleep:
                                        await resp_sleep.text()
                                    elapsed = time.time() - start_time

                                    # If response took > 2.5 seconds, likely blind SQLi
                                    if elapsed >= 2.5:
                                        logger.info(f"[SQLi Probe] Time-based blind SQLi in {param_name}: {elapsed:.2f}s delay ({db_type})")
                                        findings.append({
                                            "type": "SQLi",
                                            "vulnerability": f"SQL Injection (Time-based Blind - {db_type})",
                                            "parameter": param_name,
                                            "payload": sleep_payload,
                                            "confidence": 0.85,
                                            "severity": "Critical",
                                            "probe_validated": True,
                                            "fp_confidence": 0.8,
                                            "skeptical_score": 8,
                                            "votes": 5,
                                            "evidence": f"Response delayed by {elapsed:.2f}s with SLEEP payload (expected 3s)",
                                            "description": f"Time-based blind SQL injection detected in parameter '{param_name}'. The server response was delayed when SLEEP was injected, indicating the SQL was executed.",
                                            "reproduction": f"[PROBE-VALIDATED] time curl '{url_sleep}' # Should take ~3 seconds"
                                        })
                                        break  # Found blind SQLi, don't test other DB types
                                except asyncio.TimeoutError:
                                    # Timeout could also indicate SQLi (server waiting)
                                    logger.info(f"[SQLi Probe] Possible time-based blind SQLi (timeout) in {param_name} ({db_type})")
                                    findings.append({
                                        "type": "SQLi",
                                        "vulnerability": f"SQL Injection (Time-based Blind - {db_type})",
                                        "parameter": param_name,
                                        "payload": sleep_payload,
                                        "confidence": 0.7,
                                        "severity": "Critical",
                                        "probe_validated": True,
                                        "fp_confidence": 0.7,
                                        "skeptical_score": 7,
                                        "votes": 5,
                                        "evidence": "Request timed out with SLEEP payload (>8s)",
                                        "description": f"Possible time-based blind SQL injection in '{param_name}'. Request timed out when SLEEP payload was injected.",
                                        "reproduction": f"[PROBE-VALIDATED] time curl --max-time 10 '{url_sleep}'"
                                    })
                                    break
                                except Exception:
                                    continue  # Try next payload

                    except Exception as e:
                        logger.debug(f"[SQLi Probe] Network error testing {param_name}: {e}")
                        continue

                # === Phase 2: Test params from HTML <a> links ===
                # Discovers params like "category" from nav links that point to
                # different endpoints (e.g., /catalog?category=Juice)
                for link_url, link_params in link_targets.items():
                    link_parsed = urlparse(link_url)

                    for param_name, param_value in link_params.items():
                        if param_name in tested_params:
                            continue
                        tested_params.add(param_name)

                        try:
                            # Build test URLs on the link's endpoint
                            test_single = {k: v for k, v in link_params.items()}
                            test_single[param_name] = f"{param_value}'"

                            test_double = {k: v for k, v in link_params.items()}
                            test_double[param_name] = f"{param_value}''"

                            url_single = f"{link_url}?{urlencode(test_single)}"
                            url_double = f"{link_url}?{urlencode(test_double)}"

                            async with session.get(url_single, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp_single:
                                status_single = resp_single.status
                                body_single = await resp_single.text()

                            async with session.get(url_double, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp_double:
                                status_double = resp_double.status

                            # Detection: Status code differential
                            if status_single >= 500 and status_double < 400:
                                logger.info(f"[SQLi Probe] Link param: status differential in {param_name} @ {link_url}: '={status_single}, ''={status_double}")
                                findings.append({
                                    "type": "SQLi",
                                    "vulnerability": "SQL Injection (Error-based)",
                                    "parameter": param_name,
                                    "url": link_url,
                                    "payload": "'",
                                    "confidence": 0.9,
                                    "severity": "Critical",
                                    "probe_validated": True,
                                    "fp_confidence": 0.85,
                                    "skeptical_score": 8,
                                    "votes": 5,
                                    "evidence": f"Status code differential: single quote (') returns {status_single}, escaped quote ('') returns {status_double}",
                                    "description": f"Error-based SQL injection detected in parameter '{param_name}' at {link_url}. Discovered from HTML navigation link.",
                                    "reproduction": f"[PROBE-VALIDATED] curl -s -o /dev/null -w '%{{http_code}}' '{url_single}' # Returns {status_single}"
                                })
                                continue

                            # Detection: SQL error messages
                            body_lower = body_single.lower()
                            for error_pattern in SQL_ERRORS:
                                if error_pattern in body_lower:
                                    logger.info(f"[SQLi Probe] Link param: SQL error '{error_pattern}' in {param_name} @ {link_url}")
                                    findings.append({
                                        "type": "SQLi",
                                        "vulnerability": "SQL Injection (Error-based)",
                                        "parameter": param_name,
                                        "url": link_url,
                                        "payload": "'",
                                        "confidence": 0.95,
                                        "severity": "Critical",
                                        "probe_validated": True,
                                        "fp_confidence": 0.9,
                                        "skeptical_score": 9,
                                        "votes": 5,
                                        "evidence": f"SQL error detected: '{error_pattern}' in response",
                                        "description": f"Error-based SQL injection detected in parameter '{param_name}' at {link_url}. Discovered from HTML navigation link.",
                                        "reproduction": f"[PROBE-VALIDATED] curl '{url_single}' | grep -i 'error\\|sql'"
                                    })
                                    break

                        except Exception as e:
                            logger.debug(f"[SQLi Probe] Link param error testing {param_name} @ {link_url}: {e}")
                            continue

            self._v.emit("discovery.sqli_probe.completed", {"url": self.url, "findings_count": len(findings)})
            return {"vulnerabilities": findings}

        except Exception as e:
            logger.error(f"SQLi probe check failed: {e}", exc_info=True)
            return {"vulnerabilities": []}

    async def _check_cookie_sqli_probes(self) -> Dict:
        """
        Active SQLi probe for cookies: Test each cookie value for SQL injection.
        Handles Base64-encoded values (like TrackingId with JSON inside).
        Also tests synthetic cookies for common vulnerable patterns.
        """
        self._v.emit("discovery.cookie_sqli.started", {"url": self.url})
        import base64
        import json
        from urllib.parse import urlparse

        logger.info(f"[Cookie SQLi Probe] Starting cookie probe for {self.url[:50]}...")
        findings = []

        try:
            # Get cookies from browser session (JavaScript document.cookie — misses HttpOnly!)
            from bugtrace.tools.visual.browser import browser_manager
            session_data = await browser_manager.get_session_data()
            cookies = session_data.get("cookies", [])
            logger.debug(f"[Cookie SQLi Probe] Got {len(cookies)} cookies from browser session")

            # If _run_reflection_probes didn't capture cookies (e.g. URL had no params),
            # make HTTP requests to capture Set-Cookie headers.
            # We hit both self.url AND the root "/" because cookies may only be set
            # on specific endpoints, including the site root.
            http_cookies = getattr(self, '_http_cookies', {})
            if not http_cookies and not cookies:
                from urllib.parse import urlparse as _urlparse
                parsed_url = _urlparse(self.url)
                root_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
                cookie_urls = [self.url]
                if self.url.rstrip("/") != root_url.rstrip("/"):
                    cookie_urls.append(root_url)
                try:
                    # Jar-less capture (stable 891f012): pooled jar may already hold
                    # TrackingId so server won't re-issue Set-Cookie. DummyCookieJar
                    # forces a clean request so Set-Cookie reaches us.
                    async with _analysis_orchestrator().session(DestinationType.TARGET) as cookie_session:
                        if hasattr(cookie_session, "cookie_jar"):
                            cookie_session.cookie_jar.clear()
                        for curl in cookie_urls:
                            try:
                                async with cookie_session.get(
                                    curl, ssl=False,
                                    timeout=aiohttp.ClientTimeout(total=10)
                                ) as resp:
                                    await resp.text()
                                    self._extract_cookies_from_http_headers(resp)
                            except Exception:
                                pass
                        http_cookies = getattr(self, '_http_cookies', {})
                        if http_cookies:
                            logger.info(f"[Cookie SQLi Probe] Captured {len(http_cookies)} cookies via direct request")
                except Exception as e:
                    logger.debug(f"[Cookie SQLi Probe] Direct cookie capture failed: {e}")

            # Gap 1 Fix: Merge HttpOnly cookies captured from HTTP Set-Cookie headers
            # These are invisible to document.cookie but are the highest-value SQLi targets
            if http_cookies:
                existing_names = {c.get("name", "").lower() for c in cookies}
                for name, cookie_data in http_cookies.items():
                    if name.lower() not in existing_names:
                        cookies.append(cookie_data)
                        existing_names.add(name.lower())
                httponly_count = sum(1 for c in http_cookies.values() if c.get("httponly"))
                logger.info(f"[Cookie SQLi Probe] Merged {len(http_cookies)} HTTP header cookies ({httponly_count} HttpOnly)")

            logger.debug(f"[Cookie SQLi Probe] Testing {len(cookies)} observed cookies")

            # Insecure Cookie Configuration Detection (V-008)
            # Emit directly as VALIDATED_CONFIRMED via event bus (bypasses ThinkingConsolidation)
            # Same pattern as Nuclei misconfigurations — these are observation-based, no specialist needed
            if http_cookies:
                for name, cookie_data in http_cookies.items():
                    if cookie_data.get("_synthetic"):
                        continue
                    # Class-level dedup: only emit once per cookie name per scan
                    if name in type(self)._emitted_cookie_configs:
                        continue
                    is_httponly = cookie_data.get("httponly", False)
                    is_secure = cookie_data.get("secure", False)
                    is_samesite = cookie_data.get("samesite", False)
                    missing_flags = []
                    if not is_httponly:
                        missing_flags.append("HttpOnly")
                    if not is_secure:
                        missing_flags.append("Secure")
                    if not is_samesite:
                        missing_flags.append("SameSite")
                    if missing_flags:
                        await event_bus.emit(
                            EventType.VULNERABILITY_DETECTED,
                            {
                                "type": "MISCONFIGURATION",
                                "category": "INSECURE_COOKIE",
                                "specialist": "dastysast",
                                "severity": "MEDIUM" if "HttpOnly" in missing_flags else "LOW",
                                             "url": self.url,
                                "parameter": f"Cookie: {name}",
                                "description": f"Cookie '{name}' is set without security flags: "
                                               f"{', '.join(missing_flags)}. Missing HttpOnly allows XSS-based "
                                               f"session hijacking, missing Secure allows MITM interception, "
                                               f"missing SameSite enables CSRF attacks.",
                                "remediation": f"Add the following flags to the Set-Cookie header for '{name}': "
                                               f"{'; '.join(missing_flags)}",
                                "cwe_id": "CWE-614",
                                "validated": True,
                                "status": "VALIDATED_CONFIRMED",
                                "scan_context": self.scan_context,
                                "evidence": {
                                    "cookie_name": name,
                                    "missing_flags": missing_flags,
                                    "detection_method": "set_cookie_header_analysis",
                                },
                            }
                        )
                        type(self)._emitted_cookie_configs.add(name)
                        logger.info(f"[Cookie Config] Emitted: cookie '{name}' missing {', '.join(missing_flags)}")

            if not cookies:
                return {"vulnerabilities": []}

            parsed = urlparse(self.url)
            # Test cookies against current path + root only (avoid combinatorial explosion)
            test_paths = [parsed.path, "/"]
            test_paths = list(dict.fromkeys([p for p in test_paths if p]))
            base_scheme_host = f"{parsed.scheme}://{parsed.netloc}"

            import time as _time_budget
            cookie_probe_deadline = _time_budget.time() + 90  # Max 90s for all cookie probes

            logger.debug(f"[Cookie SQLi Probe] Will test against {len(test_paths)} paths: {test_paths}")

            # Clear the pooled jar before manually constructing Cookie headers.
            async with _analysis_orchestrator().session(DestinationType.TARGET) as session:
                if hasattr(session, "cookie_jar"):
                    session.cookie_jar.clear()
                # Test each cookie against each path (cookies are domain-wide)
                for test_path in test_paths:
                    if _time_budget.time() > cookie_probe_deadline:
                        logger.info(f"[Cookie SQLi Probe] Time budget exhausted, stopping paths")
                        break
                    test_url = f"{base_scheme_host}{test_path}"

                    for cookie in cookies:
                        # Time budget check — don't let cookie probes consume entire URL analysis
                        if _time_budget.time() > cookie_probe_deadline:
                            logger.info(f"[Cookie SQLi Probe] Time budget exhausted, stopping cookie probes")
                            break

                        cookie_name = cookie.get("name", "")
                        cookie_value = cookie.get("value", "")

                        if not cookie_name or not cookie_value:
                            continue

                        # Skip session/auth cookies (don't want to break session)
                        if cookie_name.lower() in ["session", "sessionid", "phpsessid", "jsessionid"]:
                            continue

                        # Skip if already found SQLi for this cookie (from previous path)
                        if any(f.get("parameter") == f"Cookie: {cookie_name}" for f in findings):
                            continue

                        # === Multi-strategy error-based SQLi detection ===
                        # Strategy: get baseline status, then test multiple injection chars.
                        # If ANY injection char causes 500 while baseline is <400 → SQLi.
                        # This catches diverse SQL dialects and encoding schemes.
                        injection_chars = ["'", '"', "\\", ")", ";"]

                        # Build injection test values: list of (label, injected_cookie_value, injection_char)
                        test_values = []

                        # Direct injection: append char to raw cookie value
                        for ic in injection_chars:
                            test_values.append((f"direct_{ic}", f"{cookie_value}{ic}", ic))

                        # Base64 decode and inject inside
                        try:
                            padded = cookie_value + "=" * (4 - len(cookie_value) % 4) if len(cookie_value) % 4 else cookie_value
                            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')

                            if decoded.strip().startswith('{'):
                                try:
                                    json_data = json.loads(decoded)
                                    for key in json_data:
                                        if isinstance(json_data[key], str):
                                            for ic in injection_chars:
                                                injected = json_data.copy()
                                                injected[key] = json_data[key] + ic
                                                val = base64.b64encode(json.dumps(injected).encode()).decode()
                                                test_values.append((f"b64_json_{key}_{ic}", val, ic))
                                except json.JSONDecodeError:
                                    pass
                            else:
                                for ic in injection_chars:
                                    val = base64.b64encode(f"{decoded}{ic}".encode()).decode()
                                    test_values.append((f"b64_plain_{ic}", val, ic))
                        except Exception:
                            pass  # Not Base64, skip

                        # Get baseline status (original cookie value)
                        other_cookies = {c["name"]: c["value"] for c in cookies if c["name"] != cookie_name}
                        baseline_cookie_str = "; ".join([f"{k}={v}" for k, v in other_cookies.items()] + [f"{cookie_name}={cookie_value}"])
                        try:
                            async with session.get(test_url, headers={"Cookie": baseline_cookie_str}, ssl=False) as resp_baseline:
                                status_baseline = resp_baseline.status
                        except Exception:
                            status_baseline = 0  # Can't get baseline, skip

                        if status_baseline >= 500:
                            # Baseline already errors, can't do differential detection
                            logger.debug(f"[Cookie SQLi Probe] {cookie_name} @ {test_path}: baseline={status_baseline}, skipping (already erroring)")
                            continue

                        # Test each injection
                        for test_type, val_injected, inj_char in test_values:
                            try:
                                cookies_injected = "; ".join([f"{k}={v}" for k, v in other_cookies.items()] + [f"{cookie_name}={val_injected}"])

                                async with session.get(test_url, headers={"Cookie": cookies_injected}, ssl=False) as resp_injected:
                                    status_injected = resp_injected.status

                                logger.debug(f"[Cookie SQLi Probe] {cookie_name} @ {test_path} ({test_type}): injected={status_injected}, baseline={status_baseline}")

                                # Detection: injection causes 500, baseline was OK
                                if status_injected >= 500 and status_baseline < 400:
                                    logger.info(f"[Cookie SQLi Probe] DETECTED SQLi in cookie {cookie_name} @ {test_path} ({test_type}): {status_injected} vs baseline {status_baseline}")
                                    findings.append({
                                        "type": "SQLi",
                                        "vulnerability": "SQL Injection in Cookie (Error-based)",
                                             "parameter": f"Cookie: {cookie_name}",
                                             "url": self.url,
                                        "payload": inj_char if "b64" not in test_type else f"Base64-encoded {repr(inj_char)} in {test_type}",
                                        "confidence": 0.9,
                                        "severity": "Critical",
                                        "probe_validated": True,
                                        "fp_confidence": 0.85,
                                        "skeptical_score": 8,
                                        "votes": 5,
                                        "evidence": f"Status code differential: {repr(inj_char)} injection returns {status_injected}, original cookie returns {status_baseline}",
                                        "description": f"Error-based SQL injection detected in cookie '{cookie_name}' at {test_url} ({test_type}). Injecting {repr(inj_char)} causes server error while original value works normally.",
                                        "reproduction": f"[PROBE-VALIDATED] curl -b '{cookie_name}={val_injected}' '{test_url}' # Returns {status_injected}"
                                    })
                                    break  # Found SQLi in this cookie, move on

                            except Exception as e:
                                logger.debug(f"[Cookie SQLi Probe] Error testing {cookie_name}: {e}")
                                continue

                        # Time-based Blind SQLi Detection for Cookies
                        # Differential confirmation: TRUE condition sleeps, FALSE doesn't.
                        # This eliminates false positives from slow servers.
                        if not any(f.get("parameter") == f"Cookie: {cookie_name}" for f in findings):
                            import time as time_module

                            # (true_payload, false_payload, db_type, delay_threshold)
                            # IMPORTANT: MySQL requires "-- " (with space) or "#" for comments.
                            # Bare "--" without trailing space is NOT a comment in MySQL.
                            sleep_pairs = [
                                ("' OR SLEEP(2)#", "' OR SLEEP(0)#", "mysql_or", 1.5),
                                ("' AND SLEEP(3)#", "' AND SLEEP(0)#", "mysql_and", 2.5),
                                ("' OR SLEEP(2)-- ", "' OR SLEEP(0)-- ", "mysql_or_dash", 1.5),
                                ("'; SELECT pg_sleep(3);-- ", "'; SELECT pg_sleep(0);-- ", "postgresql", 2.5),
                            ]

                            other_cookies = {c["name"]: c["value"] for c in cookies if c["name"] != cookie_name}

                            for true_payload, false_payload, db_type, delay_threshold in sleep_pairs:
                                try:
                                    # Step 1: TRUE condition (should delay)
                                    cookie_true = f"{cookie_value}{true_payload}"
                                    cookies_true = "; ".join([f"{k}={v}" for k, v in other_cookies.items()] + [f"{cookie_name}={cookie_true}"])

                                    start_true = time_module.time()
                                    true_timed_out = False
                                    try:
                                        async with session.get(test_url, headers={"Cookie": cookies_true}, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp_true:
                                            await resp_true.text()
                                    except asyncio.TimeoutError:
                                        true_timed_out = True
                                    elapsed_true = time_module.time() - start_true

                                    if elapsed_true < delay_threshold and not true_timed_out:
                                        continue  # TRUE didn't delay → not this DB type

                                    # Step 2: FALSE condition (should NOT delay)
                                    cookie_false = f"{cookie_value}{false_payload}"
                                    cookies_false = "; ".join([f"{k}={v}" for k, v in other_cookies.items()] + [f"{cookie_name}={cookie_false}"])

                                    start_false = time_module.time()
                                    try:
                                        async with session.get(test_url, headers={"Cookie": cookies_false}, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp_false:
                                            await resp_false.text()
                                    except asyncio.TimeoutError:
                                        continue  # Both timeout → probably just slow server
                                    elapsed_false = time_module.time() - start_false

                                    # Differential: TRUE delayed significantly more than FALSE.
                                    # ANTI-FP: the FALSE/no-sleep request MUST be genuinely fast.
                                    # Under scan load both TRUE and FALSE inflate and delta can
                                    # cross the threshold on noise; a real time-based blind shows a
                                    # clean fast-vs-slow split, not slow-vs-slower. Requiring
                                    # elapsed_false < threshold rejects load-noise false positives.
                                    delta = elapsed_true - elapsed_false
                                    clean_false = elapsed_false < delay_threshold
                                    if clean_false and (true_timed_out or delta >= delay_threshold):
                                        logger.info(
                                            f"[Cookie SQLi Probe] CONFIRMED time-based blind SQLi in cookie "
                                            f"{cookie_name} @ {test_path} ({db_type}): "
                                            f"TRUE={elapsed_true:.2f}s, FALSE={elapsed_false:.2f}s, delta={delta:.2f}s"
                                        )
                                        findings.append({
                                            "type": "SQLi",
                                            "vulnerability": f"SQL Injection in Cookie (Time-based Blind - {db_type})",
                                            "parameter": f"Cookie: {cookie_name}",
                                             "url": self.url,
                                            "payload": true_payload,
                                            "confidence": 0.9,
                                            "severity": "Critical",
                                            "probe_validated": True,
                                            "fp_confidence": 0.85,
                                            "skeptical_score": 9,
                                            "votes": 5,
                                            "evidence": (
                                                f"Differential timing confirmation: "
                                                f"TRUE payload ({true_payload}) took {elapsed_true:.2f}s, "
                                                f"FALSE payload ({false_payload}) took {elapsed_false:.2f}s "
                                                f"(delta: {delta:.2f}s)"
                                            ),
                                            "description": (
                                                f"Time-based blind SQL injection in cookie '{cookie_name}' at {test_url}. "
                                                f"Confirmed via differential timing: the TRUE SLEEP condition delays the response "
                                                f"while the FALSE condition responds normally."
                                            ),
                                            "reproduction": f"[PROBE-VALIDATED] curl -b '{cookie_name}={cookie_true}' '{test_url}' # TRUE: ~{elapsed_true:.0f}s vs FALSE: ~{elapsed_false:.0f}s",
                                            # Data to re-confirm in isolation before reporting (anti-FP
                                            # against ambient SLEEP load from concurrent probes).
                                             "_recheck": {
                                                 "url": test_url,
                                                "cookie_true": cookies_true,
                                                "cookie_false": cookies_false,
                                                "threshold": delay_threshold,
                                            },
                                        })
                                        break

                                except Exception as e:
                                    logger.debug(f"[Cookie SQLi Probe] Time-based test error for {cookie_name}: {e}")
                                    continue

                        # Base64-aware Time-based Blind SQLi Detection
                        # Many cookies are Base64-encoded (e.g., TrackingId).
                        # Direct payload append breaks the Base64 encoding, so the
                        # server fails at decode before reaching the SQL query.
                        # Fix: decode → inject inside → re-encode to Base64.
                        # Uses differential confirmation (TRUE vs FALSE) to avoid FPs.
                        if not any(f.get("parameter") == f"Cookie: {cookie_name}" for f in findings):
                            try:
                                cv = cookie_value
                                padded_cv = cv + "=" * (4 - len(cv) % 4) if len(cv) % 4 else cv
                                decoded_cv = base64.b64decode(padded_cv).decode('utf-8', errors='ignore')
                                # Only proceed if it looks like real Base64 (not random bytes)
                                if decoded_cv and len(decoded_cv) >= 2 and all(c.isprintable() or c.isspace() for c in decoded_cv[:50]):
                                    # (true_payload, false_payload, db_type, delay_threshold)
                                    # IMPORTANT: MySQL requires "-- " (with space) or "#" for comments.
                                    b64_sleep_pairs = [
                                        ("' OR SLEEP(2)#", "' OR SLEEP(0)#", "mysql_or_b64", 1.5),
                                        ("' AND SLEEP(3)#", "' AND SLEEP(0)#", "mysql_and_b64", 2.5),
                                        ("' OR SLEEP(2)-- ", "' OR SLEEP(0)-- ", "mysql_or_dash_b64", 1.5),
                                        ("'; SELECT pg_sleep(3);-- ", "'; SELECT pg_sleep(0);-- ", "postgresql_b64", 2.5),
                                    ]
                                    other_cookies_b64 = {c["name"]: c["value"] for c in cookies if c["name"] != cookie_name}

                                    def _b64_inject(decoded_val, payload_raw):
                                        """Inject payload into decoded B64 value and re-encode."""
                                        if decoded_val.strip().startswith('{'):
                                            try:
                                                json_obj = json.loads(decoded_val)
                                                first_str_key = next((k for k, v in json_obj.items() if isinstance(v, str)), None)
                                                if first_str_key:
                                                    injected_obj = json_obj.copy()
                                                    injected_obj[first_str_key] = json_obj[first_str_key] + payload_raw
                                                    injected = json.dumps(injected_obj)
                                                else:
                                                    injected = decoded_val + payload_raw
                                            except json.JSONDecodeError:
                                                injected = decoded_val + payload_raw
                                        else:
                                            injected = decoded_val + payload_raw
                                        return injected, base64.b64encode(injected.encode()).decode()

                                    for true_payload, false_payload, b64_db_type, b64_threshold in b64_sleep_pairs:
                                        try:
                                            # Step 1: TRUE condition (should delay)
                                            injected_decoded_true, b64_true = _b64_inject(decoded_cv, true_payload)
                                            cookies_true = "; ".join(
                                                [f"{k}={v}" for k, v in other_cookies_b64.items()] +
                                                [f"{cookie_name}={b64_true}"]
                                            )

                                            start_true = time_module.time()
                                            true_timed_out = False
                                            try:
                                                async with session.get(test_url, headers={"Cookie": cookies_true}, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp_true:
                                                    await resp_true.text()
                                            except asyncio.TimeoutError:
                                                true_timed_out = True
                                            elapsed_true = time_module.time() - start_true

                                            if elapsed_true < b64_threshold and not true_timed_out:
                                                continue  # TRUE didn't delay → not this DB type

                                            # Step 2: FALSE condition (should NOT delay)
                                            _injected_decoded_false, b64_false = _b64_inject(decoded_cv, false_payload)
                                            cookies_false = "; ".join(
                                                [f"{k}={v}" for k, v in other_cookies_b64.items()] +
                                                [f"{cookie_name}={b64_false}"]
                                            )

                                            start_false = time_module.time()
                                            try:
                                                async with session.get(test_url, headers={"Cookie": cookies_false}, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp_false:
                                                    await resp_false.text()
                                            except asyncio.TimeoutError:
                                                continue  # Both timeout → probably slow server
                                            elapsed_false = time_module.time() - start_false

                                            # Differential: TRUE delayed significantly more than FALSE.
                                            # ANTI-FP: FALSE/no-sleep must be genuinely fast (see raw
                                            # path above) — rejects load-noise false positives where
                                            # both timings inflate and delta crosses on noise.
                                            delta = elapsed_true - elapsed_false
                                            clean_false = elapsed_false < b64_threshold
                                            if clean_false and (true_timed_out or delta >= b64_threshold):
                                                logger.info(
                                                    f"[Cookie SQLi Probe] CONFIRMED B64 time-based blind SQLi in cookie "
                                                    f"{cookie_name} @ {test_path} ({b64_db_type}): "
                                                    f"TRUE={elapsed_true:.2f}s, FALSE={elapsed_false:.2f}s, delta={delta:.2f}s"
                                                )
                                                findings.append({
                                                    "type": "SQLi",
                                                    "vulnerability": f"SQL Injection in Cookie (Time-based Blind - {b64_db_type})",
                                                     "parameter": f"Cookie: {cookie_name}",
                                                     "url": self.url,
                                                    "payload": f"Base64({true_payload})",
                                                    "confidence": 0.9,
                                                    "severity": "Critical",
                                                    "probe_validated": True,
                                                    "fp_confidence": 0.85,
                                                    "skeptical_score": 9,
                                                    "votes": 5,
                                                    "evidence": (
                                                        f"Differential timing confirmation (Base64-encoded): "
                                                        f"TRUE payload ({true_payload}) took {elapsed_true:.2f}s, "
                                                        f"FALSE payload ({false_payload}) took {elapsed_false:.2f}s "
                                                        f"(delta: {delta:.2f}s)"
                                                    ),
                                                    "description": (
                                                        f"Time-based blind SQL injection in Base64-encoded cookie '{cookie_name}' at {test_url}. "
                                                        f"Confirmed via differential timing: the TRUE SLEEP condition delays the response "
                                                        f"while the FALSE condition responds normally. "
                                                        f"The cookie value is Base64-decoded by the server before use in a SQL query."
                                                    ),
                                                    "reproduction": (
                                                        f"[PROBE-VALIDATED] echo -n \"{injected_decoded_true}\" | base64 | "
                                                        f"xargs -I{{}} curl -b '{cookie_name}={{}}' '{test_url}' "
                                                        f"# TRUE: ~{elapsed_true:.0f}s vs FALSE: ~{elapsed_false:.0f}s"
                                                    ),
                                                    # Data to re-confirm in isolation before reporting (anti-FP
                                                    # against ambient SLEEP load from concurrent probes).
                                                    "_recheck": {
                                                        "url": test_url,
                                                        "cookie_true": cookies_true,
                                                        "cookie_false": cookies_false,
                                                        "threshold": b64_threshold,
                                                    },
                                                })
                                                break

                                        except Exception as e:
                                            logger.debug(f"[Cookie SQLi Probe] B64 test error for {cookie_name} ({b64_db_type}): {e}")
                                            continue
                            except Exception:
                                pass  # Cookie value is not valid Base64, skip

                        # Insecure Deserialization Detection
                        # Check if cookie values trigger deserialization error messages
                        # (e.g., Python pickle, Java ObjectInputStream, PHP unserialize)
                        if not any(
                            f.get("parameter") == f"Cookie: {cookie_name}"
                            for f in findings
                        ):
                            DESER_PATTERNS = [
                                # Python pickle
                                "invalid load key", "could not find MARK", "unpickling",
                                "pickle.loads", "_pickle.UnpicklingError",
                                "pickle data", "_pickle.",
                                # Java
                                "java.io.ObjectInputStream", "ClassNotFoundException",
                                "java.io.InvalidClassException", "readObject",
                                # PHP
                                "unserialize()", "allowed_classes",
                                # .NET
                                "BinaryFormatter", "ObjectStateFormatter",
                                # Ruby
                                "Marshal.load",
                            ]
                            try:
                                # Send a Base64-encoded non-serialized probe value
                                deser_probe = base64.b64encode(b"BTAI_deser_probe_test").decode()
                                other_cookies_d = {c["name"]: c["value"] for c in cookies if c["name"] != cookie_name}
                                cookies_deser = "; ".join(
                                    [f"{k}={v}" for k, v in other_cookies_d.items()] +
                                    [f"{cookie_name}={deser_probe}"]
                                )
                                async with session.get(test_url, headers={"Cookie": cookies_deser}, ssl=False) as resp_deser:
                                    body_deser = await resp_deser.text()

                                matched_patterns = [p for p in DESER_PATTERNS if p.lower() in body_deser.lower()]
                                if matched_patterns:
                                    logger.info(f"[Cookie Deser Probe] Insecure deserialization in cookie {cookie_name} @ {test_path}: {matched_patterns}")
                                    findings.append({
                                        "type": "Insecure Deserialization",
                                        "vulnerability": "Insecure Deserialization via Cookie",
                                        "parameter": f"Cookie: {cookie_name}",
                                        "url": test_url,
                                        "payload": deser_probe,
                                        "confidence": 0.9,
                                        "severity": "High",
                                        "status": "MANUAL_REVIEW_RECOMMENDED",
                                        "probe_validated": True,
                                        "fp_confidence": 0.85,
                                        "skeptical_score": 9,
                                        "votes": 5,
                                        "cwe_id": "CWE-502",
                                        "evidence": f"Deserialization error keywords in response: {matched_patterns}",
                                        "description": f"Deserialization sink detected in cookie '{cookie_name}' at {test_url}. Non-serialized data in the cookie triggers deserialization error messages. This confirms a reachable sink, not an exploitable gadget chain or RCE.",
                                        "manual_review_reason": "Confirm accepted types and gadget availability with a safe, authorized proof.",
                                        "reproduction": f"[PROBE-VALIDATED] curl -b '{cookie_name}={deser_probe}' '{test_url}' | grep -i pickle"
                                    })
                            except Exception as e:
                                logger.debug(f"[Cookie Deser Probe] Error: {e}")

            # Emit probe-confirmed cookie SQLi directly as VALIDATED_CONFIRMED.
            # Differential-timing / error-based confirmation is authoritative
            # (TRUE sleeps ~Ns, FALSE does not — the gold standard for blind SQLi).
            # Routing it through ThinkingConsolidation strips the confirmation and
            # hands a bare "Cookie: <name>" param to the SQLi specialist, which
            # cannot re-test cookie injection -> the confirmed finding is silently
            # dropped before the report. Emit directly, same architecture as the
            # V-008 cookie-config emit above and the Nuclei misconfig path.
            for _f in findings:
                if "sql" not in str(_f.get("type", "")).lower():
                    continue  # deser/other cookie findings already survive normal routing
                _cookie_param = _f.get("parameter", "")
                _dedup_key = f"sqli::{_cookie_param}"
                if _dedup_key in type(self)._emitted_cookie_sqli:
                    continue
                # ANTI-FP re-confirmation. Time-based findings carry _recheck data;
                # re-verify in isolation that the delay is REPRODUCIBLE (a real
                # injection sleeps on every sample, ambient SLEEP load from
                # concurrent probes does not). Only emit if it survives.
                _recheck = _f.get("_recheck")
                if _recheck:
                    if not await self._reconfirm_cookie_sqli(_recheck):
                        logger.info(
                            f"[Cookie SQLi Probe] Re-confirm FAILED (ambient load / FP) — "
                            f"dropping {_cookie_param}"
                        )
                        continue
                type(self)._emitted_cookie_sqli.add(_dedup_key)
                _ev = _f.get("evidence")
                await event_bus.emit(
                    EventType.VULNERABILITY_DETECTED,
                    {
                        "type": "SQLI",
                        "subtype": _f.get("vulnerability", "SQL Injection in Cookie"),
                        "specialist": "dastysast",
                        "severity": _f.get("severity", "Critical"),
                        "url": _f.get("url", self.url),
                        "parameter": _cookie_param,
                        "payload": _f.get("payload", ""),
                        "description": _f.get("description", ""),
                        "remediation": (
                            "Use parameterized queries / prepared statements; never build SQL "
                            "from cookie values. Bind the decoded cookie as a parameter."
                        ),
                        "cwe_id": "CWE-89",
                        "confidence": _f.get("confidence", 0.9),
                        "probe_validated": True,
                        "validated": True,
                        "status": "VALIDATED_CONFIRMED",
                        "scan_context": self.scan_context,
                        "evidence": {"detail": _ev} if isinstance(_ev, str) else (_ev or {}),
                        "reproduction": _f.get("reproduction", ""),
                    }
                )
                logger.info(f"[Cookie SQLi Probe] Emitted VALIDATED_CONFIRMED cookie SQLi: {_cookie_param}")

            # Strip internal re-check scaffolding so it never leaks into the report.
            for _f in findings:
                _f.pop("_recheck", None)

            self._v.emit("discovery.cookie_sqli.completed", {"url": self.url, "findings_count": len(findings)})
            logger.info(f"[Cookie SQLi Probe] Completed: {len(findings)} findings")
            return {"vulnerabilities": findings}

        except Exception as e:
            logger.error(f"Cookie SQLi probe check failed: {e}", exc_info=True)
            return {"vulnerabilities": []}

    async def _reconfirm_cookie_sqli(self, recheck: Dict, rounds: int = 3) -> bool:
        """Re-confirm a time-based cookie SQLi in isolation to reject false
        positives caused by ambient SLEEP load from concurrent probes.

        During a scan, many agents inject `OR SLEEP(n)` into the real vulnerable
        cookie; those queries hold DB connections sleeping, so an UNRELATED
        request can queue behind them and look "slow" once. The single-shot
        differential then mis-confirms a non-vulnerable (often synthetic) cookie.

        A genuine injection sleeps on EVERY TRUE sample while its FALSE/no-sleep
        sample is always fast. Ambient load is bursty and fails this consistency.
        Requires: every round has FALSE fast AND TRUE slow (jar-less session so
        the assembled Cookie header is sent verbatim).
        """
        import time as _t
        url = recheck.get("url")
        cookie_true = recheck.get("cookie_true")
        cookie_false = recheck.get("cookie_false")
        threshold = float(recheck.get("threshold", 2.0))
        if not (url and cookie_true and cookie_false):
            return False
        rounds = max(3, rounds)
        to = max(4.0, threshold + 2.0)

        async def _measure(session, header):
            start = _t.time()
            try:
                async with session.get(url, headers={"Cookie": header}, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=to)) as r:
                    await r.text()
                return _t.time() - start, False
            except asyncio.TimeoutError:
                return to, True

        true_slow = 0
        false_fast = 0
        try:
            async with _analysis_orchestrator().isolated_session(
                DestinationType.TARGET, cookie_jar=aiohttp.DummyCookieJar()
            ) as s:
                for _ in range(rounds):
                    ef, _f_to = await _measure(s, cookie_false)
                    et, t_to = await _measure(s, cookie_true)
                    if ef < threshold:
                        false_fast += 1
                    if t_to or et >= threshold:
                        true_slow += 1
        except Exception as e:
            logger.debug(f"[Cookie SQLi Probe] Re-confirm error: {e}")
            return False

        # A genuine injection sleeps on EVERY TRUE sample (deterministic), while its
        # no-sleep FALSE is fast on at least the majority of samples. Ambient SLEEP
        # load is bursty -> TRUE is not slow every round (and FALSE is often slow too).
        confirmed = (true_slow == rounds) and (false_fast >= (rounds + 1) // 2)
        logger.info(
            f"[Cookie SQLi Probe] Re-confirm {'PASS' if confirmed else 'FAIL'}: "
            f"TRUE_slow={true_slow}/{rounds}, FALSE_fast={false_fast}/{rounds}"
        )
        return confirmed
