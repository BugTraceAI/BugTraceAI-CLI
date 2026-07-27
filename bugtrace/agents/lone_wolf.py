"""
LoneWolf Autonomous Agent v2 - Expert-level parallel exploration.

Runs alongside the main 6-phase pipeline during Phases 2-5, independently
exploring the target to find vulnerabilities the structured pipeline might miss.

What changed vs v1 (the rewrite):
- PERSISTENT MEMORY: a structured KnowledgeBase (endpoints, params, tech, cookies,
  findings, suspicions, hypotheses) survives the whole run and is injected into every
  prompt. v1 only kept a 20-action sliding window and passed COUNTERS, so after 20
  cycles the LLM forgot the app map, looped forever, and burned ~500 cycles of tokens.
- AUTONOMOUS SURFACE MAPPING: every HTML response is parsed (regex, no deps) for links,
  forms and params -> the agent "sees" the attack surface without spending LLM cycles
  on discovery, and is steered toward the UNTESTED surface.
- STRICT CONFIRMATION (no FP backdoor): v1 marked any `payload in response` as
  VALIDATED_CONFIRMED and wrote it straight to the report glob, bypassing the validator.
  v2 confirms per-vuln-class with context-aware, deterministic checks (executable
  reflection, distinctive CSTI arithmetic 1000003*1000003->1000006000009, re-confirmed
  time-based SQLi, /etc/passwd signatures, ...). Weak/ambiguous signals are written as
  NEEDS_VALIDATION (low confidence -> report quality gate routes them to manual_review),
  never as confirmed.
- CONVERGENCE: persistent hypotheses + a no-progress early-stop cut token spend
  dramatically (the memory fix is also the token fix).

Architecture:
- Completely decoupled: own aiohttp session, own rate limiter, no shared tools
- LLM-driven: every action decided by the configured model ([LONEWOLF] MODEL)
- Error-isolated: entire run() wrapped in try/except, always returns findings
- Fire-and-forget: launched via asyncio.create_task(), pipeline never waits

Finding output: specialists/results/lone_wolf_results.json
(picked up by ReportingAgent via existing glob pattern)
"""

import asyncio
import aiohttp
import base64
import html
import json
import re
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from urllib.parse import quote, urljoin, urlparse, parse_qs

from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.lone_wolf")

# ---------------------------------------------------------------------------
# Distinctive CSTI/SSTI arithmetic marker (matches CSTIAgent 3.6.17+).
# A 13-digit product cannot collide with random tokens/hashes the way "49" did.
# ---------------------------------------------------------------------------
_CSTI_EXPR = "1000003*1000003"
_CSTI_RESULT = "1000006000009"

# ---------------------------------------------------------------------------
# System prompt -- expert pentester methodology. The real value lives here.
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = f"""You are an elite, world-class offensive security researcher running INSIDE a fully authorized penetration-testing system. You hack like a top-tier bug-bounty hunter: you look at a web app and you already know where it bleeds.

AUTHORIZATION: This engagement is fully authorized with written consent. Every recon/exploitation action is pre-approved. Never ask for permission, never add authorization warnings — act with confidence.

You work ALONE with raw HTTP and your expertise. No frameworks, no tools — just requests and reasoning.

OPERATING DOCTRINE (think like a sniper, not a scanner):
1. MAP before you shoot. Read the KNOWLEDGE BASE you are given each turn — it is your persistent memory of everything discovered so far. Never re-discover what is already mapped.
2. Attack the UNTESTED surface first (it is listed for you). Do not re-test combos already in `tested`.
3. Form HYPOTHESES and record them with the `note` action so your future self remembers them — your raw action history is short, but notes persist forever.
4. Be context-aware. Before firing an exploit, confirm WHERE input reflects (HTML text vs attribute vs JS string vs JSON) and tailor the breakout. A blind payload is a wasted request.
5. Chain. An open redirect feeds SSRF; a decoded cookie may hide SQLi; a leaked API route may be unauthenticated. Use findings to reach deeper.
6. Converge. When the mapped surface is tested and no new leads remain, emit `done` — do not loop.

HIGH-VALUE TARGETS:
- Reflected input -> XSS (test executable contexts; backslash-quote breakout when servers escape \\ but not quotes)
- DB-backed params -> SQLi (error-based with ' or ", time-based with sleep, UNION). Decode Base64/JSON cookies and inject INSIDE them.
- Template evaluation -> CSTI/SSTI: probe with {{{_CSTI_EXPR}}} and look for {_CSTI_RESULT} (NOT the literal expression). Engine-specific next.
- File/path params -> LFI (../../../etc/passwd -> look for root:x:0:0)
- Params feeding shell/exec -> OS command injection (try `;id`, `|id`, `$(id)`, backticks -> look for uid=...gid=)
- url/redirect/next params -> Open Redirect / SSRF
- Hidden forms, admin panels, API routes in JS files, error pages leaking stack traces/versions
- Missing security headers, Set-Cookie without Secure/HttpOnly

PAYLOAD RULES:
- NEVER use alert(1). Use document.domain or a unique DOM marker.
- Always verify your probe reflects BEFORE sending the heavy exploit.
- For time-based SQLi use a clear sleep (e.g. sleep(5)) so timing is unambiguous.

OUTPUT — respond with EXACTLY ONE JSON action, nothing else:

Fetch a page (also POST/JSON/cookies/headers):
{{"action": "fetch", "url": "https://t/path", "method": "GET", "params": {{"q":"x"}}, "data": {{"u":"a"}}, "json_body": {{"k":"v"}}, "cookies": {{"c":"v"}}, "headers": {{"X-Forwarded-For":"127.0.0.1"}}}}

Test a payload (inject_in: param|cookie|header|json|path):
{{"action": "test", "url": "https://t/search", "parameter": "q", "payload": "<img src=x onerror=document.domain>", "vuln_type": "XSS", "severity": "HIGH", "method": "GET", "inject_in": "param"}}

Record a persistent hypothesis / observation (survives forever — use this as your memory):
{{"action": "note", "text": "searchTerm reflects in a JS single-quoted string; try \\\\' breakout"}}

When the mapped surface is exhausted:
{{"action": "done", "reason": "..."}}

Output ONLY the JSON object."""

# SQL error signatures for error-based SQLi detection
_SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_", "ora-", "postgresql", "sqlite3",
    "sqlstate", "unclosed quotation", "quoted string not properly terminated",
    "microsoft sql native client", "odbc sql server driver",
    "pg::syntaxerror", "syntax error in sql", "unterminated string",
    "java.sql.sqlexception", "com.mysql.jdbc", "psql:", "warning: pg_",
]

# Time-based SQLi indicators in payloads
_TIME_INDICATORS = ["sleep", "waitfor", "pg_sleep", "benchmark", "delay"]

# LFI success signatures
_LFI_SIGNATURES = [
    re.compile(r"root:.*?:0:0:"),          # /etc/passwd
    re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.I),  # win.ini
    re.compile(r"daemon:.*?:/usr/sbin"),
]

# RCE / OS-command-injection success signatures (command output in the response)
_RCE_SIGNATURES = [
    re.compile(r"uid=\d+\([\w-]+\)\s+gid=\d+"),     # `id` on *nix
    re.compile(r"Volume Serial Number is [0-9A-F]{4}-[0-9A-F]{4}", re.I),  # `dir` on Windows
    re.compile(r"\broot:.*?:0:0:"),                 # `cat /etc/passwd` via cmd
]

# Server-side template engine error signatures (error-based SSTI confirmation)
_TEMPLATE_ERROR_SIGS = [
    "jinja2.exceptions", "twig_error", "twig\\error", "freemarker.core",
    "smarty_compiler", "templatesyntaxerror", "mako.exceptions",
    "velocity.exception", "org.thymeleaf",
]

# Regexes for autonomous HTML surface extraction (no BeautifulSoup dependency)
_RE_HREF = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#\s>]+)""", re.I)
_RE_INPUT = re.compile(r"""<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["']""", re.I)
_RE_FORM = re.compile(r"<form\b[^>]*>", re.I)
_RE_SERVER_HDR = ("Server", "X-Powered-By")
_SECURITY_HEADERS = (
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
)


class KnowledgeBase:
    """Persistent memory of the engagement — the fix for v1's amnesia.

    Holds the app map (endpoints, params, cookies, tech), the LLM's own
    hypotheses (notes), confirmed findings, weaker suspicions, and a `tested`
    fingerprint set so the agent never repeats a probe. Rendered compactly into
    every prompt so the model always reasons from the FULL picture, not counters.
    """

    def __init__(self, target_url: str):
        self.target = target_url
        self.origin = self._origin(target_url)
        self.tech: Dict[str, str] = {}
        self.missing_sec_headers: Set[str] = set()
        self.endpoints: Dict[str, Dict] = {}          # path -> {status, ctype, params:set, methods:set}
        self.params: Dict[str, Dict] = {}             # name -> {urls:set, contexts:set, probed:bool}
        self.cookies: Dict[str, Dict] = {}            # name -> {flags, structured}
        self.findings: List[Dict] = []
        self.suspicions: List[Dict] = []
        self.notes: List[str] = []                    # LLM-authored persistent hypotheses
        self.tested: Set[str] = set()                 # fingerprints of probed combos
        self.urls_visited: Set[str] = set()

    @staticmethod
    def _origin(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _same_origin(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == urlparse(self.target).netloc
        except Exception:
            return False

    def add_endpoint(self, url: str, status: int, ctype: str, method: str = "GET"):
        key = self._path_key(url)
        ep = self.endpoints.setdefault(key, {"status": status, "ctype": ctype, "params": set(), "methods": set()})
        # Don't let a re-discovered link (status 0 / unknown ctype) clobber real data
        # we already learned by visiting the endpoint.
        if status:
            ep["status"] = status
        if ctype:
            ep["ctype"] = ctype
        ep["methods"].add(method.upper())
        # URL query params count as discovered params
        for pname in parse_qs(urlparse(url).query):
            ep["params"].add(pname)
            self.add_param(pname, url)

    @staticmethod
    def _path_key(url: str) -> str:
        p = urlparse(url)
        return p.path or "/"

    def add_param(self, name: str, url: str, context: Optional[str] = None):
        if not name:
            return
        pinfo = self.params.setdefault(name, {"urls": set(), "contexts": set(), "probed": False})
        pinfo["urls"].add(self._path_key(url))
        if context:
            pinfo["contexts"].add(context)

    def add_cookie(self, name: str, flags: str, structured: bool):
        self.cookies[name] = {"flags": flags, "structured": structured}

    def add_note(self, text: str):
        text = (text or "").strip()
        if text and text not in self.notes:
            self.notes.append(text)
            if len(self.notes) > 40:
                self.notes = self.notes[-40:]

    def fingerprint(self, url: str, param: str, payload: str, inject_in: str) -> str:
        # Collapse payloads to a class so trivial variations still count as tested
        pclass = re.sub(r"\d+", "N", (payload or ""))[:40]
        return f"{self._path_key(url)}|{param}|{inject_in}|{pclass}"

    def is_tested(self, url: str, param: str, payload: str, inject_in: str) -> bool:
        return self.fingerprint(url, param, payload, inject_in) in self.tested

    def mark_tested(self, url: str, param: str, payload: str, inject_in: str):
        self.tested.add(self.fingerprint(url, param, payload, inject_in))
        if param in self.params:
            self.params[param]["probed"] = True

    def untested_surface(self) -> Tuple[List[str], List[str]]:
        """Return (unprobed_params, unvisited_endpoint_paths) to steer the agent."""
        unprobed = [n for n, p in self.params.items() if not p["probed"]]
        unvisited = [k for k in self.endpoints if k not in {self._path_key(u) for u in self.urls_visited}]
        return unprobed[:25], unvisited[:25]

    def render(self) -> str:
        """Compact textual snapshot injected into every prompt."""
        lines = [f"Target: {self.target}"]
        if self.tech:
            lines.append("Tech: " + ", ".join(f"{k}={v}" for k, v in list(self.tech.items())[:8]))
        if self.missing_sec_headers:
            lines.append("Missing security headers: " + ", ".join(sorted(self.missing_sec_headers)))

        if self.endpoints:
            lines.append(f"\nEndpoints discovered ({len(self.endpoints)}):")
            for k, ep in list(self.endpoints.items())[:25]:
                ps = ",".join(sorted(ep["params"])[:8]) or "-"
                lines.append(f"  [{ep['status']}] {','.join(sorted(ep['methods']))} {k}  params={ps}")

        if self.params:
            lines.append(f"\nParameters ({len(self.params)}):")
            for n, p in list(self.params.items())[:25]:
                ctx = ",".join(sorted(p["contexts"])) if p["contexts"] else "?"
                lines.append(f"  {n}  reflects={ctx}  probed={p['probed']}")

        if self.cookies:
            lines.append("\nCookies: " + "; ".join(
                f"{n}({'structured' if c['structured'] else 'opaque'};{c['flags'] or 'no-flags'})"
                for n, c in list(self.cookies.items())[:8]))

        unprobed, unvisited = self.untested_surface()
        if unprobed:
            lines.append("\nUNTESTED params (attack these): " + ", ".join(unprobed))
        if unvisited:
            lines.append("UNVISITED endpoints: " + ", ".join(unvisited[:15]))

        if self.findings:
            lines.append(f"\nCONFIRMED findings ({len(self.findings)}):")
            for f in self.findings[-10:]:
                lines.append(f"  {f['severity']} {f['type']} on '{f['parameter']}' @ {self._path_key(f['url'])} ({f.get('confirmation_method','')})")

        if self.suspicions:
            lines.append(f"\nSUSPICIONS to verify ({len(self.suspicions)}):")
            for s in self.suspicions[-8:]:
                lines.append(f"  {s['type']} on '{s['parameter']}' @ {self._path_key(s['url'])} — {s.get('why','')}")

        if self.notes:
            lines.append("\nYour notes / hypotheses (persistent memory):")
            for note in self.notes[-15:]:
                lines.append(f"  - {note}")

        return "\n".join(lines)


class LoneWolf:
    """Autonomous exploration agent that runs parallel to the pipeline.

    Usage:
        wolf = LoneWolf(target_url, scan_dir)
        asyncio.create_task(wolf.run())  # fire-and-forget
    """

    def __init__(self, target_url: str, scan_dir: Path):
        self.target_url = target_url
        self.scan_dir = scan_dir
        self.kb = KnowledgeBase(target_url)
        self.findings: List[Dict] = self.kb.findings  # alias kept for back-compat
        self.session: Optional[aiohttp.ClientSession] = None

        self.model = settings.LONEWOLF_MODEL
        self.rate_limit = settings.LONEWOLF_RATE_LIMIT
        self.truncate_len = settings.LONEWOLF_RESPONSE_TRUNCATE
        # New tunables (getattr keeps backward-compat if .conf lacks them)
        self.max_cycles = int(getattr(settings, "LONEWOLF_MAX_CYCLES", 120))
        self.no_progress_limit = int(getattr(settings, "LONEWOLF_NO_PROGRESS_LIMIT", 18))
        self.recent_window = int(getattr(settings, "LONEWOLF_RECENT_WINDOW", 6))

        self._recent: List[str] = []          # short rolling tail of raw actions
        self._last_request_time = 0.0
        self._cycle_count = 0
        self._consecutive_llm_failures = 0
        self._no_progress = 0

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> List[Dict]:
        logger.info(f"[LoneWolf] Starting autonomous exploration of {self.target_url}")
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15, connect=5),
            headers={"User-Agent": settings.USER_AGENT},
            connector=aiohttp.TCPConnector(limit=5, ssl=False, enable_cleanup_closed=True),
        )
        try:
            return await self._exploration_loop()
        except asyncio.CancelledError:
            logger.info("[LoneWolf] Cancelled by pipeline")
            return self.kb.findings
        except Exception as e:
            logger.error(f"[LoneWolf] Fatal error: {e}", exc_info=True)
            return self.kb.findings
        finally:
            if self.session and not self.session.closed:
                await self.session.close()
            self._save_results()
            logger.info(
                f"[LoneWolf] Finished: {len(self.kb.findings)} findings, "
                f"{len(self.kb.suspicions)} suspicions, {len(self.kb.endpoints)} endpoints "
                f"in {self._cycle_count} cycles"
            )

    # ------------------------------------------------------------------
    # Core exploration loop
    # ------------------------------------------------------------------

    async def _exploration_loop(self) -> List[Dict]:
        # Autonomous recon seed: map the surface BEFORE spending LLM cycles.
        await self._seed_recon()
        await self._write_progress(f"LoneWolf mapped {len(self.kb.endpoints)} endpoints on {self.target_url}")

        while True:
            if not settings.LONEWOLF_ENABLED:
                logger.info("[LoneWolf] Disabled in config, shutting down gracefully.")
                break
            if self._cycle_count >= self.max_cycles:
                logger.info(f"[LoneWolf] Reached max cycles ({self.max_cycles}), stopping")
                break
            if self._no_progress >= self.no_progress_limit:
                logger.info(f"[LoneWolf] No progress for {self.no_progress_limit} cycles — converged, stopping")
                break

            self._cycle_count += 1
            logger.info(f"[LoneWolf] === Cycle {self._cycle_count}/{self.max_cycles} (no-progress {self._no_progress}/{self.no_progress_limit}) ===")

            action = await self._think()
            if action is None:
                self._consecutive_llm_failures += 1
                if self._consecutive_llm_failures >= 3:
                    logger.warning("[LoneWolf] 3 consecutive LLM failures, stopping")
                    break
                self._no_progress += 1
                continue
            self._consecutive_llm_failures = 0

            atype = action.get("action", "unknown")
            if atype == "done":
                logger.info(f"[LoneWolf] LLM decided to stop: {action.get('reason','')}")
                break

            if atype == "note":
                self.kb.add_note(action.get("text", ""))
                self._push_recent(f"note: {action.get('text','')[:120]}")
                # a note is progress (new hypothesis) but cheap — small credit
                self._no_progress = max(0, self._no_progress - 1)
                continue

            progressed = await self._execute(action)
            self._no_progress = 0 if progressed else self._no_progress + 1

            if self._cycle_count % 15 == 0:
                await self._write_progress(
                    f"LoneWolf: {len(self.kb.endpoints)} endpoints, "
                    f"{len(self.kb.findings)} findings, cycle {self._cycle_count}"
                )

        await self._write_progress(
            f"LoneWolf finished: {len(self.kb.findings)} findings in {self._cycle_count} cycles"
        )
        return self.kb.findings

    # ------------------------------------------------------------------
    # Autonomous recon seed
    # ------------------------------------------------------------------

    async def _seed_recon(self):
        """Fetch the target + a few well-known paths and auto-map the surface."""
        seeds = [
            self.target_url,
            urljoin(self.kb.origin + "/", "robots.txt"),
            urljoin(self.kb.origin + "/", "sitemap.xml"),
        ]
        for url in seeds:
            resp = await self._fetch(url)
            if resp["ok"]:
                self._ingest_response(url, resp)

    # ------------------------------------------------------------------
    # LLM reasoning
    # ------------------------------------------------------------------

    async def _think(self) -> Optional[Dict]:
        prompt = self._build_prompt()
        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="LoneWolf",
                model_override=self.model,
                system_prompt=SYSTEM_PROMPT,
                temperature=0.6,
                max_tokens=1200,
            )
        except Exception as e:
            logger.debug(f"[LoneWolf] LLM call failed: {e}")
            return None
        if not response:
            return None
        parsed = llm_client.validate_json_response(response)
        if parsed is None:
            logger.debug("[LoneWolf] Failed to parse LLM response as JSON")
        return parsed

    def _build_prompt(self) -> str:
        recent = "\n".join(f"  - {r}" for r in self._recent[-self.recent_window:]) or "  (none yet)"
        return (
            f"{self.kb.render()}\n\n"
            f"Recent raw actions (short tail — rely on the KNOWLEDGE BASE above for the full picture):\n{recent}\n\n"
            f"Cycle {self._cycle_count}/{self.max_cycles}. "
            f"Pick the single highest-value next action against the UNTESTED surface. "
            f"Record hypotheses with `note`. Output one JSON action."
        )

    def _push_recent(self, line: str):
        self._recent.append(line)
        if len(self._recent) > self.recent_window * 2:
            self._recent = self._recent[-self.recent_window * 2:]

    # ------------------------------------------------------------------
    # Action execution -- returns True if it produced PROGRESS
    # ------------------------------------------------------------------

    async def _execute(self, action: Dict) -> bool:
        atype = action.get("action", "")
        if atype == "fetch":
            url = action.get("url", self.target_url)
            if not self.kb._same_origin(url):
                self._push_recent(f"fetch SKIPPED off-origin {url[:60]}")
                return False
            before_ep = len(self.kb.endpoints)
            before_pa = len(self.kb.params)
            resp = await self._fetch(
                url=url,
                method=action.get("method", "GET"),
                params=action.get("params"),
                data=action.get("data"),
                json_body=action.get("json_body"),
                cookies=action.get("cookies"),
                headers=action.get("headers"),
            )
            self._ingest_response(url, resp, method=action.get("method", "GET"))
            self._push_recent(f"{action.get('method','GET')} {self.kb._path_key(url)} -> {resp['status']} ({resp['ctype'][:20]})")
            # progress if we learned new surface
            return (len(self.kb.endpoints) > before_ep) or (len(self.kb.params) > before_pa)

        if atype == "test":
            return await self._test_payload(action)

        self._push_recent(f"unknown action {atype}")
        return False

    # ------------------------------------------------------------------
    # HTTP fetch with retry -> structured response
    # ------------------------------------------------------------------

    async def _fetch(self, url: str, method: str = "GET", params=None, data=None,
                     json_body=None, cookies=None, headers=None) -> Dict:
        """Rate-limited HTTP request with retry. Returns a structured dict:
        {ok, status, ctype, headers, body, elapsed, url}."""
        max_attempts = 3
        backoff_base = 1.0
        last_error = ""
        kwargs: Dict = {"allow_redirects": True}
        if params:
            kwargs["params"] = params
        if data:
            kwargs["data"] = data
        if json_body:
            kwargs["json"] = json_body
        if cookies:
            kwargs["cookies"] = cookies
        if headers:
            kwargs["headers"] = headers

        for attempt in range(1, max_attempts + 1):
            await self._rate_limit_wait()
            start = time.monotonic()
            try:
                async with self.session.request(method, url, **kwargs) as resp:
                    elapsed = time.monotonic() - start
                    body = await resp.text()
                    self.kb.urls_visited.add(url)
                    if resp.status == 429 and attempt < max_attempts:
                        ra = resp.headers.get("Retry-After")
                        await asyncio.sleep(float(ra) if ra and ra.isdigit() else backoff_base * (2 ** (attempt - 1)))
                        last_error = "HTTP 429"
                        continue
                    if resp.status == 503 and attempt < max_attempts:
                        await asyncio.sleep(backoff_base * (2 ** (attempt - 1)))
                        last_error = "HTTP 503"
                        continue
                    return {
                        "ok": True,
                        "status": resp.status,
                        "ctype": resp.headers.get("Content-Type", ""),
                        "headers": {k: v for k, v in resp.headers.items()},
                        "body": body,
                        "elapsed": elapsed,
                        "url": str(resp.url),
                    }
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                last_error = f"{type(e).__name__}: {e}"
                if attempt < max_attempts:
                    await asyncio.sleep(backoff_base * (2 ** (attempt - 1)))
                    continue
        logger.debug(f"[LoneWolf] Fetch failed after {max_attempts} attempts: {last_error}")
        return {"ok": False, "status": 0, "ctype": "", "headers": {}, "body": f"ERROR: {last_error}", "elapsed": 0.0, "url": url}

    # ------------------------------------------------------------------
    # Autonomous surface ingestion (regex, no deps)
    # ------------------------------------------------------------------

    def _ingest_response(self, url: str, resp: Dict, method: str = "GET"):
        if not resp["ok"]:
            return
        self.kb.add_endpoint(resp["url"], resp["status"], resp["ctype"], method)

        # Tech fingerprint from headers
        for h in _RE_SERVER_HDR:
            v = resp["headers"].get(h)
            if v:
                self.kb.tech[h] = v[:80]
        # Missing security headers (only meaningful on real HTML pages)
        if "html" in resp["ctype"]:
            for h in _SECURITY_HEADERS:
                if h not in resp["headers"]:
                    self.kb.missing_sec_headers.add(h)
        # Cookies
        for name, val in self._parse_set_cookies(resp["headers"]):
            flags = []
            low = val.lower()
            if "httponly" not in low:
                flags.append("no-HttpOnly")
            if "secure" not in low:
                flags.append("no-Secure")
            cookie_val = val.split("=", 1)[1].split(";", 1)[0] if "=" in val else ""
            self.kb.add_cookie(name, ",".join(flags), self._looks_structured(cookie_val))

        body = resp["body"]
        if "html" in resp["ctype"] or "xml" in resp["ctype"]:
            # Links / endpoints
            for m in _RE_HREF.findall(body)[:200]:
                absu = urljoin(resp["url"], m)
                if self.kb._same_origin(absu):
                    self.kb.add_endpoint(absu, 0, "", "GET")
            # Form/input params
            for name in _RE_INPUT.findall(body)[:100]:
                self.kb.add_param(name, resp["url"])

    @staticmethod
    def _parse_set_cookies(headers: Dict[str, str]) -> List[Tuple[str, str]]:
        out = []
        raw = headers.get("Set-Cookie")
        if raw:
            name = raw.split("=", 1)[0].strip()
            out.append((name, raw))
        return out

    @staticmethod
    def _looks_structured(val: str) -> bool:
        if not val:
            return False
        if val.startswith("{") or val.startswith("%7B"):
            return True
        # base64-ish
        try:
            dec = base64.b64decode(val + "===", validate=False)
            return dec.startswith(b"{") or b":" in dec[:30]
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Payload testing with STRICT, context-aware confirmation
    # ------------------------------------------------------------------

    async def _test_payload(self, action: Dict) -> bool:
        url = action.get("url", self.target_url)
        param = action.get("parameter", "")
        payload = action.get("payload", "")
        vuln_type = (action.get("vuln_type", "Unknown") or "Unknown")
        severity = action.get("severity", "MEDIUM")
        method = action.get("method", "GET")
        inject_in = action.get("inject_in", "param")

        if not payload or not param:
            self._push_recent("test SKIPPED (missing param/payload)")
            return False
        if not self.kb._same_origin(url):
            self._push_recent(f"test SKIPPED off-origin {url[:50]}")
            return False
        if self.kb.is_tested(url, param, payload, inject_in):
            self._push_recent(f"test SKIPPED already-tested {param} ({vuln_type})")
            return False
        self.kb.mark_tested(url, param, payload, inject_in)

        resp = await self._send_injected(url, param, payload, method, inject_in)
        if not resp["ok"]:
            self._push_recent(f"test {param} -> request error")
            return False

        # Learn WHERE this param reflects so the LLM (and future breakouts) are context-aware.
        ctx = self._reflection_context(resp["body"], payload)
        if ctx:
            self.kb.add_param(param, url, context=ctx)

        verdict = self._confirm(vuln_type, payload, resp)

        # Time-based SQLi needs re-confirmation (deterministic eval repeats; jitter doesn't)
        if verdict is None and self._is_time_payload(payload) and resp["elapsed"] > 4.5:
            verdict = await self._reconfirm_time_based(url, param, payload, method, inject_in, resp["elapsed"])

        if verdict is None:
            self._push_recent(f"test {param} ({vuln_type}) -> not confirmed")
            return False

        self._record_finding(verdict, vuln_type, url, param, payload, severity, inject_in)
        progressed = verdict["strength"] == "confirmed"
        self._push_recent(f"test {param} ({vuln_type}) -> {verdict['strength'].upper()} via {verdict['method']}")
        return progressed

    async def _send_injected(self, url: str, param: str, payload: str, method: str, inject_in: str) -> Dict:
        fetch_kwargs: Dict = {"method": method}
        target = url
        if inject_in == "cookie":
            fetch_kwargs["cookies"] = {param: payload}
        elif inject_in == "header":
            fetch_kwargs["headers"] = {param: payload}
        elif inject_in == "json":
            fetch_kwargs["json_body"] = {param: payload}
        elif inject_in == "path":
            target = url.replace(f"{{{param}}}", quote(payload))
        else:
            if method.upper() == "POST":
                fetch_kwargs["data"] = {param: payload}
            else:
                fetch_kwargs["params"] = {param: payload}
        return await self._fetch(target, **fetch_kwargs)

    def _confirm(self, vuln_type: str, payload: str, resp: Dict) -> Optional[Dict]:
        """Strict per-class confirmation. Returns a verdict dict or None.

        strength: 'confirmed' (deterministic proof) | 'suspected' (worth manual review).
        Reflection ALONE is never 'confirmed' — that was v1's FP backdoor.
        """
        body = resp["body"]
        ctype = resp["ctype"].lower()
        is_html = "html" in ctype
        vt = vuln_type.strip().upper()

        # --- XSS / HTML injection: require EXECUTABLE reflection ---
        if "XSS" in vt or "HTML" in vt:
            if html.escape(payload) != payload and html.escape(payload) in body:
                return self._suspect("encoded_reflection", "payload reflected but HTML-encoded (not executable)", body, html.escape(payload))
            if payload in body:
                if is_html and ("<" in payload and ">" in payload):
                    return self._confirmed("xss_executable_reflection", body, payload)
                # reflected raw but not in an HTML execution context
                return self._suspect("raw_reflection_nonhtml", f"reflected raw in {ctype or 'unknown'} context", body, payload)
            return None

        # --- RCE / OS command injection: command output in the response ---
        if "RCE" in vt or "COMMAND" in vt or "OS COMMAND" in vt or vt == "INJECTION":
            for rx in _RCE_SIGNATURES:
                if rx.search(body):
                    return self._confirmed("command_output", body, rx.pattern)
            return None

        # --- CSTI / SSTI: distinctive arithmetic eval OR template error signature ---
        if "CSTI" in vt or "SSTI" in vt or "TEMPLATE" in vt:
            if _CSTI_RESULT in body and _CSTI_EXPR not in body and payload not in body:
                return self._confirmed("template_arithmetic_eval", body, _CSTI_RESULT)
            low = body.lower()
            for sig in _TEMPLATE_ERROR_SIGS:
                if sig in low:
                    return self._confirmed("template_error_signature", body, sig)
            if "{{" in payload and payload in body:
                return self._suspect("template_literal_reflected", "template syntax reflected but not evaluated", body, payload)
            return None

        # --- SQLi: error-based (time-based handled by caller) ---
        if "SQL" in vt:
            has_meta = any(c in payload for c in ("'", '"', ";", "--", "/*", ")"))
            if has_meta:
                low = body.lower()
                for sig in _SQL_ERROR_SIGNATURES:
                    if sig in low and payload.lower() not in low:
                        return self._confirmed("error_based", body, sig)
            return None

        # --- LFI / path traversal: file content signatures ---
        if "LFI" in vt or "TRAVERSAL" in vt or "FILE" in vt:
            for rx in _LFI_SIGNATURES:
                if rx.search(body):
                    return self._confirmed("file_disclosure", body, rx.pattern)
            return None

        # --- Open Redirect / SSRF: redirect to attacker-controlled host ---
        if "REDIRECT" in vt or "SSRF" in vt:
            loc = resp["headers"].get("Location", "")
            phost = urlparse(payload if "//" in payload else "//" + payload).netloc
            if loc and phost and phost in loc and not self.kb._same_origin(loc):
                return self._confirmed("external_redirect", loc, phost)
            return None

        # --- Generic: raw reflection is only a suspicion ---
        if payload in body:
            return self._suspect("raw_reflection", "input reflected — needs manual validation", body, payload)
        return None

    async def _reconfirm_time_based(self, url, param, payload, method, inject_in, first_elapsed) -> Optional[Dict]:
        """Re-confirm time-based SQLi: real injection is deterministic, jitter is not.
        Require the slow response to REPEAT and a benign baseline to be fast."""
        threshold = self._sleep_seconds(payload) * 0.7 or 4.5
        r2 = await self._send_injected(url, param, payload, method, inject_in)
        benign = re.sub(r"(sleep|pg_sleep|benchmark|waitfor\s+delay)[^)]*\)?", "0", payload, flags=re.I)
        rb = await self._send_injected(url, param, benign, method, inject_in)
        if r2["ok"] and rb["ok"] and first_elapsed > threshold and r2["elapsed"] > threshold and rb["elapsed"] < threshold * 0.6:
            return self._confirmed(
                f"time_based_reconfirmed:{first_elapsed:.1f}s/{r2['elapsed']:.1f}s vs baseline {rb['elapsed']:.1f}s",
                f"slow x2 ({first_elapsed:.1f}s, {r2['elapsed']:.1f}s), baseline fast ({rb['elapsed']:.1f}s)", "")
        return None

    @staticmethod
    def _is_time_payload(payload: str) -> bool:
        low = payload.lower()
        return any(ind in low for ind in _TIME_INDICATORS)

    @staticmethod
    def _sleep_seconds(payload: str) -> float:
        m = re.search(r"(?:sleep|pg_sleep|delay\s+'?0?0?:?0?0?:?)\s*\(?\s*(\d+)", payload, re.I)
        try:
            return float(m.group(1)) if m else 5.0
        except Exception:
            return 5.0

    @staticmethod
    def _reflection_context(body: str, value: str) -> Optional[str]:
        """Classify WHERE a reflected value lands, so breakouts can be tailored.

        Returns one of: js_string_single|js_string_double|js_string_template|
        script_block|html_attribute|url_context|html_comment|html_text — or None.
        Heuristic, regex-free, cheap. This is what makes the agent 'see' the sink.
        """
        idx = body.find(value)
        if idx == -1:
            return None
        pre = body[max(0, idx - 200):idx]
        # Inside a <script> block?
        if pre.rfind("<script") > pre.rfind("</script"):
            for q, label in (("'", "js_string_single"), ('"', "js_string_double"), ("`", "js_string_template")):
                qpos = pre.rfind(q)
                if qpos != -1 and pre.count(q) % 2 == 1:  # unbalanced => we're inside a string
                    return label
            return "script_block"
        # Inside an HTML comment?
        if pre.rfind("<!--") > pre.rfind("-->"):
            return "html_comment"
        # Inside a tag (attribute value)?
        if pre.rfind("<") > pre.rfind(">"):
            tag = pre[pre.rfind("<"):].lower()
            if "href=" in tag or "src=" in tag:
                return "url_context"
            return "html_attribute"
        # href/src ending right before the value (link context outside a quote)
        return "html_text"

    @staticmethod
    def _snippet(body: str, needle: str) -> str:
        try:
            i = body.index(needle)
        except ValueError:
            try:
                i = body.lower().index(needle.lower())
            except ValueError:
                return body[:160]
        return body[max(0, i - 60): i + len(needle) + 60]

    def _confirmed(self, method: str, body: str, needle: str) -> Dict:
        return {"strength": "confirmed", "method": method, "evidence": self._snippet(body, needle) if needle else body[:200], "confidence": 0.9}

    def _suspect(self, method: str, why: str, body: str, needle: str) -> Dict:
        return {"strength": "suspected", "method": method, "why": why, "evidence": self._snippet(body, needle), "confidence": 0.4}

    def _record_finding(self, verdict: Dict, vuln_type, url, param, payload, severity, inject_in):
        confirmed = verdict["strength"] == "confirmed"
        finding = {
            "type": vuln_type,
            "url": url,
            "parameter": param,
            "payload": payload,
            "evidence": verdict["evidence"],
            "severity": severity,
            "status": "VALIDATED_CONFIRMED" if confirmed else "NEEDS_VALIDATION",
            "source": "lone_wolf",
            "specialist": "LoneWolf",
            "confirmation_method": verdict["method"],
            "fp_confidence": verdict["confidence"],
            "confidence_score": verdict["confidence"],
            "inject_in": inject_in,
        }
        if confirmed:
            self.kb.findings.append(finding)
            self._save_results()
            try:
                from bugtrace.core.event_bus import EventType, event_bus
                asyncio.ensure_future(event_bus.emit(EventType.VULNERABILITY_DETECTED, finding))
            except Exception:
                pass
            logger.info(f"[LoneWolf] CONFIRMED {vuln_type} on {param} ({verdict['method']})")
            asyncio.ensure_future(self._write_progress(f"LoneWolf confirmed: {vuln_type} on {param}"))
        else:
            finding["why"] = verdict.get("why", "")
            self.kb.suspicions.append(finding)
            self._save_results()
            logger.info(f"[LoneWolf] SUSPECTED {vuln_type} on {param} ({verdict['method']}) — needs validation")

    # ------------------------------------------------------------------
    # Rate limiter
    # ------------------------------------------------------------------

    async def _rate_limit_wait(self):
        if self.rate_limit <= 0:
            return
        min_interval = 1.0 / self.rate_limit
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request_time = time.monotonic()

    # ------------------------------------------------------------------
    # Results persistence
    # ------------------------------------------------------------------

    def _save_results(self):
        """Write findings (+ suspicions as NEEDS_VALIDATION) to the results glob."""
        results_dir = self.scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        output_path = results_dir / "lone_wolf_results.json"
        data = {
            "specialist": "lone_wolf",
            "findings": self.kb.findings + self.kb.suspicions,
        }
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            logger.debug(f"[LoneWolf] Saved {len(self.kb.findings)} confirmed + {len(self.kb.suspicions)} suspected")
        except Exception as e:
            logger.warning(f"[LoneWolf] Failed to save results: {e}")

    # ------------------------------------------------------------------
    # Progress reporting (DB write-only rule: never SELECT)
    # ------------------------------------------------------------------

    async def _write_progress(self, message: str):
        logger.info(f"[LoneWolf] {message}")
