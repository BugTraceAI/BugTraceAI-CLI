"""
Verbose Event Emitter - Fire-and-forget event emission for real-time scan narration.

Provides a lightweight wrapper around the core EventBus that:
- Injects scan_context + agent name into every event payload
- Supports sync-safe fire-and-forget emission (from sync or async code)
- Provides throttled progress events to prevent volume explosion
- Always includes _event key for pattern-based bridge handlers

Author: BugtraceAI Team
Date: 2026-02-10
Version: 1.0.0
"""

import asyncio
import re
import time
from typing import Dict, Any, Optional, Tuple


class VerboseEventEmitter:
    """
    Lightweight event emitter that holds scan_context + agent_name.

    Usage:
        from bugtrace.core.verbose_events import create_emitter
        v = create_emitter("XSSAgent", str(scan_id))
        v.emit("exploit.xss.level.started", {"level": 2, "param": "q"})
        v.progress("exploit.xss.level.progress", {"payload": p}, every=50)
    """

    def __init__(self, agent: str, scan_context: str, event_bus=None):
        self._agent = agent
        self._ctx = scan_context
        self._bus = event_bus
        self._counters: Dict[str, int] = {}

    def _payload(self, event: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Build event payload with standard fields."""
        return {
            "_event": event,
            "scan_context": self._ctx,
            "agent": self._agent,
            "ts": time.time(),
            **(data or {}),
        }

    def emit(self, event: str, data: Dict[str, Any] = None):
        """
        Fire-and-forget emit from sync or async context.

        Safe to call from anywhere — if no running event loop,
        the event is silently dropped (scan continues unaffected).
        """
        payload = self._payload(event, data)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._bus.emit(event, payload))
        except RuntimeError:
            pass

    async def aemit(self, event: str, data: Dict[str, Any] = None):
        """Awaitable emit for async code paths."""
        payload = self._payload(event, data)
        await self._bus.emit(event, payload)

    def progress(self, event: str, data: Dict[str, Any] = None, every: int = 50):
        """
        Throttled emit — fires on 1st call, then every N-th.

        Prevents event flooding during payload loops (e.g., 870 Go fuzzer payloads).
        The counter value 'n' is always included in the payload.
        """
        n = self._counters.get(event, 0) + 1
        self._counters[event] = n
        if n == 1 or n % every == 0:
            self.emit(event, {"n": n, **(data or {})})

    def reset(self, event: str = None):
        """Reset throttle counter(s). Call between params/phases."""
        if event:
            self._counters.pop(event, None)
        else:
            self._counters.clear()


def create_emitter(agent: str, scan_context: str) -> VerboseEventEmitter:
    """
    Factory function — creates a VerboseEventEmitter with the global event bus.

    Args:
        agent: Agent name (e.g., "XSSAgent", "DASTySAST", "pipeline")
        scan_context: Scan ID as string (e.g., str(self.scan_id))

    Returns:
        VerboseEventEmitter instance bound to the global event bus
    """
    from bugtrace.core.event_bus import event_bus
    return VerboseEventEmitter(agent, scan_context, event_bus)


# ---------------------------------------------------------------------------
# CLI UI Formatter — maps verbose events to human-readable messages for the
# Rich/Textual TUI LogPanel and terminal output via conductor.notify_log().
# ---------------------------------------------------------------------------

# (level, template) — {key} interpolated from event data
_TEMPLATES: Dict[str, Tuple[str, str]] = {
    # Pipeline
    'pipeline.initializing':       ('INFO',    '[PIPELINE] Initializing scan pipeline'),
    'pipeline.phase_transition':   ('INFO',    '[PIPELINE] → {from_phase} → {to_phase}'),
    'pipeline.checkpoint':         ('INFO',    '[PIPELINE] Checkpoint: {phase} verified'),
    'pipeline.error':              ('ERROR',   '[PIPELINE] Error: {error}'),
    'pipeline.heartbeat':          ('DEBUG',   '[PIPELINE] Heartbeat: {phase}'),
    'pipeline.completed':          ('INFO',    '[PIPELINE] Pipeline completed'),
    # Recon
    'recon.started':               ('INFO',    '[RECON] Reconnaissance started'),
    'recon.completed':             ('INFO',    '[RECON] Recon complete — {urls_found} URLs'),
    'recon.gospider.started':      ('INFO',    '[RECON] GoSpider crawling target'),
    'recon.gospider.completed':    ('INFO',    '[RECON] GoSpider done — {urls_found} URLs'),
    'recon.nuclei.started':        ('INFO',    '[RECON] Nuclei scanning'),
    'recon.nuclei.completed':      ('INFO',    '[RECON] Nuclei done — {matches} matches'),
    'recon.auth.completed':        ('INFO',    '[RECON] Auth discovery complete'),
    # Discovery
    'discovery.started':           ('INFO',    '[DAST] Discovery phase started'),
    'discovery.completed':         ('INFO',    '[DAST] Discovery phase completed'),
    'discovery.url.started':       ('INFO',    '[DAST] Analyzing URL {index}/{total}'),
    'discovery.url.frameworks_detected': ('INFO', '[DAST] Frameworks: {frameworks}'),
    'discovery.url.params_found':  ('INFO',    '[DAST] {params_count} parameters found'),
    'discovery.probe.started':     ('INFO',    '[DAST] Probing {total_params} params'),
    'discovery.probe.completed':   ('INFO',    '[DAST] Probes: {reflecting} reflecting'),
    'discovery.llm.started':       ('INFO',    '[DAST] LLM analysis (approach {approach})'),
    'discovery.llm.completed':     ('INFO',    '[DAST] LLM done — {findings_count} findings'),
    'discovery.consolidation.completed': ('INFO', '[DAST] Consolidated: {raw}→{dedup}→{passing}'),
    'discovery.url.completed':     ('INFO',    '[DAST] URL done — {findings_count} findings'),
    # Strategy
    'strategy.started':            ('INFO',    '[STRATEGY] Strategy phase started'),
    'strategy.completed':          ('INFO',    '[STRATEGY] Strategy phase completed'),
    'strategy.thinking.batch_started': ('INFO', '[STRATEGY] Batch: {batch_size} findings'),
    'strategy.finding.classified': ('INFO',    '[STRATEGY] {type} → {specialist}'),
    'strategy.finding.queued':     ('INFO',    '[STRATEGY] Queued for {specialist}'),
    'strategy.finding.backpressure': ('WARNING', '[STRATEGY] Backpressure: {specialist}'),
    'strategy.distribution_summary': ('INFO',  '[STRATEGY] {received}→{filtered}→{distributed}'),
    'strategy.auto_dispatch':      ('INFO',    '[STRATEGY] Auto-dispatch: {specialist}'),
    'strategy.nuclei_injected':    ('INFO',    '[STRATEGY] Nuclei injected: {count}'),
    # Exploitation: XSS
    'exploit.xss.started':         ('INFO',    '[XSS] Agent started on {url}'),
    'exploit.xss.completed':       ('INFO',    '[XSS] Done — {confirmed_count} confirmed'),
    'exploit.xss.waf_detected':    ('WARNING', '[XSS] WAF detected'),
    'exploit.xss.param.started':   ('INFO',    '[XSS] Testing param \'{param}\''),
    'exploit.xss.level.started':   ('INFO',    '[XSS] Level {level} on \'{param}\''),
    'exploit.xss.level.progress':  ('DEBUG',   '[XSS] L{level}: {n} payloads on \'{param}\''),
    'exploit.xss.go_fuzzer.started': ('INFO',  '[XSS] Go Fuzzer on \'{param}\''),
    'exploit.xss.go_fuzzer.completed': ('INFO', '[XSS] Go Fuzzer done — {payloads_tested}p'),
    'exploit.xss.browser.testing': ('INFO',    '[XSS] Browser validation \'{param}\''),
    'exploit.xss.confirmed':       ('SUCCESS', '[XSS] CONFIRMED on \'{param}\' — L{level}'),
    'exploit.xss.interactsh.callback': ('SUCCESS', '[XSS] OOB callback received!'),
    # Exploitation: SQLi
    'exploit.sqli.started':        ('INFO',    '[SQLi] Agent started on {url}'),
    'exploit.sqli.completed':      ('INFO',    '[SQLi] Done — {confirmed_count} confirmed'),
    'exploit.sqli.param.started':  ('INFO',    '[SQLi] Testing param \'{param}\''),
    'exploit.sqli.level.started':  ('INFO',    '[SQLi] Level {level} on \'{param}\''),
    'exploit.sqli.level.progress': ('DEBUG',   '[SQLi] L{level}: {n} payloads on \'{param}\''),
    'exploit.sqli.error_found':    ('INFO',    '[SQLi] Error-based: {db_type} on \'{param}\''),
    'exploit.sqli.boolean_diff':   ('INFO',    '[SQLi] Boolean diff on \'{param}\''),
    'exploit.sqli.union_found':    ('INFO',    '[SQLi] UNION: {columns} cols on \'{param}\''),
    'exploit.sqli.oob.callback':   ('SUCCESS', '[SQLi] OOB callback on \'{param}\'!'),
    'exploit.sqli.time_delay':     ('INFO',    '[SQLi] Time delay on \'{param}\''),
    'exploit.sqli.confirmed':      ('SUCCESS', '[SQLi] CONFIRMED on \'{param}\' — {technique}'),
    # Exploitation: Generic specialists
    'exploit.specialist.started':  ('INFO',    '[{agent}] Started on {url}'),
    'exploit.specialist.completed': ('INFO',   '[{agent}] Completed'),
    'exploit.specialist.param.started': ('INFO', '[{agent}] Testing \'{param}\''),
    'exploit.specialist.progress': ('DEBUG',   '[{agent}] {n} payloads on \'{param}\''),
    'exploit.specialist.signature_match': ('INFO', '[{agent}] Signature match \'{param}\''),
    'exploit.specialist.confirmed': ('SUCCESS', '[{agent}] CONFIRMED on \'{param}\'!'),
    # Specialist lifecycle
    'exploit.specialist.activated': ('INFO',   '[EXPLOIT] Specialist up: {specialist}'),
    'exploit.specialist.queue_progress': ('INFO', '[EXPLOIT] Queue: {active}↑ {completed}✓ {pending}…'),
    'exploit.specialist.deactivated': ('INFO', '[EXPLOIT] Specialist down: {specialist}'),
    'exploit.phase_stats':         ('INFO',    '[EXPLOIT] {total_specialists} specialists, {findings} findings'),
    # Validation
    'validation.started':          ('INFO',    '[VALIDATION] Queue processor started'),
    'validation.completed':        ('INFO',    '[VALIDATION] Done — {cdp_confirmed}✓ {cdp_rejected}✗'),
    'validation.finding.queued':   ('INFO',    '[VALIDATION] Queued: {type} on \'{param}\''),
    'validation.finding.started':  ('INFO',    '[VALIDATION] Validating {type} \'{param}\''),
    'validation.browser.launching': ('INFO',   '[VALIDATION] Browser → {vuln_type} \'{param}\''),
    'validation.cdp.confirmed':    ('SUCCESS', '[VALIDATION] CDP CONFIRMED — alert: {alert}'),
    'validation.cdp.silent':       ('INFO',    '[VALIDATION] CDP silent → vision fallback'),
    'validation.vision.started':   ('INFO',    '[VALIDATION] Vision analysis for {type}'),
    'validation.vision.result':    ('INFO',    '[VALIDATION] Vision: {validated} ({confidence})'),
    'validation.finding.confirmed': ('SUCCESS', '[VALIDATION] VALIDATED: {type} on \'{param}\''),
    'validation.finding.rejected': ('WARNING', '[VALIDATION] Rejected: {type} on \'{param}\''),
    # Reporting
    'reporting.started':           ('INFO',    '[REPORTING] Generating report'),
    'reporting.completed':         ('INFO',    '[REPORTING] Report generation complete'),
    'reporting.scan_summary':      ('INFO',    '[REPORTING] {findings_count} findings'),
    'reporting.error':             ('ERROR',   '[REPORTING] Error: {error}'),
}

# Category → tag for auto-formatter
_CATEGORY_TAGS = {
    'pipeline': 'PIPELINE', 'recon': 'RECON', 'discovery': 'DAST',
    'strategy': 'STRATEGY', 'exploit': 'EXPLOIT',
    'validation': 'VALIDATION', 'reporting': 'REPORTING',
}

# Humanize subcategory names
_HUMANIZE = {
    'xss': 'XSS', 'sqli': 'SQLi', 'lfi': 'LFI', 'ssrf': 'SSRF',
    'csti': 'CSTI', 'idor': 'IDOR', 'rce': 'RCE', 'xxe': 'XXE',
    'cdp': 'CDP', 'llm': 'LLM', 'dom': 'DOM', 'waf': 'WAF',
    'go_fuzzer': 'Go Fuzzer', 'oob': 'OOB', 'gospider': 'GoSpider',
    'nuclei': 'Nuclei', 'sqlmap': 'SQLMap',
}

# Action → level for auto-formatter
_ACTION_LEVELS = {
    'confirmed': 'SUCCESS', 'error': 'ERROR', 'rejected': 'WARNING',
    'waf_detected': 'WARNING', 'fp_filtered': 'WARNING',
    'backpressure': 'WARNING', 'progress': 'DEBUG', 'heartbeat': 'DEBUG',
}


def _interp(template: str, data: Dict[str, Any]) -> str:
    """Interpolate {field} placeholders from event data."""
    def replacer(m):
        val = data.get(m.group(1))
        if val is None or val == '':
            return ''
        s = str(val)
        return s[:77] + '...' if len(s) > 77 else s
    result = re.sub(r'\{(\w+)\}', replacer, template)
    return re.sub(r' {2,}', ' ', result).strip()


def _humanize_part(part: str) -> str:
    return _HUMANIZE.get(part, part.replace('_', ' ').title())


def _auto_format(event_name: str, data: Dict[str, Any]) -> Tuple[str, str]:
    """Auto-generate (level, message) from event name structure."""
    parts = event_name.split('.')
    category = parts[0]
    action = parts[-1]
    tag = _CATEGORY_TAGS.get(category, category.upper())
    level = _ACTION_LEVELS.get(action, 'INFO')
    middle = ' '.join(_humanize_part(p) for p in parts[1:-1])
    action_label = _humanize_part(action)
    suffix = ''
    if data.get('param'):
        suffix += f" '{data['param']}'"
    if data.get('agent') and not middle:
        suffix = f" {data['agent']}{suffix}"
    detail = f"{middle} " if middle else ''
    return level, f"[{tag}] {detail}{action_label}{suffix}"


def format_event(event_name: str, data: Dict[str, Any]) -> Tuple[str, str]:
    """
    Format a verbose event for CLI display.

    Returns:
        Tuple of (level, formatted_message)
        level: 'DEBUG', 'INFO', 'WARNING', 'ERROR', or 'SUCCESS'
    """
    template = _TEMPLATES.get(event_name)
    if template:
        level, tmpl = template
        return level, _interp(tmpl, data)
    return _auto_format(event_name, data)


# ---------------------------------------------------------------------------
# UI Bridge — subscribes to verbose events and routes to conductor.notify_log()
# ---------------------------------------------------------------------------

_bridge_installed = False


def install_ui_bridge() -> None:
    """
    Subscribe to all verbose event patterns on the core EventBus
    and route formatted messages to the conductor for TUI display.

    Safe to call multiple times — installs only once.
    """
    global _bridge_installed
    if _bridge_installed:
        return
    _bridge_installed = True

    from bugtrace.core.event_bus import event_bus
    from bugtrace.core.conductor import conductor

    prefixes = [
        "pipeline.*", "recon.*", "discovery.*", "strategy.*",
        "exploit.*", "validation.*", "reporting.*",
    ]

    for prefix in prefixes:
        def make_handler(p=prefix):
            async def handler(data: Dict[str, Any]):
                event_name = data.get("_event", p)
                level, message = format_event(event_name, data)
                # Map SUCCESS → INFO for conductor (SUCCESS is a LogPanel level, not standard)
                log_level = "INFO" if level == "SUCCESS" else level
                conductor.notify_log(log_level, message)
            handler.__name__ = f"ui_bridge_{p.replace('*', 'all').replace('.', '_')}"
            return handler
        event_bus.subscribe_pattern(prefix, make_handler())


# ---------------------------------------------------------------------------
# Event catalog — all 148 verbose event types by category.
# This is documentation only; events are dynamically routed via pattern bridge.
# ---------------------------------------------------------------------------
VERBOSE_EVENT_CATALOG = {
    "pipeline": [
        "pipeline.initializing",
        "pipeline.phase_transition",
        "pipeline.checkpoint",
        "pipeline.paused",
        "pipeline.resumed",
        "pipeline.error",
        "pipeline.heartbeat",
        "pipeline.completed",
    ],
    "recon": [
        "recon.started", "recon.completed",
        "recon.gospider.started", "recon.gospider.url_found", "recon.gospider.completed",
        "recon.nuclei.started", "recon.nuclei.match", "recon.nuclei.completed",
        "recon.auth.started", "recon.auth.scanning_url", "recon.auth.jwt_found",
        "recon.auth.cookie_found", "recon.auth.completed",
        "recon.assets.started", "recon.assets.dns_found", "recon.assets.ct_results",
        "recon.assets.wayback_results", "recon.assets.cloud_found",
        "recon.assets.sensitive_path", "recon.assets.completed",
        "recon.visual.started", "recon.visual.completed",
    ],
    "discovery": [
        "discovery.started", "discovery.completed",
        "discovery.url.started", "discovery.url.html_captured",
        "discovery.url.frameworks_detected", "discovery.url.params_found",
        "discovery.url.jwt_detected",
        "discovery.probe.started", "discovery.probe.result",
        "discovery.probe.header_reflection", "discovery.probe.completed",
        "discovery.sqli_probe.started", "discovery.sqli_probe.result",
        "discovery.sqli_probe.completed",
        "discovery.cookie_sqli.started", "discovery.cookie_sqli.result",
        "discovery.cookie_sqli.completed",
        "discovery.llm.started", "discovery.llm.completed",
        "discovery.skeptical.started", "discovery.skeptical.verdict",
        "discovery.consolidation.started", "discovery.consolidation.voting",
        "discovery.consolidation.fp_filtered", "discovery.consolidation.completed",
        "discovery.url.completed",
        "discovery.retry.started", "discovery.retry.url",
    ],
    "strategy": [
        "strategy.started", "strategy.completed",
        "strategy.thinking.batch_started", "strategy.thinking.batch_completed",
        "strategy.finding.received", "strategy.finding.fp_filtered",
        "strategy.finding.duplicate", "strategy.finding.classified",
        "strategy.finding.queued", "strategy.finding.backpressure",
        "strategy.embeddings.result",
        "strategy.distribution_summary",
        "strategy.auto_dispatch", "strategy.nuclei_injected",
    ],
    "exploit_xss": [
        "exploit.xss.started", "exploit.xss.completed",
        "exploit.xss.waf_detected",
        "exploit.xss.param.started", "exploit.xss.param.completed",
        "exploit.xss.probe.result", "exploit.xss.llm_payloads",
        "exploit.xss.level.started", "exploit.xss.level.progress",
        "exploit.xss.level.completed",
        "exploit.xss.go_fuzzer.started", "exploit.xss.go_fuzzer.completed",
        "exploit.xss.manipulator.phase",
        "exploit.xss.browser.testing", "exploit.xss.browser.result",
        "exploit.xss.interactsh.callback",
        "exploit.xss.confirmed",
        "exploit.xss.dom.started", "exploit.xss.dom.result",
    ],
    "exploit_sqli": [
        "exploit.sqli.started", "exploit.sqli.completed",
        "exploit.sqli.param.started",
        "exploit.sqli.baseline", "exploit.sqli.filters_detected",
        "exploit.sqli.level.started", "exploit.sqli.level.progress",
        "exploit.sqli.level.completed",
        "exploit.sqli.error_found", "exploit.sqli.boolean_diff",
        "exploit.sqli.union_found",
        "exploit.sqli.oob.sent", "exploit.sqli.oob.callback",
        "exploit.sqli.time_delay",
        "exploit.sqli.sqlmap.started", "exploit.sqli.sqlmap.completed",
        "exploit.sqli.confirmed",
        "exploit.sqli.json_testing",
    ],
    "exploit_generic": [
        "exploit.specialist.started", "exploit.specialist.completed",
        "exploit.specialist.param.started", "exploit.specialist.param.completed",
        "exploit.specialist.go_fuzzer", "exploit.specialist.progress",
        "exploit.specialist.signature_match", "exploit.specialist.confirmed",
    ],
    "exploit_phase": [
        "exploit.specialist.activated", "exploit.specialist.queue_progress",
        "exploit.specialist.deactivated", "exploit.phase_stats",
    ],
    "validation": [
        "validation.started", "validation.completed",
        "validation.finding.received", "validation.finding.dedup_skipped",
        "validation.finding.queued", "validation.finding.started",
        "validation.payload_loaded",
        "validation.cache.hit", "validation.cache.miss",
        "validation.static.result",
        "validation.browser.launching", "validation.browser.navigating",
        "validation.browser.loaded",
        "validation.cdp.monitoring", "validation.cdp.event",
        "validation.cdp.confirmed", "validation.cdp.silent",
        "validation.vision.started", "validation.vision.result",
        "validation.finding.confirmed", "validation.finding.rejected",
    ],
    "reporting": [
        "reporting.started", "reporting.completed",
        "reporting.file_generated",
        "reporting.scan_summary",
        "reporting.engagement_data",
        "reporting.error",
    ],
}
