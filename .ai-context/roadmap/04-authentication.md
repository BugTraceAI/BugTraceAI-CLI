# 2FA/TOTP Authentication - Feature Tasks

## Feature Overview
Add support for testing authenticated applications with 2FA/TOTP, session management, and OAuth2.

**Why**: Modern apps require auth to access functionality
**Competitor Gap**: Shannon (2FA/TOTP support)
**Phase**: 2 - Competitive Parity
**Duration**: 2 weeks
**Effort**: $15k

---

## 🔵 Core Features

### FEATURE-038: TOTP Generator Integration
**Complexity**: 🔵 MEDIUM (3 days)

```python
# Install: pip install pyotp
import pyotp

class TOTPAuthenticator:
    def __init__(self, secret):
        self.totp = pyotp.TOTP(secret)

    def get_code(self):
        return self.totp.now()  # Returns 6-digit code

# Config
authentication:
  type: totp
  totp_secret: JBSWY3DPEHPK3PXP
  login_url: https://example.com/login
  username: test@example.com
```

### FEATURE-039: Session Management
**Complexity**: 🔵 MEDIUM (3 days)

```python
class SessionManager:
    def __init__(self):
        self.sessions = {}  # domain -> session

    async def get_session(self, domain):
        if domain in self.sessions:
            if self.is_valid(self.sessions[domain]):
                return self.sessions[domain]

        # Create new session
        return await self.create_session(domain)

    def is_valid(self, session):
        # Check if session expired
        return session.expires_at > datetime.now()

    async def refresh(self, session):
        # Auto-refresh expired sessions
        pass
```

### FEATURE-040: OAuth2/OIDC Support
**Complexity**: 🟠 COMPLEX (5 days)

```python
from playwright.async_api import async_playwright

async def handle_oauth_login(url, provider="google"):
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()

        # Click "Sign in with Google"
        await page.goto(url)
        await page.click("text=Sign in with Google")

        # Handle Google OAuth flow
        await page.fill("input[type=email]", settings.OAUTH_EMAIL)
        await page.click("button:has-text('Next')")
        await page.fill("input[type=password]", settings.OAUTH_PASSWORD)
        await page.click("button:has-text('Sign in')")

        # Wait for redirect back
        await page.wait_for_url(f"{url}/*")

        # Extract cookies
        cookies = await page.context.cookies()
        return cookies
```

### FEATURE-041: Multi-Step Login Flows
**Complexity**: 🔵 MEDIUM (3 days)

```yaml
# auth_flow.yaml
steps:
  - action: navigate
    url: https://example.com/login

  - action: fill
    selector: input[name=username]
    value: ${USERNAME}

  - action: fill
    selector: input[name=password]
    value: ${PASSWORD}

  - action: click
    selector: button[type=submit]

  - action: wait
    selector: input[name=totp_code]

  - action: fill
    selector: input[name=totp_code]
    value: ${TOTP_CODE}

  - action: click
    selector: button:has-text('Verify')

  - action: wait_for_url
    pattern: /dashboard
```

### FEATURE-042: Cookie Persistence Across Agents
**Complexity**: 🟣 QUICK (2 days)

```python
class AgentCookieJar:
    def __init__(self):
        self.cookies = {}  # Shared across all agents

    def set_cookies(self, domain, cookies):
        self.cookies[domain] = cookies

    def get_cookies(self, domain):
        return self.cookies.get(domain, {})

# Usage in agents
async def xss_agent_scan(url):
    cookies = cookie_jar.get_cookies(domain)
    response = await client.get(url, cookies=cookies)
```

### FEATURE-043: SAML/ADFS Support
**Complexity**: 🟠 COMPLEX (1 week)

```python
# Handle SAML redirects
async def handle_saml_login(url):
    # Follow SAML redirect chain
    # POST assertion to IdP
    # Handle SAML response
    pass
```

---

## 🟢 Advanced Features

### FEATURE-044: Session Replay
**Complexity**: 🔵 MEDIUM (2 days)

```python
# Save session for replay
class SessionRecorder:
    def record_login(self, steps):
        self.session_file.write(json.dumps({
            "domain": domain,
            "steps": steps,
            "cookies": cookies,
            "timestamp": datetime.now().isoformat()
        }))

    def replay(self, session_file):
        # Replay saved session
        session = json.load(session_file)
        return self.execute_steps(session["steps"])
```

### FEATURE-045: Credential Vault Integration
**Complexity**: 🔵 MEDIUM (3 days)

```python
# Integrate with 1Password, LastPass, etc.
from onepasswordconnectsdk.client import Client

client = Client(
    url=settings.ONEPASSWORD_CONNECT_URL,
    token=settings.ONEPASSWORD_TOKEN
)

credentials = client.get_item(vault_id, item_id)
```

### FEATURE-046: Captcha Bypass (2Captcha)
**Complexity**: 🔵 MEDIUM (3 days)

```python
from python_anticaptcha import AnticaptchaClient, NoCaptchaTaskProxylessTask

client = AnticaptchaClient(settings.ANTICAPTCHA_KEY)
task = NoCaptchaTaskProxylessTask(
    website_url=url,
    website_key=site_key
)
job = client.createTask(task)
job.join()
captcha_token = job.get_solution_response()
```

### FEATURE-047: Rate Limit Handling
**Complexity**: 🟣 QUICK (1 day)

```python
# Respect rate limits during auth
class RateLimitedAuth:
    def __init__(self):
        self.attempts = 0
        self.last_attempt = None

    async def attempt_login(self):
        if self.attempts >= 3:
            wait_time = 60  # Wait 60s after 3 failed attempts
            await asyncio.sleep(wait_time)
            self.attempts = 0

        try:
            await self.login()
            self.attempts = 0
        except:
            self.attempts += 1
            raise
```

### FEATURE-048: Headless Browser Stealth
**Complexity**: 🔵 MEDIUM (2 days)

```python
# Avoid bot detection
from playwright_stealth import stealth_async

async def create_stealth_browser():
    browser = await playwright.chromium.launch(
        args=[
            '--disable-blink-features=AutomationControlled',
            '--disable-web-security'
        ]
    )
    page = await browser.new_page()
    await stealth_async(page)
    return page
```

### FEATURE-049: MFA Backup Codes
**Complexity**: 🟣 QUICK (1 day)

```yaml
# Config with backup codes
authentication:
  type: totp
  totp_secret: JBSWY3DPEHPK3PXP
  backup_codes:
    - ABC123
    - DEF456
```

### FEATURE-050: JWT Token Refresh
**Complexity**: 🔵 MEDIUM (2 days)

```python
class JWTSessionManager:
    async def refresh_token(self, refresh_token):
        response = await self.client.post(
            f"{self.auth_url}/refresh",
            json={"refresh_token": refresh_token}
        )
        new_token = response.json()["access_token"]
        return new_token
```

---

## Summary

**Total Tasks**: 13
- 🟣 Quick: 3 (4 days)
- 🔵 Medium: 8 (20 days)
- 🟠 Complex: 2 (12 days)

**Estimated Effort**: 2 weeks
**Investment**: ~$15k

**Competitive Gap Closed**: Shannon (2FA/TOTP, authenticated testing)

**Config Example**:
```yaml
# bugtraceai-cli.conf
[AUTHENTICATION]
TYPE=totp
LOGIN_URL=https://example.com/login
USERNAME=test@example.com
PASSWORD_ENV_VAR=TEST_PASSWORD
TOTP_SECRET=JBSWY3DPEHPK3PXP
SESSION_TIMEOUT=3600
AUTO_REFRESH=true
```
