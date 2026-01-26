# Dojo Testing Infrastructure

**Date**: 2026-01-13
**Version**: 1.0
**Status**: ACTIVE

---

## 🎯 Overview

The **Dojo** is BugTraceAI's local testing environment - a collection of intentionally vulnerable web applications used to validate agent capabilities, measure detection rates, and ensure consistency across versions.

**Key Files**:

- `dojo_comprehensive.py` - **Dojo V4 (Ultimate)** - All-in-One Testing (Port 5090)
- `dojo_v3.py` - Legacy multi-vuln server (Port 5070)
- `lab/server.py` - File upload testing lab (Port 5006)

---

## 🏗️ Current Dojo Architecture

### **Dojo Comprehensive (dojo_comprehensive.py) - The Ultimate Gauntlet (V4)**

The new standard for V4 Reactor testing. Runs on `http://127.0.0.1:5090`.

**Capabilities**:

- **XSS**: Levels 0-8 (Reflected, stored, DOM, WAF bypass, Polyglots, Context-aware).
- **SQLi**: Levels 0-8 (Error, Union, Blind, Time-based, Second-order, WAF).
- **SSRF**: Levels 0-2 (Basic, Protocol smuggling, Cloud metadata).
- **XXE**: Levels 0-2 (Basic entity, Parameter entity, OOB).
- **IDOR**: Levels 0-2 (Numeric, UUID, Parameter pollution).
- **JWT**: Levels 0-4 (None alg, Weak key, Key confusion, Header injection).
- **FileUpload**: Levels 0-2 (Extension bypass, Content-Type, Magic Bytes).
- **CSTI**: Levels 0-2 (Angular, Vue, React template injection).

### **Dojo v3 (dojo_v3.py) - Legacy**

Multi-vulnerability testing environment running on `http://127.0.0.1:5070`

#### **Endpoints**

| Endpoint | Vulnerability Type | Difficulty | Notes |
|----------|-------------------|------------|-------|
| `/search?q=` | Reflected XSS | Medium | Blocks `<script>` tags but allows SVG/iframe |
| `/login?user=` | SQL Injection | Easy | Error-based SQLi with flag extraction |
| `/dashboard#user=` | DOM XSS | Medium | Client-side injection via URL hash |
| `/upload` | File Upload | Hard | Blocks `.php` but allows `.PhP`, `.phtml` |

#### **Built-in WAF Simulation**

```python
# Mimics real-world filtering
clean_q = re.sub(r'(?i)<script.*?>.*?</script>', '[BLOCKED]', q)
```

#### **Expected Findings**

1. **XSS in /search**: `"><svg/onload=alert(1)>` or `"><iframe src=javascript:alert(1)>`
2. **SQLi in /login**: `' OR '1'='1` → `FLAG{SQLI_MASTER}`
3. **DOM XSS in /dashboard**: `#user=<img src=x onerror=alert(1)>`
4. **File Upload Bypass**: Upload `.PhP` or `.phtml` webshell

---

### **Lab Server (lab/server.py) - File Upload Testing**

Specialized unrestricted file upload server on `http://127.0.0.1:5006`

**Purpose**: Test file upload exploitation and webshell detection

**Endpoints**:

- `GET /` - Upload form
- `POST /` - File upload handler (NO restrictions)
- `GET /uploads/{filename}` - Serve uploaded files

**Attack Scenarios**:

1. PHP webshell upload
2. SVG-based XSS (via file upload)
3. XXE via XML file upload
4. Path traversal in filename (`../../etc/passwd`)

---

## 📊 Testing Methodology

### **Test Categories**

#### **Category 1: Detection Rate Testing**

**Goal**: Ensure BugTraceAI finds vulnerabilities consistently

**Process**:

1. Run agent against known vulnerable endpoint
2. Verify finding is reported
3. Check for false negatives (missed vulns)

**Success Criteria**: 100% detection on all dojo endpoints

#### **Category 2: False Positive Testing**

**Goal**: Ensure clean endpoints don't trigger false alarms

**Process**:

1. Add safe endpoints to dojo (e.g., `/safe?q=test` with proper escaping)
2. Run agent and verify NO findings
3. Track false positive rate

**Success Criteria**: 0% false positives

#### **Category 3: WAF Bypass Testing**

**Goal**: Validate mutation engine and bypass capabilities

**Process**:

1. Enable WAF simulation in dojo
2. Test if agent can generate bypass payloads
3. Measure success rate vs different filters

**Success Criteria**: >80% bypass rate on common filters

#### **Category 4: Validation Accuracy**

**Goal**: Ensure triple validation (Interactsh + Vision + CDP) works

**Process**:

1. Run agent with all validation methods enabled
2. Check which validation layer confirms each vuln
3. Verify no contradictions between methods

**Success Criteria**: 100% validation agreement

#### **Category 5: Regression Testing**

**Goal**: Ensure new features don't break existing detection

**Process**:

1. Run full dojo suite before code changes
2. Document baseline results
3. Run again after changes and compare

**Success Criteria**: No degradation in detection rate

---

## 🚀 Enhancement Plan: Dojo v4

### **Current Limitations**

1. Only 4 vulnerability types (XSS, SQLi, DOM XSS, File Upload)
2. No API testing (GraphQL, REST, JWT)
3. No chained exploitation scenarios
4. No authentication bypass testing
5. No SSRF/XXE/CSTI endpoints
6. No rate limiting simulation
7. Manual test execution

### **Proposed Enhancements**

#### **Phase 1: Expand Vulnerability Coverage** (2 days)

Add new endpoints to `dojo_v3.py`:

```python
# CSTI / SSTI
'/template?name=' → Template injection (Jinja2 simulation)

# XXE
'/xml/parse' → XML parser with external entity support

# SSRF
'/proxy?url=' → Internal URL fetcher (allows 127.0.0.1)

# IDOR
'/user/profile?id=' → User data access (predictable IDs)

# Open Redirect
'/redirect?url=' → Unvalidated redirect

# CSRF
'/transfer?amount=&to=' → State-changing operation without token

# JWT Vulnerabilities
'/api/auth' → JWT with "none" algorithm support
'/api/data' → JWT verification bypass (RS256→HS256)

# GraphQL
'/graphql' → Introspection enabled, injection points

# Command Injection
'/ping?host=' → OS command execution (filtered but bypassable)

# LFI/Path Traversal
'/download?file=' → File read with path traversal
```

**Implementation**:

```python
# New dojo_v4.py structure
class VulnDojo:
    def __init__(self):
        self.vulnerabilities = {
            'xss': XSSModule(),
            'sqli': SQLiModule(),
            'ssrf': SSRFModule(),
            'xxe': XXEModule(),
            'csti': CSTIModule(),
            'jwt': JWTModule(),
            'graphql': GraphQLModule(),
            'idor': IDORModule(),
            'redirect': RedirectModule(),
            'csrf': CSRFModule(),
            'cmdi': CommandInjectionModule(),
            'lfi': LFIModule(),
        }
```

#### **Phase 2: Add Chained Exploitation** (3 days)

**Scenario 1: SQLi → Auth Bypass → Privilege Escalation**

```
1. /login?user=' OR '1'='1 (SQLi)
2. Bypass auth, get admin cookie
3. /admin/users?id=1 (IDOR to other users)
4. /admin/config (Sensitive config access)
```

**Scenario 2: SSRF → Cloud Metadata → AWS Key Theft**

```
1. /proxy?url=http://169.254.169.254/latest/meta-data/
2. Extract IAM role credentials
3. Use credentials to access S3 bucket simulation
```

**Scenario 3: File Upload → XSS → Cookie Theft**

```
1. Upload malicious.svg with embedded XSS
2. Trigger XSS via /uploads/malicious.svg
3. Steal admin session cookie
4. Access /admin panel
```

**Implementation**:

```python
class ChainedScenario:
    def __init__(self, name, steps):
        self.name = name
        self.steps = steps  # List of vulnerability exploits
        self.current_step = 0

    def verify_chain(self, agent_findings):
        """Check if agent discovered the full chain"""
        for i, step in enumerate(self.steps):
            if not self._step_completed(step, agent_findings):
                return False, f"Chain broken at step {i+1}"
        return True, "Full chain exploited"
```

#### **Phase 3: Automated Test Suite** (2 days)

**Create `dojo_test_suite.py`**:

```python
#!/usr/bin/env python3
"""
Dojo Automated Test Suite
Runs BugTraceAI against all dojo challenges and generates report
"""

import asyncio
import json
from datetime import datetime
from bugtrace.core.team import TeamOrchestrator

class DojoTestSuite:
    def __init__(self):
        self.results = {
            'run_date': datetime.now().isoformat(),
            'version': '1.0',
            'tests': []
        }

    async def run_all_tests(self):
        """Execute full test suite"""
        # Start dojo server
        dojo_proc = await self.start_dojo()

        # Define test cases
        test_cases = [
            {
                'name': 'XSS_Reflected_Search',
                'url': 'http://127.0.0.1:5070/search?q=test',
                'expected_vuln': 'XSS',
                'expected_payload': '"><svg/onload=alert(1)>',
                'difficulty': 'Medium',
            },
            {
                'name': 'SQLi_Login_Bypass',
                'url': 'http://127.0.0.1:5070/login?user=test',
                'expected_vuln': 'SQLi',
                'expected_payload': "' OR '1'='1",
                'difficulty': 'Easy',
            },
            {
                'name': 'DOM_XSS_Dashboard',
                'url': 'http://127.0.0.1:5070/dashboard',
                'expected_vuln': 'DOM XSS',
                'expected_payload': '#user=<img src=x onerror=alert(1)>',
                'difficulty': 'Medium',
            },
            # ... more test cases
        ]

        # Run each test
        for test_case in test_cases:
            result = await self.run_test(test_case)
            self.results['tests'].append(result)

        # Stop dojo
        dojo_proc.terminate()

        # Generate report
        self.generate_report()

    async def run_test(self, test_case):
        """Run single test case"""
        print(f"[TEST] Running: {test_case['name']}")

        # Create agent instance
        orchestrator = TeamOrchestrator(target=test_case['url'])

        # Run scan
        start_time = datetime.now()
        findings = await orchestrator.run()
        duration = (datetime.now() - start_time).total_seconds()

        # Analyze results
        detected = self.check_detection(findings, test_case)

        return {
            'test_name': test_case['name'],
            'url': test_case['url'],
            'expected': test_case['expected_vuln'],
            'detected': detected['found'],
            'payload_used': detected.get('payload', None),
            'duration_seconds': duration,
            'status': 'PASS' if detected['found'] else 'FAIL',
            'difficulty': test_case['difficulty'],
        }

    def check_detection(self, findings, test_case):
        """Check if expected vulnerability was found"""
        for finding in findings:
            if test_case['expected_vuln'].lower() in finding['type'].lower():
                return {'found': True, 'payload': finding.get('payload')}
        return {'found': False}

    def generate_report(self):
        """Generate comprehensive test report"""
        total_tests = len(self.results['tests'])
        passed = sum(1 for t in self.results['tests'] if t['status'] == 'PASS')
        failed = total_tests - passed

        report = f"""
╔══════════════════════════════════════════════════════════╗
║           BUGTRACE AI - DOJO TEST REPORT                 ║
╚══════════════════════════════════════════════════════════╝

Run Date: {self.results['run_date']}

SUMMARY
───────────────────────────────────────────────────────────
Total Tests:      {total_tests}
Passed:           {passed} ({passed/total_tests*100:.1f}%)
Failed:           {failed} ({failed/total_tests*100:.1f}%)
Success Rate:     {'✅ EXCELLENT' if passed/total_tests >= 0.95 else '⚠️ NEEDS WORK'}

DETAILED RESULTS
───────────────────────────────────────────────────────────
"""
        for test in self.results['tests']:
            status_icon = '✅' if test['status'] == 'PASS' else '❌'
            report += f"""
{status_icon} {test['test_name']}
   Expected:  {test['expected']}
   Detected:  {test['detected']}
   Payload:   {test.get('payload_used', 'N/A')}
   Duration:  {test['duration_seconds']:.2f}s
   Difficulty: {test['difficulty']}
"""

        # Save to file
        with open('dojo_test_results.txt', 'w') as f:
            f.write(report)

        # Also save JSON
        with open('dojo_test_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)

        print(report)

if __name__ == '__main__':
    suite = DojoTestSuite()
    asyncio.run(suite.run_all_tests())
```

#### **Phase 4: CI/CD Integration** (1 day)

**Create `.github/workflows/dojo-tests.yml`**:

```yaml
name: Dojo Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  dojo-tests:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'

    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        playwright install chromium

    - name: Run Dojo Test Suite
      env:
        OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
      run: python dojo_test_suite.py

    - name: Upload Test Results
      uses: actions/upload-artifact@v3
      with:
        name: dojo-test-results
        path: |
          dojo_test_results.txt
          dojo_test_results.json

    - name: Check Success Rate
      run: |
        SUCCESS_RATE=$(jq '.tests | map(select(.status == "PASS")) | length' dojo_test_results.json)
        TOTAL=$(jq '.tests | length' dojo_test_results.json)
        PERCENTAGE=$((SUCCESS_RATE * 100 / TOTAL))
        echo "Success Rate: $PERCENTAGE%"
        if [ $PERCENTAGE -lt 95 ]; then
          echo "❌ Test suite failed: Success rate below 95%"
          exit 1
        fi
```

---

## 📈 Benchmarking Strategy

### **Baseline Metrics** (Record current performance)

| Metric | Current | Target | Competitor (Shannon) |
|--------|---------|--------|---------------------|
| XSS Detection Rate | ??% | 100% | 96.15% |
| SQLi Detection Rate | ??% | 100% | N/A |
| False Positive Rate | ??% | <1% | Unknown |
| Avg Time per Vuln | ??s | <30s | ~90s |
| Cost per Scan | $0.10 | $0.10 | $50.00 |

### **Testing Protocol**

1. **Run dojo suite 10 times** to establish baseline
2. **Record all metrics** (detection rate, time, cost, false positives)
3. **Make code changes** (new features, optimizations)
4. **Re-run dojo suite** and compare results
5. **Accept changes** only if metrics improve or stay same

---

## 🎯 Success Criteria

### **Phase 1 Complete**

- [ ] 12+ vulnerability types in dojo
- [ ] 100% detection rate on all known vulns
- [ ] <1% false positive rate

### **Phase 2 Complete**

- [ ] 3+ chained exploitation scenarios
- [ ] Agent discovers full chains automatically
- [ ] Chain detection in <5 minutes

### **Phase 3 Complete**

- [ ] Automated test suite runs in <10 minutes
- [ ] Comprehensive JSON/text reports generated
- [ ] Regression testing working

### **Phase 4 Complete**

- [ ] CI/CD pipeline runs tests on every commit
- [ ] PRs blocked if tests fail (<95% success rate)
- [ ] Automated performance tracking

---

## 🔧 Running the Dojo

### **Quick Start**

```bash
# Terminal 1: Start Dojo v3
python3 dojo_v3.py
# Server: http://127.0.0.1:5070

# Terminal 2: Start Lab
cd lab && python3 server.py
# Server: http://127.0.0.1:5006

# Terminal 3: Run BugTraceAI
./bugtraceai-cli http://127.0.0.1:5070 --verbose
```

### **Automated Testing**

```bash
# Run single test
./run_xss_dojo.sh

# Run full suite (Phase 3)
python3 dojo_test_suite.py

# Run with CI (Phase 4)
git push  # Triggers GitHub Actions
```

---

## 📚 Additional Resources

**External Test Environments**:

- DVWA (Damn Vulnerable Web App)
- OWASP Juice Shop
- WebGoat
- HackTheBox Labs
- PortSwigger Web Security Academy

**Integration Plan**:

```bash
# Add external targets to test suite
EXTERNAL_TARGETS=(
    "http://localhost:8080"  # DVWA
    "http://localhost:3000"  # Juice Shop
)
```

---

## 🚀 Next Steps

1. **Immediate**: Document current dojo detection rates
2. **Week 1**: Implement Dojo v4 with 12+ vulnerability types
3. **Week 2**: Add chained exploitation scenarios
4. **Week 3**: Build automated test suite
5. **Week 4**: Integrate with CI/CD pipeline

---

**Maintainer**: Development Team
**Last Updated**: 2026-01-13
**Status**: Active Development
