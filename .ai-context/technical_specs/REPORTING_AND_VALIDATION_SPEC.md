# BugtraceAI V5: Reporting & Validation Specifications (Triager-Ready)

## 1. The Core Philosophy: "Triager-Ready"

The ultimate goal of BugtraceAI is not just to find bugs, but to get them **accepted** by Bug Bounty programs or Client Security Teams.

Reports must be designed for a human "Triager" who has < 30 seconds to validate the issue.

---

## 2. Validation Architecture (The "Lead Pentester" Role)

The `AgenticValidator` acts as the **QA Lead**. It is partially decoupled from the scanning agents.

### 2.1. Separation of Concerns

- **Red Team (Agents)**: Propose findings. They are biased towards reporting everything.
- **QA Team (Validator)**: Verify findings. They are biased towards rejecting false positives.

### 2.2. Smart Validation Logic

The system now chooses the most efficient validation method based on vulnerability type:

| Vulnerability Type | Validation Method | Cost/Time |
| :--- | :--- | :--- |
| **XSS (DOM/Reflected)** | **Browser (CDP/Playwright)** | High |
| **Defacement / UI Spoofing** | **Vision AI (Gemini)** | High |
| **SQLi (Error-Based)** | **Vision AI** (Verify Error Dump) | Medium |
| **Blind XSS / Blind SQLi** | **Automated Request (Skip Vision)** | Low |
| **Headers / SSL / Info** | **Automated Request (Skip Vision)** | Low |

---

## 3. The "Triager-Ready" Report Format

Every finding in the final Markdown report now includes specific sections to ensure reproducibility.

### 3.1. Structure

```markdown
### 2.1. Reflected Cross-Site Scripting (XSS)

| Classification | Detail |
| :--- | :--- |
| Severity | High |
| Confidence | Certain |
| Validation | Browser Verification (CDP/Playwright) |

#### 🕵️ Steps to Reproduce (Triager Ready)
1. Open the target URL: `http://example.com/v1?q=test`
2. Locate the input parameter `q`.
3. Inject the following payload: `<script>alert(1)</script>`
4. Observe the execution of the payload (alert box).

#### 💥 Proof of Concept (Curl)
```bash
curl "http://example.com/v1?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

#### Issue Background

...

```

### 3.2. Automatic Artifact Generation
- **Steps to Reproduce**: Generated heuristically based on finding type (XSS vs SQLi vs General).
- **PoC Command**: Automatically constructs a valid `curl` command (handling GET/POST and encoding).
- **Visual Proof**: Embeds the screenshot captured by the validator.
- **AI Commentary**: "AI Validator Comment: Confirmed alert box visible."

---

## 4. Future Roadmap (V6+)
- **Interactive Re-Testing**: The Validator should be able to ask agents to "try again" with different parameters if verification is ambiguous.
- **Exploit Chain Visualization**: Graph of how XSS led to Auth Bypass.
