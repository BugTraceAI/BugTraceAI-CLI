# Content Spoofing vs. XSS Policy

**Version**: 1.0
**Date**: 2026-01-13
**Author**: BugTraceAI Team

## 🎯 Strategic Shift: Pentesting vs. Bug Bounty

BugTraceAI is evolving from a pure "Bug Bounty Hunter" (which cares only about High/Critical impact) to a **Comprehensive Pentesting Framework**. This means reporting defects that may not have direct technical impact (RCE, XSS) but pose significant **Business/Social Engineering risks**.

---

## 🔍 The Scenario: Reflected Input without Execution

When scanning a target (e.g., `race.es`), we often encounter:

1. **Reflection**: User input is reflected in the HTTP response body.
    * Input: `?search=<script>...`
    * Output: `You searched for: &lt;script&gt;...`
2. **Sanitization**: The application correctly HTML-encodes special characters.
    * Rendered HTML: `&lt;script&gt;...`
    * Browser: Displays the text `<script>` but **does NOT execute it**.

### Old Behavior (Bug Bounty Mode)

* **Verdict**: False Positive.
* **Action**: Discard finding.
* **Result**: 0 Findings in report.

### New Behavior (Pentesting Mode)

* **Verdict**: **Content Spoofing / Text Injection**.
* **Severity**: **Info / Low**.
* **Action**: Report as a valid finding.
* **Rationale**: Facilitates highly credible Phishing / Social Engineering attacks.

---

## 🛡️ Rationale for Reporting

Why report something that "isn't a bug"?

1. **Trust Exploitation**: Users trust the domain (e.g., `race.es`).
2. **Phishing Vector**: An attacker can construct a URL that displays a message like:
    > "Your session has expired. Please call 900-123-456 immediately."
3. **Client Value**: Corporate clients need to know about "Quality Defects" that affect their brand reputation, even if they aren't technical vulnerabilities.

---

## 📝 Implementation Architecture

### 1. Detection Logic (XSSAgent)

The agent must verify two states:
* **State A (Reflection)**: Is the probe string present in the response? -> **YES**
* **State B (Execution)**: Did the Javascript execute (Interactsh/Alert)? -> **NO**

**Decision Matrix**:

| Reflection | Execution | Verdict | Severity |
| :--- | :--- | :--- | :--- |
| ✅ Yes | ✅ Yes | **Reflected XSS** | 🔴 High/Critical |
| ✅ Yes | ❌ No | **Content Spoofing** | 🔵 Info/Low |
| ❌ No | ❌ No | Safe | N/A |

### 2. Reporting Output

The final report must clearly distinguish:
* **Title**: "Content Spoofing (Reflected Input)"
* **Description**: "The application reflects user input without sufficient context validation. While XSS protection is active (HTML Encoding), this behavior can be leveraged for Social Engineering attacks."
* **Remediation**: "Ensure user input is not reflected unless necessary, or use a generic message like 'Invalid Input'."

---

## ✅ Success Criteria

* [ ] `XSSAgent` identifies sanitized reflection.
* [ ] Finding is stored in DB with type `CONTENT_SPOOFING` (or similar).
* [ ] Report generation includes these findings in the "Informational" section.
* [ ] No longer treated as "Failed XSS".
