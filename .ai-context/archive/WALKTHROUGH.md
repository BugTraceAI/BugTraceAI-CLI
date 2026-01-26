# BugtraceAI-CLI: The "Best in Class" Autonomous Pentesting Team

## 1. System Overview
**BugtraceAI-CLI** is a next-generation offensive security framework. Unlike legacy tools that run linear scripts, BugtraceAI deploys an **Autonomous Swarm** of agents that collaborate in real-time.

### The Team
1.  **ReconAgent (The Scout)** 🕵️
    *   **Visual Intelligence**: Uses `Playwright` to "see" the target, identifying interactive elements (Inputs, Buttons) that text-based scanners miss.
    *   **External Integration**: Orchestrates industrial tools like `Nuclei` and `GoSpider` (via Docker) to map the attack surface.
2.  **ExploitAgent (The Hacker)** ⚔️
    *   **Context-Aware**: Monitors the **Knowledge Graph** (GraphRAG) for new opportunities.
    *   **Adaptive**: Uses a `MutationEngine` (LLM-driven) to rewrite payloads if WAFs are detected.
    *   **Active Arsenal**: Launches `SQLMap` and custom XSS payloads asynchronously.
3.  **TeamOrchestrator (The Boss)** 🧠
    *   Manages resource allocation, state persistence, and the master **Knowledge Graph**.

---

## 2. Installation & Usage

### Option A: Docker (Recommended)
The system is fully containerized for one-click deployment.

```bash
# Build the image
docker build -t bugtrace .

# Run the Team against a target
docker run -it bugtrace --target https://ginandjuice.shop/
```

### Option B: Local Python
Requires Python 3.10+ and Playwright dependencies.

```bash
# Install dependencies
pip install -r requirements.txt
playwright install chromium

# Launch the CLI
python -m bugtrace --target https://ginandjuice.shop/ --resume
```

---

## 3. Key Capabilities "Under the Hood"

### 🧠 GraphRAG Memory
We don't just dump logs. We build a graph:
`[URL: /login] --(HAS_INPUT)--> [Input: username] --(VULNERABLE_TO)--> [Exploit: SQLi]`
This allows agents to chain attacks intelligently.

### 👁️ Visual Adversarial Validation
The agent uses **Vision (VLM)** to verify exploits. It doesn't trust HTTP 200 OK; it looks for the popped alert box or the admin dashboard title.

### 🛡️ Mutation Engine
Hard-coded payloads are dead. Our engine re-writes attacks on the fly:
*   Standard: `<script>alert(1)</script>`
*   Mutated: `<svg/onload=alert(1)>` (if WAF blocks script tags)

---

## 4. Conclusion
We have successfully built a framework that provides industry-leading capabilities in memory persistence, visual verification, and production readiness.

**Welcome to the future of offensive security.**
