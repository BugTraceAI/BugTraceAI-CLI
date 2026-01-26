# BugtraceAI-CLI: The "Best in Class" Autonomous Pentesting Team

## 1. System Overview (v1.6.0)
**BugtraceAI-CLI** is a next-generation offensive security framework. Unlike legacy tools that run linear scripts, BugtraceAI deploys an **Autonomous Swarm** of agents that collaborate in real-time.

### The Team (v1.6 Advanced Edition)
1.  **URLMasterAgent (The Vertical Specialist)** 🕷️
    *   **Full Lifecycle Ownership**: One agent per URL manages everything from recon to final exploitation.
    *   **Integrated Arsenal**: 20+ specialized skills including SSRF, IDOR, and OOB Detection.
2.  **Conductor V2 (The Orchestrator)** 🧠
    *   **Context Sharing**: Global bus that allows agents to share metadata and findings in real-time.
    *   **Anti-Hallucination**: Validates LLM predictions before tool execution.
3.  **MemoryManager (The Brain)** 💾
    *   **GraphRAG Persistence**: Stores every finding and discovered relationship in a persistent SQLite + LanceDB graph.
    *   **Semantic Deduplication**: Prevents redundant testing by checking for similar previous findings.

---

## 2. Advanced v1.6 Capabilities

### 📡 Out-of-Band (OOB) Detection (Interactsh)
Leverage external callback servers (Interactsh) to detect "blind" vulnerabilities like XSS and SSRF that don't return immediate HTTP reflections.

### 📊 Performance Tracing (OpenTelemetry)
Full observability into LLM costs, tool execution times, and scan efficiency using an integrated OpenTelemetry-based tracing engine.

### 🛡️ Mutation Engine (WAF Bypass)
Payloads are mutated by AI on-the-fly to bypass Web Application Firewalls. If one payload fails, the system learns and tries a mutated version (e.g., `<svg/onload=alert(1)>` vs `<script>`).

---

## 3. Usage & Command Line

```bash
# Launch a vertical scan with v1.6 features
./bugtraceai-cli "https://example.com/api/v1" --exhaustive-mode

# Key Arguments:
# --exhaustive-mode: Auto-tests SQLi, XSS, and LFI on all parameters.
# --max-urls: Cap the scope of discovery.
# --resume: Load previous session state from SQLite.
```

---

## 4. Key Metrics
- **Consensus Voting**: Multi-model analysis ensures High-Confidence findings.
- **Smart Deduplication**: Mapping vulnerability types (e.g., `sqli`) across tools (`sqlmap`, `URLMaster`) saves ~50% in LLM tokens.
- **Visual Validation**: Integrating Vision models to provide PoC proof of attack success.

---

**Welcome to the future of offensive security.**
**BugtraceAI-CLI v1.6.0 - Advanced Context Edition**
