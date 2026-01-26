# BugtraceAI-CLI: Phoenix Edition Architecture

## Agentic Bug Bounty Framework | Version: 2.0.0 (Phoenix Edition)

---

## ⚠️ CORE PRINCIPLE: CONSISTENCY IS NON-NEGOTIABLE

BugtraceAI-CLI is an **Agentic Bug Bounty Framework**. Unlike traditional scanners, it uses AI to make intelligent decisions. However, the **most critical requirement** is:

> **Results MUST be consistent and reproducible across scans.**

A vulnerability that exists should be found EVERY time the tool is run against the same target. Inconsistent results undermine trust and make the framework useless for professional bug bounty work.

### Consistency Guarantees

1. **Deterministic Discovery**: GoSpider + VisualCrawler use fixed configurations.
2. **Exhaustive Mode**: When enabled, all parameters are tested regardless of AI analysis.
3. **Validated Findings Only**: Only vulnerabilities confirmed by Conductor V2 + Browser/Vision are reported.
4. **No Random Sampling**: Every discovered endpoint is processed.

---

## 🚀 NEW: PROMPT EXTERNALIZATION (v1.7.2)

To ensure consistency and ease of maintenance, BugTraceAI-CLI v1.7.2 implements a **Fully Decoupled Prompt Architecture**:

1. **Markdown-Based Personas**: System prompts are no longer hardcoded. They reside in `bugtrace/agents/system_prompts/*.md`.
2. **BaseAgent Paradigm**: Every agent inherits from `BaseAgent`, which handles automatic prompt loading and YAML configuration parsing.
3. **XML-Like Interaction Protocol**: All LLM communications follow a strict XML-tag-based protocol to ensure reliable parsing regardless of model verbosity.

---

## 1. CORE PHILOSOPHY: THE VERTICAL SHIFT

BugtraceAI-CLI (Phoenix Edition) abandons the traditional horizontal pipeline (Recon -> Scan -> Exploit) in favor of a **Vertical Agent Architecture**.

### The "URL Master" Paradigm

Instead of passing data between agents, we spawn a dedicated **URLMasterAgent** for EACH unique URL found. This agent owns the complete lifecycle of that specific target:

1. **Analyze** it deeply (SAST/DAST).
2. **Decide** attack vectors based on context.
3. **Exploit** using specialized skills.
4. **Validate** findings with concrete proof.

---

## 2. HIGH-LEVEL WORKFLOW

### Phase 1: Global Reconnaissance (The Feeder)

**Executor**: `TeamOrchestrator` (`core/team.py`)
Before spawning agents, the orchestrator builds the attack surface.

1. **Session Priming**: `BrowserManager` visits the target to capture authentication cookies.
2. **Deep Discovery**: Execute `GoSpider` (Docker) injecting session cookies to map ALL endpoints.
3. **Fallback**: If GoSpider fails, `VisualCrawler` uses Playwright to render JS-heavy links.
4. **Deduplication**: Resulting URLs are filtered and prioritized.

### Phase 2: Vertical Execution (The Swarm)

**Executor**: `URLMasterAgent` (`agents/url_master.py`)
For every unique URL, a Master Agent is spawned (concurrency limited by semaphore).

#### The Master Loop

1. **Context Assembly**:
    * Extract params (`id=1`, `search=test`).
    * Identify Tech Stack (Headers, Wappalyzer logic).
2. **Intelligent Analysis (SAST/DAST)**:
    * Calls `AnalysisSkill` (wrapping `AnalysisAgent` logic).
    * **5-Approach Analysis** (for consistency): Pentester, Bug Bounty, Code Auditor, Red Team, and Security Researcher personas analyze the same URL.
    * **Consensus Voting**: Only vulnerabilities detected by 2+ approaches are considered high-confidence.
    * *Output*: "SQLi (5/5 votes, 0.78 confidence) on parameter 'id'".
    * 📚 **See**: [`dast_strategy.md`](./dast_strategy.md) for full details.
3. **Dynamic Routing**:
    * Based on analysis, the Master activates specific **Skills**.
    * *If SQLi detected*: -> **SQLiSkill** (Python Check -> SQLMap Docker).
    * *If XSS suspected*: -> **XSSSkill** (Invokes `ManipulatorOrchestrator`).
4. **Validation (The Proof)**:
    * **BrowserSkill**: If XSS succeeds, browser navigates to payload URL.
    * **Vision Check**: Captures screenshot. Visual LLM confirms alert box visibility.

### Phase 3: Global Review & Chaining

**Executor**: `TeamOrchestrator`
Analyzes findings from all agents to identify complex attack chains (e.g., IDOR + Info Leak).

### Phase 4: Reporting (The Deliverable)

**Executor**: `ReportingAgent` (`agents/reporting.py`)
Aggregates VALIDATED findings from all Masters.

1. **Enrichment**: AI adds Impact/Remediation/CWE context.
2. **Evidence Linking**: Embeds screenshots and raw HTTP logs.
3. **Reproduction Commands**: SQLi findings include the exact `sqlmap` command used.

---

## 3. VALIDATION SYSTEM (Conductor V2)

### Proof of Execution (PoE)

The system focuses on **Proof of Execution** rather than just reflection.

* **Primary**: Interactsh (OOB callback).
* **Secondary**: CDP Markers (DOM elements created by JS).
* **Tertiary**: Vision Model (visual confirmation of alerts).

---

## 4. COMPONENT MAP

| Component          | Responsibility                           |
| :----------------- | :--------------------------------------- |
| `BaseAgent`        | Base class for all agents (Prompt loader) |
| `ConductorV2`      | Anti-hallucination & Rule Enforcement     |
| `URLMasterAgent`   | Per-URL state and orchestration           |
| `ExploitAgent`     | Specialized exploitation logic            |
| `AnalysisAgent`    | Multi-approach vulnerability prediction   |
| `XmlParser`        | Robust extraction of structured LLM data  |

---

## 5. DIRECTORY STRUCTURE MAP

```text
bugtrace/
├── core/
│   ├── team.py            # V2 Sequential Pipeline Orchestrator
│   ├── conductor.py       # Anti-Hallucination Validation System
│   ├── llm_client.py      # AI Gateway (OpenRouter) with Model Shifting
│   ├── database.py        # SQLite + Vector Embeddings for findings
│   └── boot.py            # Startup Health Checks
├── agents/
│   ├── url_master.py      # Phase 2: The Core Vertical Agent (~770 lines)
│   ├── nuclei_agent.py    # Phase 1: Nuclei tech detection
│   ├── gospider_agent.py  # Phase 1: GoSpider URL discovery
│   ├── dast_agent.py      # Phase 2: 5-Approach DAST analysis
│   ├── xss_agent.py       # Specialist: XSS exploitation
│   ├── sqlmap_agent.py    # Specialist: SQLMap confirmation
│   ├── analysis.py        # Analysis logic (used as Skill)
│   └── reporting.py       # Phase 4: Final Report Gen
├── skills/                 # NEW: Modular skill classes (extracted from url_master.py)
│   ├── __init__.py        # SKILL_REGISTRY with 20 skills
│   ├── base.py            # BaseSkill foundation class
│   ├── recon.py           # ReconSkill, AnalyzeSkill
│   ├── injection.py       # XSSSkill, SQLiSkill, LFISkill, XXESkill, CSTISkill
│   ├── infrastructure.py  # HeaderInjectionSkill, PrototypePollutionSkill
│   ├── external_tools.py  # SQLMapSkill, NucleiSkill, GoSpiderSkill, MutationSkill
│   ├── advanced.py        # SSRFSkill, IDORSkill, OpenRedirectSkill, OOBXSSSkill, CSRFSkill
│   └── utility.py         # BrowserSkill, ReportSkill
├── tools/
│   ├── visual/
│   │   ├── browser.py     # Playwright Manager
│   │   └── crawler.py     # JS Crawler
│   ├── manipulator/       # Advanced Exploitation Engine
│   ├── interactsh.py      # OOB Detection (Blind XSS, SSRF)
│   └── external.py        # Docker Wrapper (GoSpider, SQLMap)
└── reporting/
    └── generator.py       # Jinja2 HTML Template Engine
```

## 6. CRITICAL DATA FLOW

1. **User Target** -> `TeamOrchestrator`
2. `GoSpider` -> **URL List**
3. **URL List** -> `URLMasterAgent` (Spawn Loop)
4. `URLMasterAgent` -> `AnalysisSkill` -> **Risk Profile**
5. **Risk Profile** -> `ExploitSkills` (SQLMap/Manipulator) -> **Raw Finding**
6. **Raw Finding** -> `Conductor Validation` -> `Browser Verification` -> **Validated Finding**
7. **Validated Finding** -> `MemoryManager` -> `ReportingAgent` -> **Final HTML**

---

## 7. CONFIGURATION FOR CONSISTENCY

To maximize result consistency, use these settings in `bugtraceaicli.conf`:

```ini
[scan]
EXHAUSTIVE_MODE = true      # Test ALL params, not just AI-suggested ones
MAX_DEPTH = 3               # Fixed crawl depth
MAX_URLS = 100              # Fixed URL limit

[validation]
MANDATORY_SQLMAP = true     # Always confirm SQLi with SQLMap
VISION_ENABLED = true       # Use Vision model for XSS confirmation
```

---

## 8. KNOWN LIMITATIONS

1. **AI Variability**: LLM responses can vary slightly between runs. Mitigated by using Conductor V2 deterministic validation.
2. **WAF Bypass**: Success depends on payload mutation creativity.
3. **JavaScript-Heavy Sites**: May require longer crawl times or manual seed URLs.

---

*Last Updated: 2026-01-12 | Phoenix Edition v1.7.2*
