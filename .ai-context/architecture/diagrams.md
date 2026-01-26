# BugtraceAI Architecture Diagrams

> **Version**: 2.0.0 (Phoenix Edition)
> **Architecture**: Reactor V4

## 1. High-Level System Architecture

```
                              BugtraceAI-CLI System Overview
    +==============================================================================+
    |                                                                              |
    |    +------------------+                                                      |
    |    |   CLI / TUI      |  User Interface                                      |
    |    +--------+---------+                                                      |
    |             |                                                                |
    |             v                                                                |
    |    +------------------+       +------------------+       +------------------+|
    |    | TeamOrchestrator |<----->|     Reactor      |<----->|    EventBus      ||
    |    | (Scan Manager)   |       |   (Job Engine)   |       | (Pub/Sub)        ||
    |    +--------+---------+       +--------+---------+       +------------------+|
    |             |                          |                                     |
    |             v                          v                                     |
    |    +------------------+       +------------------+                           |
    |    |   Agent Pool     |       |   JobManager     |                           |
    |    | (XSS,SQLi,RCE..) |       | (SQLite Queue)   |                           |
    |    +--------+---------+       +------------------+                           |
    |             |                                                                |
    |             v                                                                |
    |    +------------------+       +------------------+       +------------------+|
    |    |  LLM Client      |       | Browser Manager  |       | External Tools   ||
    |    | (OpenRouter)     |       | (CDP/Playwright) |       | (SQLMap,Nuclei)  ||
    |    +------------------+       +------------------+       +------------------+|
    |                                                                              |
    +==============================================================================+
```

## 2. 4-Phase Pipeline Flow

```
    Phase 1: HUNTER              Phase 2: RESEARCHER          Phase 3: VALIDATOR           Phase 4: REPORTER
    (Reconnaissance)             (Analysis)                   (Confirmation)               (Output)

    +---------------+           +------------------+         +------------------+         +------------------+
    | GoSpider      |           | URLMasterAgent   |         | Global Review    |         | ReportingAgent   |
    | Nuclei        |   URLs    | (per URL)        |  Raw    | Cross-URL Chain  |  Valid  | AI Enrichment    |
    | VisualCrawler +---------->+ 5-Approach DAST  +-------->+ Deduplication    +-------->+ Evidence Link    |
    +---------------+           | Skill Routing    |Findings | Browser Verify   |Findings | HTML/JSON/MD     |
                                +------------------+         | Vision AI        |         +------------------+
                                                             +------------------+

    Time: ~2-5 min              Time: ~1-3 min/URL           Time: ~1-2 min               Time: ~30 sec
```

## 3. Validation Triad (Accuracy Engine)

```
                            VALIDATION TRIAD
    +================================================================+
    |                                                                |
    |   Layer 1: PAYLOAD VERIFICATION                                |
    |   +----------------------------------------------------------+ |
    |   | Agent confirms syntax (SQL error, XSS reflection, etc.)  | |
    |   +----------------------------------------------------------+ |
    |                              |                                 |
    |                              v                                 |
    |   Layer 2: BROWSER VERIFICATION                                |
    |   +----------------------------------------------------------+ |
    |   | CDP/Playwright executes exploit                          | |
    |   | - alert() popup detection                                | |
    |   | - Cookie/storage access check                            | |
    |   | - DOM mutation monitoring                                | |
    |   +----------------------------------------------------------+ |
    |                              |                                 |
    |                              v                                 |
    |   Layer 3: VISION AI VALIDATION                                |
    |   +----------------------------------------------------------+ |
    |   | qwen/qwen3-vl-8b-thinking analyzes screenshot            | |
    |   | - "Is this a real PHP error dump?"                       | |
    |   | - "Does the alert box contain our payload?"              | |
    |   +----------------------------------------------------------+ |
    |                                                                |
    +================================================================+
                                   |
                                   v
                        +--------------------+
                        | VALIDATED FINDING  |
                        | Confidence: HIGH   |
                        +--------------------+
```

## 4. Agent Ecosystem

```
                              SPECIALIZED AGENTS
    +========================================================================+
    |                                                                        |
    |   INJECTION AGENTS              INFRASTRUCTURE AGENTS                  |
    |   +------------------+          +------------------+                   |
    |   | XSSAgent         |          | HeaderInjection  |                   |
    |   | - DOM/Reflected  |          | - Host header    |                   |
    |   | - Stored         |          | - Cache poison   |                   |
    |   +------------------+          +------------------+                   |
    |                                                                        |
    |   +------------------+          +------------------+                   |
    |   | SQLMapAgent      |          | PrototypePollut  |                   |
    |   | - Docker wrapper |          | - JS prototype   |                   |
    |   | - 100% confirm   |          +------------------+                   |
    |   +------------------+                                                 |
    |                                 ADVANCED AGENTS                        |
    |   +------------------+          +------------------+                   |
    |   | RCEAgent         |          | SSRFAgent        |                   |
    |   | - Command inject |          | - Cloud metadata |                   |
    |   | - OOB payloads   |          | - Internal ports |                   |
    |   +------------------+          +------------------+                   |
    |                                                                        |
    |   +------------------+          +------------------+                   |
    |   | LFIAgent         |          | IDORAgent        |                   |
    |   | - Path traversal |          | - Object refs    |                   |
    |   +------------------+          +------------------+                   |
    |                                                                        |
    |   +------------------+          +------------------+                   |
    |   | JWTAgent         |          | CSRFAgent        |                   |
    |   | - None algo      |          | - Token checks   |                   |
    |   | - Key confusion  |          +------------------+                   |
    |   +------------------+                                                 |
    |                                                                        |
    +========================================================================+
```

## 5. Reactor V4 Job Flow

```
                              REACTOR V4 JOB FLOW

    +-------------+     +-------------+     +-------------+     +-------------+
    |   PENDING   |---->|   RUNNING   |---->|  COMPLETED  |     |   TIMEOUT   |
    |   (Queue)   |     | (Processing)|     |  (Success)  |     | (Exceeded)  |
    +-------------+     +------+------+     +-------------+     +-------------+
                               |                                      ^
                               |                                      |
                               v                                      |
                        +-------------+     +-------------+           |
                        |   FAILED    |---->|     DLQ     |-----------+
                        | (Error)     |     | (Dead Ltr)  | (after 3 retries)
                        +-------------+     +-------------+

    Job Manager Features:
    - Atomic fetch-and-lock (UPDATE...RETURNING)
    - Priority queue (ORDER BY priority DESC)
    - Dead letter queue after MAX_RETRIES=3
    - Crash recovery (reset RUNNING -> PENDING on startup)
```

## 6. Data Flow Diagram

```
    USER                    ORCHESTRATOR                   AGENTS                    OUTPUT

    Target URL              TeamOrchestrator               URLMasterAgent            Reports
       |                          |                             |                       ^
       |   start(url)             |                             |                       |
       +------------------------->+                             |                       |
       |                          |                             |                       |
       |                    +-----+-----+                       |                       |
       |                    | Phase 1   |                       |                       |
       |                    | GoSpider  |                       |                       |
       |                    | Nuclei    |                       |                       |
       |                    +-----+-----+                       |                       |
       |                          |                             |                       |
       |                          |  URLs                       |                       |
       |                          +------------+--------------->+                       |
       |                          |            |                |                       |
       |                    +-----+-----+      |          +-----+-----+                 |
       |                    | Phase 2   |      |          | Analyze   |                 |
       |                    | Parallel  |<-----+          | Exploit   |                 |
       |                    | Workers   |                 | Validate  |                 |
       |                    +-----+-----+                 +-----+-----+                 |
       |                          |                             |                       |
       |                          |<----------------------------+                       |
       |                          |  Raw Findings               |                       |
       |                    +-----+-----+                       |                       |
       |                    | Phase 3   |                       |                       |
       |                    | Validate  |                       |                       |
       |                    | Vision AI |                       |                       |
       |                    +-----+-----+                       |                       |
       |                          |                             |                       |
       |                    +-----+-----+                       |                       |
       |                    | Phase 4   +---------------------------------------------->+
       |                    | Report    |                                               |
       |                    +-----------+                                               |
       |                                                                                |
       +<-------------------------------------------------------------------------------+
       |   HTML/JSON Report
```

## 7. LLM Client Model Shifting

```
                         LLM CLIENT - MODEL SHIFTING

    +------------------+     Request      +------------------+
    |   Agent Code     +----------------->+   LLM Client     |
    +------------------+                  +--------+---------+
                                                   |
                                                   v
                                          +----------------+
                                          | Model Selector |
                                          +-------+--------+
                                                  |
                       +-------------+------------+------------+-------------+
                       |             |            |            |             |
                       v             v            v            v             v
                 +---------+  +-----------+  +--------+  +----------+  +--------+
                 | PRIMARY |  | ANALYSIS  |  | VISION |  | MUTATION |  | FALLBACK|
                 | Model   |  | Model     |  | Model  |  | Model    |  | Model   |
                 +---------+  +-----------+  +--------+  +----------+  +--------+
                 |  o3     |  | deepseek  |  | qwen3  |  | deepseek |  | gemini  |
                 | /qwen3  |  | -chat-v3  |  | -vl-8b |  | -chat-v3 |  | -flash  |
                 +---------+  +-----------+  +--------+  +----------+  +--------+

    Features:
    - Token usage tracking
    - Model metrics (latency, success rate)
    - Response caching (1hr TTL)
    - Refusal detection with fallback
    - Streaming support
```

## 8. Directory Structure

```
    bugtrace/
    +-- core/                      # Core orchestration layer
    |   +-- team.py                # TeamOrchestrator (Phase coordinator)
    |   +-- reactor.py             # Reactor V4 (Job engine)
    |   +-- job_manager.py         # SQLite job queue + DLQ
    |   +-- event_bus.py           # Pub/sub event system
    |   +-- llm_client.py          # OpenRouter API client
    |   +-- config.py              # Settings management
    |   +-- conductor.py           # Anti-hallucination validation
    |   +-- database.py            # SQLite + vector storage
    |   +-- cdp_client.py          # Chrome DevTools Protocol
    |   +-- state_manager.py       # Finding persistence
    |   +-- ui.py                  # TUI dashboard
    |   +-- boot.py                # Startup health checks
    |
    +-- agents/                    # Specialized vulnerability agents
    |   +-- url_master.py          # Per-URL orchestrator
    |   +-- xss_agent.py           # XSS specialist
    |   +-- sqlmap_agent.py        # SQLi with SQLMap
    |   +-- nuclei_agent.py        # Tech detection
    |   +-- gospider_agent.py      # URL discovery
    |   +-- dast_agent.py          # 5-approach analysis
    |   +-- reporting.py           # Report generation
    |   +-- system_prompts/        # Agent personas (markdown)
    |
    +-- skills/                    # Modular skill system
    |   +-- injection.py           # XSS, SQLi, LFI, XXE, CSTI
    |   +-- advanced.py            # SSRF, IDOR, OpenRedirect
    |   +-- infrastructure.py      # Headers, Prototype Pollution
    |   +-- external_tools.py      # SQLMap, Nuclei wrappers
    |   +-- utility.py             # Browser, Report skills
    |
    +-- tools/                     # External integrations
    |   +-- visual/                # Browser automation
    |   +-- manipulator/           # Payload mutation engine
    |   +-- interactsh.py          # OOB detection
    |   +-- external.py            # Docker tool wrappers
    |
    +-- reporting/                 # Output generation
        +-- generator.py           # Jinja2 HTML templates
        +-- templates/             # Report templates
```

---

*Last Updated: 2026-01-26*
