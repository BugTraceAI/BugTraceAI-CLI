# BugtraceAI-CLI: Architecture V2 (Sequential Pipeline)

> ✅ **STATUS: PARTIALLY IMPLEMENTED** - The sequential pipeline (`_run_sequential_pipeline()`) is now available in `team.py`. Use `--sequential` flag or `PIPELINE_MODE=sequential` config.

## Version 2.0.0 (Phoenix Edition) - Implemented 2026-01-08

---

## 1. PROBLEM WITH CURRENT ARCHITECTURE

The current Phoenix Edition uses **parallel URLMasterAgents** which causes:

| Issue | Description |
|-------|-------------|
| **Chaos** | Too many agents running simultaneously, hard to debug |
| **Resource Contention** | Browser, LLM, SQLMap compete for resources |
| **Redundant Work** | SQLMap crawls even when GoSpider already did |
| **No Clear Flow** | Hard to understand what's happening |
| **No Cross-URL Correlation** | Can't detect vulnerability chaining |

---

## 2. PROPOSED ARCHITECTURE: SEQUENTIAL PIPELINE

### 2.1 High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         MAIN ORCHESTRATOR                                │
│          (Cybersecurity Expert - Coordinates Everything)                 │
│                              │                                           │
│                    ┌─────────┴─────────┐                                │
│                    │     CONDUCTOR     │ ← Anti-hallucination helper    │
│                    └─────────┬─────────┘                                │
│                              │                                           │
│              ┌───────────────┴───────────────┐                          │
│              ▼                               ▼                          │
│        ┌──────────┐                   ┌──────────────┐                 │
│        │ DATABASE │ ← Source of truth │   FICHEROS   │ ← Artifacts     │
│        │ (SQLite) │   for queries     │  (.md, .png) │   for humans    │
│        └──────────┘                   └──────────────┘                 │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Execution Phases

#### PHASE 1: RECONNAISSANCE (Sequential)

```
Orchestrator → Nuclei Agent
                   ↓
            tech_profile.json (PHP, MySQL, Apache, etc.)
                   ↓
            Orchestrator → GoSpider Agent
                   ↓
            urls.txt (max N URLs based on config)
```

**Purpose**:

- Nuclei detects technology to avoid useless attacks (no XSS payloads for API-only backends)
- GoSpider respects `bugtrace.conf` limits (depth, max_urls)

---

#### PHASE 2: URL-BY-URL ANALYSIS (Controlled Threads)

```
urls.txt → URL Pool
              │
    ┌─────────┴─────────┐
    │  Thread Pool      │
    │  (N from config,  │
    │   default=1)      │
    └─────────┬─────────┘
              │
    ┌─────────▼─────────┐
    │   For Each URL:   │
    │                   │
    │  1. DAST/SAST     │ → 5 analysis approaches
    │     Agent         │ → Skeptical (soft) validation
    │         ↓         │
    │  vulnerabilities_ │ ← Potential vulns found
    │  urlX.md          │
    │         ↓         │
    │  2. Orchestrator  │ ← Reads report, decides
    │     decides       │
    │         ↓         │
    │  3. Specialist    │ ← Only if DAST found something
    │     Agents        │
    │     - XSS Agent   │ (uses HTTPManipulator, Interactsh, Vision)
    │     - SQLMap Agent│ (uses Docker SQLMap with -p param)
    │     - IDOR Agent  │
    │     - LFI Agent   │
    │     - SSTI Agent  │
    │     - etc.        │
    │         ↓         │
    │  4. Conductor     │ ← Validates (not too strict)
    │     validates     │
    │         ↓         │
    │  exploited_urlX.md│ ← Confirmed exploits only
    │         ↓         │
    │  5. Database      │ ← INSERT finding
    │     stores        │
    └───────────────────┘
```

**Key Points**:

- **Sequential conversation**: Orchestrator asks → waits for response → asks next
- **Files created per URL**: `vulnerabilities_url1.md`, `exploited_url1.md`
- **Database is source of truth**: Orchestrator queries DB, not files
- **Files are artifacts**: For humans, for final report

---

#### PHASE 3: GLOBAL REVIEW (Before Final Report)

```
Orchestrator reviews ALL findings in Database:
   │
   ├── SELECT * FROM findings WHERE scan_id = X
   │
   └── Looks for CHAINING patterns:
       
       URL1: IDOR (can see other users)     ──┐
                                               ├── Combined = ACCOUNT TAKEOVER (CRITICAL)
       URL2: Token Leak (sees auth tokens) ────┘
       
       If found → Create new "Chained" vulnerability
       If doubt → Re-validate with different approach
```

**Purpose**:

- Detect vulnerabilities that only work when combined
- Re-try failed exploitations with new context
- Smart correlation that single-URL analysis can't do

---

#### PHASE 4: REPORTING (Final)

```
Reporting Agent:
   │
   ├── Query Database for all validated findings
   ├── Read tech_profile.json
   ├── Include screenshots from url_folders/
   ├── Include chained vulnerabilities from Phase 3
   │
   └── Generate:
       ├── FINAL_REPORT.html (Premium, interactive)
       ├── FINAL_REPORT.md (Technical)
       └── executive_summary.md (For management)
```

---

## 3. FILE STRUCTURE

```
scan_folder/
├── tech_profile.json          ← Nuclei output
├── urls.txt                   ← GoSpider output
│
├── url1_search_php/
│   ├── vulnerabilities_url1.md   ← DAST/SAST findings (potential)
│   ├── exploited_url1.md         ← Specialist findings (confirmed)
│   └── screenshots/
│       └── xss_proof_1.png
│
├── url2_login_php/
│   ├── vulnerabilities_url2.md
│   └── (no exploited file - not exploitable)
│
├── url5_admin_php/
│   ├── vulnerabilities_url5.md
│   ├── exploited_url5.md
│   └── screenshots/
│
├── findings.db                ← SQLite database
│
└── FINAL_REPORT.html          ← Reporting Agent output
```

**Note**: URLs without vulnerabilities don't create folders.

---

## 4. CONFIGURATION (`bugtrace.conf`)

```ini
[crawl]
depth = 2                    # GoSpider crawl depth
max_urls = 10                # Maximum URLs to analyze

[scan]
max_threads = 1              # Start with 1 to avoid chaos
url_timeout = 60             # Timeout per URL analysis

[validation]
conductor_enabled = true     # Use Conductor for anti-hallucination
skeptical_level = soft       # Not too strict (avoid false negatives)
vision_enabled = true        # Use Vision model for XSS confirmation

[specialists]
sqlmap_enabled = true
interactsh_enabled = true
```

---

## 5. ORCHESTRATOR PROMPTS (Examples)

### 5.1 To Nuclei Agent

```
Analyze the technology stack of {target_url}.
Return: frameworks, languages, databases, WAF detected.
```

### 5.2 To DAST/SAST Agent

```
Analyze this URL: {url}
Technology context: {tech_profile}

Use 5 different analysis approaches:
1. Pentester perspective
2. Bug Bounty Hunter perspective  
3. Code Auditor perspective
4. Red Team perspective
5. Security Researcher perspective

Return potential vulnerabilities with confidence scores.
```

### 5.3 To XSS Agent

```
I have a DAST report indicating possible XSS in {url} parameter '{param}'.
Technology: {tech_profile}

Validate this XSS vulnerability:
1. Use HTTPManipulator to try payloads
2. If blind XSS suspected, use Interactsh
3. Capture screenshot for visual proof
4. Use Vision model to confirm alert box

Return: validated (true/false), evidence, payload used.
```

---

## 6. SPECIALIST AGENTS INVENTORY

| Agent | Tools Used | When Called |
|-------|-----------|-------------|
| **Nuclei Agent** | nuclei CLI | Phase 1 (tech detection) |
| **GoSpider Agent** | gospider Docker | Phase 1 (URL discovery) |
| **DAST/SAST Agent** | LLM 5-approach | Phase 2 (every URL) |
| **XSS Agent** | HTTPManipulator, Interactsh, Vision | Phase 2 (if DAST finds XSS) |
| **SQLMap Agent** | sqlmap Docker (`-p param`) | Phase 2 (if DAST finds SQLi) |
| **IDOR Agent** | Custom logic | Phase 2 (if DAST finds IDOR) |
| **LFI Agent** | Manipulator payloads | Phase 2 (if DAST finds LFI) |
| **SSTI Agent** | Template payloads | Phase 2 (if DAST finds SSTI) |
| **XXE Agent** | XML payloads | Phase 2 (if DAST finds XXE) |
| **Reporting Agent** | Jinja2 templates | Phase 4 (final report) |

---

## 7. KEY IMPROVEMENTS OVER V1

| Aspect | V1 (Current) | V2 (Proposed) |
|--------|--------------|---------------|
| **Flow** | Parallel, chaotic | Sequential, controlled |
| **Agents** | Monolithic URLMaster | Specialized (Nuclei, DAST, XSS...) |
| **Threads** | Unlimited (chaos) | Configurable (default 1) |
| **SQLMap** | Crawls redundantly | Uses `-p param` (targeted) |
| **Files** | Flat structure | Per-URL folders |
| **Orchestrator** | Dumb dispatcher | Expert that reads/decides |
| **Cross-URL** | None | Chaining detection in Phase 3 |
| **Database** | Passive storage | Active source of truth |

---

## 8. IMPLEMENTATION PRIORITY

1. **Phase A**: Refactor TeamOrchestrator to sequential flow
2. **Phase B**: Extract Nuclei Agent (separate from skills)
3. **Phase C**: Extract GoSpider Agent (separate from skills)
4. **Phase D**: Create DAST/SAST Agent with 5 approaches
5. **Phase E**: Per-URL folder structure
6. **Phase F**: Orchestrator reads from Database
7. **Phase G**: Add Phase 3 (Global Review / Chaining)
8. **Phase H**: Update bugtrace.conf schema

---

*Proposed: 2026-01-05 | Target Version: 3.0.0*
