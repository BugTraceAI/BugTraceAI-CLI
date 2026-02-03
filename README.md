# BugTraceAI-CLI

[![Website](https://img.shields.io/badge/Website-bugtraceai.com-blue?logo=google-chrome&logoColor=white)](https://bugtraceai.com)
[![Wiki Documentation](https://img.shields.io/badge/Wiki%20Documentation-000?logo=wikipedia&logoColor=white)](https://deepwiki.com/BugTraceAI/BugTraceAI-CLI)
![License](https://img.shields.io/badge/License-Proprietary-red.svg)
![Status](https://img.shields.io/badge/Status-Beta-orange)
![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Required-blue?logo=docker)
![Made with](https://img.shields.io/badge/Made%20with-❤️-red)

****

## 📑 Table of Contents
- [🚨 Disclaimer](#-disclaimer)
- [✨ Features](#-features)
- [🔬 Core Methodology](#-core-methodology)
- [🏗️ Architecture](#️-architecture)
- [🛠️ Technology Stack](#️-technology-stack)
- [🚀 Getting Started](#-getting-started)
- [⚙️ Configuration](#️-configuration)
- [📊 Output](#-output)
- [📜 License](#-license)

***

> 🏆 **The First Agentic Framework Intelligently Designed for Bug Bounty Hunting**

BugTraceAI-CLI is an autonomous offensive security framework that combines LLM-driven analysis with deterministic exploitation tools. Unlike passive analysis tools, BugTraceAI-CLI actively exploits vulnerabilities using real payloads, SQLMap integration, and browser-based validation to deliver confirmed, actionable findings.

The core philosophy is **"Think like a pentester, execute like a machine, validate like an auditor"** - using AI for intelligent hypothesis generation, but relying on real tools for exploitation and validation.

## 🚨 Disclaimer

This tool is for **authorized security testing only**.

BugTraceAI-CLI performs **active exploitation** including:
- Real SQL injection payloads via SQLMap
- XSS payload execution in browsers
- Template injection testing
- Server-side request forgery probing

**By using this tool, you acknowledge and agree that:**
- You will only test applications for which you have explicit, written permission
- You understand this tool sends actual attack payloads to targets
- The creators assume no liability for any misuse or damage caused

**Unauthorized access to computer systems is illegal.**

## ✨ Features

BugTraceAI-CLI implements a 5-phase pipeline that mirrors a professional penetration testing workflow.

### Phase 1: Discovery
- 🕷️ **GoSpider Integration**: Fast async crawling with JavaScript rendering and sitemap parsing
- 🎯 **Nuclei CVE Scanning**: Template-based detection of known vulnerabilities
- 🔍 **Parameter Extraction**: Automatic identification of injectable parameters

### Phase 2: Analysis (DASTySAST)
- 🧠 **Multi-Persona Analysis**: 6 different AI "personas" analyze each URL (bug bounty hunter, code auditor, pentester, etc.)
- ✅ **Consensus Voting**: Requires 4/5 agreement from analysis personas to reduce false positives
- 🔎 **Skeptical Review**: The 6th "Skeptical" persona (Claude Haiku) performs final filtering
- 🛡️ **Parallel Execution**: All personas analyze simultaneously for speed

### Phase 3: Intelligent Consolidation
- 🎯 **ThinkingConsolidationAgent**: Central brain that routes findings to specialists
- 🔄 **Deduplication**: Eliminates redundant findings across URLs
- ⚡ **Priority Routing**: High-confidence findings get tested first
- 🛡️ **SQLi Bypass**: SQL injection candidates always reach SQLMap (tool decides, not LLM)

### Phase 4: Exploitation
Real tools, real payloads, real results:

| Agent | Target | Method |
|-------|--------|--------|
| 🔥 **XSSAgent** | Cross-Site Scripting | Playwright browser + context-aware payloads |
| 💉 **SQLiAgent** | SQL Injection | SQLMap with WAF bypass tamper scripts |
| 🎭 **CSTIAgent** | Client-Side Template Injection | AngularJS, Vue, React expressions |
| 🌐 **SSRFAgent** | Server-Side Request Forgery | OOB callback verification |
| 📄 **XXEAgent** | XML External Entity | DTD injection + OOB exfiltration |
| 🔓 **IDORAgent** | Insecure Direct Object Reference | ID manipulation testing |
| 📁 **LFIAgent** | Local File Inclusion | Path traversal with filter evasion |
| 🧩 **ProtoAgent** | Prototype Pollution | Browser-based property verification |
| 🔌 **ApiAgent** | API Security | Broken Object Level Authorization (BOLA) testing |

### Phase 5: Validation
- 🖥️ **Chrome DevTools Protocol**: Low-level browser verification for XSS
- 👁️ **Vision AI**: Screenshot analysis confirms visual vulnerabilities
- 📸 **Evidence Capture**: Every confirmed finding includes proof

### Intelligence Systems
- 🔀 **LLM Shifting**: Automatic fallback through model tiers (Gemini → DeepSeek → Claude → Qwen)
- 🛡️ **WAF Detection**: Identifies Cloudflare, Akamai, AWS WAF, ModSecurity
- 🎯 **Adaptive Bypass**: Encoding, chunking, and case mixing strategies per WAF type

## 🔬 Core Methodology

BugTraceAI-CLI uses a multi-layered approach to maximize accuracy while minimizing false positives.

### Multi-Persona Analysis
Instead of a single AI scan, each URL is analyzed by 6 different "personas" providing diverse perspectives:

1. **Bug Bounty Hunter**: Focuses on high-impact, reward-worthy issues (RCE, SQLi, SSRF)
2. **Code Auditor**: analyzing code patterns, input validation, and logic flaws
3. **Pentester**: Standard attack-surface mapping and OWASP Top 10 exploitation
4. **Security Researcher**: Novel attack vectors, race conditions, and edge cases
5. **Red Team Operator**: Advanced attack chains, privilege escalation, and lateral movement
6. **Skeptical Reviewer**: A separate "critic" agent that aggressively filters false positives

### Consensus + Skeptical Review
```
5 Analysis Personas run in parallel
        ↓
Consensus voting (Agreement analysis)
        ↓
6th Persona "Skeptical Agent" Review (Claude Haiku)
        ↓
Passed to specialist agents
```

### Tool-Based Validation
The key differentiator: **AI hypothesizes, tools validate**.

- SQLi findings → SQLMap confirms with real injection
- XSS findings → Playwright executes payload in browser
- All findings → CDP + Vision AI provides evidence

This eliminates the "hallucination problem" of pure-AI scanners.

## 🏗️ V5 Reactor Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      BUGTRACE REACTOR                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐     │
│  │ Discovery│ → │ Analysis │ → │ Thinking │ → │Specialist│     │
│  │ GoSpider │   │ DASTySAST│   │ Consolid.│   │  Agents  │     │
│  │ Nuclei   │   │ 6 Personas   │ Dedup    │   │ SQLMap   │     │
│  └──────────┘   │ Consensus│   │ Priority │   │ Playwright    │
│                 └──────────┘   └──────────┘   └────┬─────┘     │
│                                                     │           │
│                                                     ▼           │
│                                              ┌──────────┐       │
│                                              │Validation│       │
│                                              │ CDP      │       │
│                                              │ Vision AI│       │
│                                              └──────────┘       │
│                                                     │           │
│                                                     ▼           │
│                                              ┌──────────┐       │
│                                              │  Report  │       │
│                                              │JSON/MD/HTML     │
│                                              └──────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

### Parallelization Control

Each phase runs with independent concurrency:

| Phase | Concurrency | Configurable | Notes |
|-------|-------------|--------------|-------|
| Discovery | 1 | No | GoSpider is already fast |
| Analysis | 5 | Yes | Parallel DAST per URL |
| Exploitation | 10 | Yes | Parallel specialist agents |
| Validation | 1 | **No** | CDP limitation (hardcoded) |

> **Why is Validation = 1?** Chrome DevTools Protocol doesn't support multiple simultaneous connections. Additionally, `alert()` popups from XSS payloads block CDP indefinitely. Single-threaded with timeouts prevents crashes.

## 🛠️ Technology Stack

- **Language**: Python 3.10+
- **AI Provider**: OpenRouter (Gemini, Claude, DeepSeek, Qwen)
- **Local AI**: BAAI/bge-small-en-v1.5 (SOTA Embeddings & Semantic Search)
- **Browser Automation**: Playwright (exploitation), Chrome CDP (validation)
- **SQL Injection**: SQLMap via Docker
- **Crawling**: GoSpider via Docker
- **CVE Scanning**: Nuclei via Docker
- **Database**: SQLite with WAL mode
- **Async**: asyncio + aiohttp

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Docker & Docker Compose
- Chrome/Chromium browser
- OpenRouter API key

### Installation

```bash
# Clone the repository
git clone https://github.com/BugTraceAI/BugTraceAI-CLI
cd BugTraceAI-CLI

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install browser
playwright install chromium

# Configure
cp bugtraceaicli.conf.example bugtraceaicli.conf
# Edit and add your OPENROUTER_API_KEY
```

### Quick Start

```bash
# Full scan
./bugtraceai-cli https://target.com

# Clean scan (reset database)
./bugtraceai-cli https://target.com --clean

# Resume interrupted scan
./bugtraceai-cli https://target.com --resume
```

## ⚙️ Configuration

All settings in `bugtraceaicli.conf`:

```ini
[API]
OPENROUTER_API_KEY = sk-or-v1-xxxxx

[SCAN]
MAX_URLS = 100
MAX_CONCURRENT_ANALYSIS = 5
MAX_CONCURRENT_SPECIALISTS = 10

[SCANNING]
MANDATORY_SQLMAP_VALIDATION = True
STOP_ON_CRITICAL = False

[VALIDATION]
CDP_ENABLED = True
VISION_ENABLED = True
```

### Model Configuration

```ini
[LLM_MODELS]
DEFAULT_MODEL = google/gemini-2.0-flash-thinking-exp:free
SKEPTICAL_MODEL = anthropic/claude-3.5-haiku:beta
VISION_MODEL = google/gemini-2.0-flash-thinking-exp:free
```

## 📊 Output

### Reports
Generated in `/reports/`:
- `report_*.json` - Machine-readable findings
- `report_*.md` - Markdown summary
- `report_*.html` - Executive presentation

### Logs
Located in `/logs/`:
- `execution.log` - Detailed trace
- `llm_audit.jsonl` - Every AI prompt/response
- `errors.log` - Error tracking

### Finding Status Flow
```
CANDIDATE → PENDING_VALIDATION → CONFIRMED / FALSE_POSITIVE → PROBE_VALIDATED
```

## 📜 License

Proprietary - All Rights Reserved

Copyright (c) 2026 BugTraceAI

See [bugtraceai.com](https://bugtraceai.com) for licensing information.

---

Made with ❤️ by Albert C. [@yz9yt](https://x.com/yz9yt)

[bugtraceai.com](https://bugtraceai.com)
