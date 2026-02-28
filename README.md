# BugTraceAI-CLI

[![Website](https://img.shields.io/badge/Website-bugtraceai.com-blue?logo=google-chrome&logoColor=white)](https://bugtraceai.com)
[![Wiki Documentation](https://img.shields.io/badge/Wiki%20Documentation-000?logo=wikipedia&logoColor=white)](https://deepwiki.com/BugTraceAI/BugTraceAI-CLI)
![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)
![Status](https://img.shields.io/badge/Status-Beta-orange)
![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Required-blue?logo=docker)
![MCP](https://img.shields.io/badge/MCP-Compatible-green?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQxIDAtOC0zLjU5LTgtOHMzLjU5LTggOC04IDggMy41OSA4IDgtMy41OSA4LTggOHoiLz48L3N2Zz4=)
![Made with](https://img.shields.io/badge/Made%20with-❤️-red)

---

## 📑 Table of Contents

- [🚨 Disclaimer](#-disclaimer)
- [✨ Features](#-features)
- [🔬 Core Methodology](#-core-methodology)
- [🏗️ Architecture](#️-architecture)
- [🛠️ Technology Stack](#️-technology-stack)
- [🚀 Getting Started](#-getting-started)
- [🤖 AI Assistant Setup (MCP)](#-ai-assistant-setup-mcp)
- [⚙️ Configuration](#️-configuration)
- [📊 Output](#-output)
- [📜 License](#-license)

---

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

BugTraceAI-CLI implements a 6-phase pipeline that mirrors a professional penetration testing workflow.

### Phase 1: Reconnaissance

- 🕷️ **GoSpider Integration**: Fast async crawling with JavaScript rendering and sitemap parsing
- 🔍 **Parameter Extraction**: Automatic identification of injectable parameters
- 🌐 **API Endpoint Enrichment**: Detail URL discovery from list endpoints
- 🧭 **SPA Route Inference**: Infers API endpoints from frontend routes

### Phase 2: Discovery (DASTySAST)

- 🧠 **Multi-Persona Analysis**: 6 different AI "personas" analyze each URL (bug bounty hunter, code auditor, pentester, etc.)
- ✅ **Consensus Voting**: Requires 4/5 agreement from analysis personas to reduce false positives
- 🔎 **Skeptical Review**: The 6th "Skeptical" persona (Claude Haiku) performs final filtering
- 🎯 **Nuclei CVE Scanning**: Template-based detection of known vulnerabilities (runs in parallel)
- 🛡️ **Parallel Execution**: All personas analyze simultaneously for speed

### Phase 3: Strategy

- 🎯 **ThinkingConsolidationAgent**: Central brain that routes findings to specialists
- 🔄 **Deduplication**: Eliminates redundant findings across URLs
- ⚡ **Priority Routing**: High-confidence findings get tested first
- 🛡️ **SQLi Bypass**: SQL injection candidates always reach SQLMap (tool decides, not LLM)
- 🧩 **Auto-Dispatch**: Framework detection triggers specialist agents automatically (e.g., Angular → CSTIAgent)

### Phase 4: Exploitation

Real tools, real payloads, real results — 14 autonomous specialist agents:

| Agent                          | Target                                | Method                                                            |
| ------------------------------ | ------------------------------------- | ----------------------------------------------------------------- |
| 🔥 **XSSAgent**                | Cross-Site Scripting                  | Playwright browser + 6-level escalation pipeline                  |
| 💉 **SQLiAgent**               | SQL Injection                         | SQLMap with WAF bypass tamper scripts                             |
| 🎭 **CSTIAgent**               | Client/Server-Side Template Injection | AngularJS, Vue, Jinja2, Twig, Mako                                |
| 🌐 **SSRFAgent**               | Server-Side Request Forgery           | OOB callback verification                                         |
| 📄 **XXEAgent**                | XML External Entity                   | DTD injection + OOB exfiltration                                  |
| 🔓 **IDORAgent**               | Insecure Direct Object Reference      | ID manipulation + path segment testing                            |
| 📁 **LFIAgent**                | Local File Inclusion                  | Path traversal with filter evasion                                |
| 🧩 **PrototypePollutionAgent** | Prototype Pollution                   | Browser-based property verification                               |
| 🔌 **APISecurityAgent**        | API Security                          | Broken Object Level Authorization (BOLA) testing                  |
| 🔑 **JWTAgent**                | JWT Vulnerabilities                   | Algorithm confusion, weak secrets, token forging                  |
| 🔀 **OpenRedirectAgent**       | Open Redirect                         | HTTP 3xx + DOM-based redirect detection                           |
| 💀 **RCEAgent**                | Remote Code Execution                 | Command injection + deserialization testing                       |
| 📨 **HeaderInjectionAgent**    | Header Injection                      | CRLF injection + response splitting                               |
| 📦 **MassAssignmentAgent**     | Mass Assignment                       | Parameter pollution + privilege escalation                        |
| 💀 **KaliAgent**               | Advanced Exploitation                 | Full Kali Linux terminal toolset via MCP (Nmap, Metasploit, etc.) |
| 🕵️ **ReconAgent**              | Automated Recon                       | Fully automated ReconFTW orchestration for deep reconnaissance    |

### Phase 5: Validation

- 🖥️ **Chrome DevTools Protocol**: Low-level browser verification for XSS
- 👁️ **Vision AI**: Screenshot analysis confirms visual vulnerabilities
- 📸 **Evidence Capture**: Every confirmed finding includes proof

### Phase 6: Reporting

- 📊 **AI-Powered Reports**: LLM-generated executive and technical assessments
- 📝 **Multiple Formats**: JSON (machine-readable), Markdown, and HTML reports
- 🔬 **PoC Enrichment**: Batch proof-of-concept generation for confirmed findings
- 📁 **Specialist Audit Trail**: Per-agent WET/DRY/Results traceability

### Intelligence Systems

- 🔀 **LLM Shifting**: Automatic fallback through model tiers (Gemini → DeepSeek → Claude → Qwen)
- 🛡️ **WAF Detection**: Identifies Cloudflare, Akamai, AWS WAF, ModSecurity
- 🎯 **Adaptive Bypass**: Encoding, chunking, and case mixing strategies per WAF type
- 🛡️ **Ecosystem Robustness**: Built-in circuit breakers for infinite loops, adaptive rate-limiting, and cross-interface (LAN/Remote) compatibility.

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

## 🏗️ Reactor Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         BUGTRACE REACTOR                             │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐   │
│  │   Phase 1  │   │   Phase 2  │   │   Phase 3  │   │   Phase 4  │   │
│  │   Recon    │ → │  Discovery │ → │  Strategy  │ → │Exploitation│   │
│  │  GoSpider  │   │ DASTySAST  │   │ ThinkingAg.│   │ 14 Agents  │   │
│  │ URL Enrich │   │ 6 Personas │   │   Dedup    │   │   SQLMap   │   │
│  │ SPA→API    │   │  + Nuclei  │   │  Routing   │   │ Playwright │   │
│  └────────────┘   └────────────┘   └────────────┘   └─────┬──────┘   │
│                                                            │         │
│                                                            ▼         │
│                                                     ┌────────────┐   │
│                                                     │   Phase 5  │   │
│                                                     │ Validation │   │
│                                                     │    CDP     │   │
│                                                     │ Vision AI  │   │
│                                                     └─────┬──────┘   │
│                                                           │          │
│                                                           ▼          │
│                                                     ┌────────────┐   │
│                                                     │   Phase 6  │   │
│                                                     │ Reporting  │   │
│                                                     │JSON/MD/HTML│   │
│                                                     └────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

### Parallelization Control

Each phase runs with independent concurrency:

| Phase          | Concurrency | Configurable | Notes                        |
| -------------- | ----------- | ------------ | ---------------------------- |
| Reconnaissance | 1           | No           | GoSpider is already fast     |
| Discovery      | 5           | Yes          | Parallel DAST per URL        |
| Strategy       | 1           | No           | Sequential dedup + routing   |
| Exploitation   | 10          | Yes          | Parallel specialist agents   |
| Validation     | 1           | **No**       | CDP limitation (hardcoded)   |
| Reporting      | 1           | No           | Sequential report generation |

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

- **For Docker**: Docker & Docker Compose
- **For Local**: Python 3.10+, Docker (for some agents), nmap (optional)
- OpenRouter API key ([get one here](https://openrouter.ai/keys))

### 🎯 Quick Installation (Recommended)

Use the **interactive installation wizard** for automatic setup:

```bash
# Clone the repository
git clone https://github.com/BugTraceAI/BugTraceAI-CLI
cd BugTraceAI-CLI

# Run the installation wizard
./install.sh
```

The wizard will:

- ✅ Check system requirements automatically
- 🔍 Detect and use free ports for Docker (no conflicts!)
- ⚙️ Set up environment configuration
- 🐳 Build and start Docker containers OR configure local Python environment
- 🎨 Provide beautiful, interactive terminal UI

**Installation Options:**

1. **Local Installation** - Python virtual environment (best for development)
2. **Docker Installation** - Containerized deployment (best for production)

### 📖 Manual Installation

<details>
<summary>Click to expand manual installation instructions</summary>

#### Local Installation

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install browser
playwright install chromium

# Configure environment
cp .env.example .env
# Edit .env and add your OPENROUTER_API_KEY
```

#### Docker Installation

```bash
# Configure environment
cp .env.example .env
# Edit .env and add your OPENROUTER_API_KEY

# Build and start
docker-compose up -d

# View logs
docker-compose logs -f
```

</details>

### Quick Start

```bash
# Full scan
./bugtraceai-cli scan https://target.com

# Clean scan (reset database)
./bugtraceai-cli scan https://target.com --clean

# Resume interrupted scan
./bugtraceai-cli scan https://target.com --resume

# Start API server (for Web UI)
./bugtraceai-cli serve --port 8000
```

**Docker Users:**

```bash
# API is already running at http://localhost:8000
# (or whatever port was auto-selected during installation)

# Execute scans via API or Web UI
curl http://localhost:8000/health
```

## 🤖 AI Assistant Setup (MCP)

BugTraceAI is **MCP-compatible** — control your security scans directly from your AI assistant through natural conversation.

Works with [**OpenClaw**](https://openclaw.com) (Telegram-based AI assistant), **Claude Code**, **Cursor**, and any MCP-compatible client. Deploy once, control from anywhere.

### How It Works

BugTraceAI exposes its scanning engine as **MCP tools** via the [Model Context Protocol](https://modelcontextprotocol.io) — the open standard for connecting AI assistants to external tools. Your AI assistant can start scans, monitor progress, query findings, and retrieve reports — all through chat.

### Quick Setup for AI Agents

> **Using OpenClaw or another AI assistant? Just tell it:**
>
> _Clone https://github.com/BugTraceAI/BugTraceAI-CLI and deploy it with Docker. Copy `.env.example` to `.env` and ask me for the `OPENROUTER_API_KEY`. Run `docker compose up -d` to start both the API and MCP server. Then add the MCP server to your config with base URL `http://localhost:8001/sse`._

### Manual MCP Setup

```bash
# 1. Clone and configure
git clone https://github.com/BugTraceAI/BugTraceAI-CLI
cd BugTraceAI-CLI
cp .env.example .env
# Edit .env → add your OPENROUTER_API_KEY

# 2. Start services (API + MCP)
docker compose up -d

# 3. Verify endpoints
curl -f http://localhost:8000/health   # API health check
curl -sf http://localhost:8001/sse     # MCP SSE endpoint
```

### Connect Your AI Assistant

Add BugTraceAI to your MCP client configuration:

```json
{
  "mcpServers": {
    "bugtraceai": {
      "baseUrl": "http://localhost:8001/sse",
      "description": "BugTraceAI Security Scanner"
    }
  }
}
```

### Available MCP Tools

Once connected, your AI assistant can use these tools:

| Tool              | Description                                           |
| ----------------- | ----------------------------------------------------- |
| `start_scan`      | Start a security scan on a target URL                 |
| `get_scan_status` | Check scan progress and current phase                 |
| `query_findings`  | Retrieve vulnerability findings with filtering        |
| `stop_scan`       | Stop a running scan gracefully                        |
| `export_report`   | Get scan report (summary, critical findings, or full) |

### Prerequisites

- **Docker & Docker Compose** installed and running
- **OpenRouter API key** ([get one here](https://openrouter.ai/keys))
- An MCP-compatible AI assistant ([OpenClaw](https://openclaw.com), Claude Code, Cursor, or any MCP client)

### Ports

| Service | Port | Description                     |
| ------- | ---- | ------------------------------- |
| API     | 8000 | REST API + health check         |
| MCP     | 8001 | SSE transport for AI assistants |

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

AGPL-3.0 License

Copyright (c) 2026 BugTraceAI

See [LICENSE](LICENSE) for details.

---

Made with ❤️ by Albert C. [@yz9yt](https://x.com/yz9yt)

[bugtraceai.com](https://bugtraceai.com)
