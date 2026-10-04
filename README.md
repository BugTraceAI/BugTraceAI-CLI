# BugTraceAI-CLI

[![Website](https://img.shields.io/badge/Website-bugtraceai.com-blue?logo=google-chrome&logoColor=white)](https://bugtraceai.com)
[![Wiki Documentation](https://img.shields.io/badge/Wiki%20Documentation-000?logo=wikipedia&logoColor=white)](https://deepwiki.com/BugTraceAI/BugTraceAI-CLI)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/BugTraceAI/BugTraceAI-CLI)
![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)
![Version](https://img.shields.io/badge/Version-4.0.16--beta-orange)
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
- [Install with your AI coding agent](#install-with-your-ai-coding-agent)
- [🤖 AI Assistant Setup (MCP)](#-ai-assistant-setup-mcp)
- [⚙️ Configuration](#️-configuration)
- [📊 Output](#-output)
- [📜 License](#-license)

---

> 🏆 **The First Agentic Framework Intelligently Designed for Bug Bounty Hunting**

BugTraceAI-CLI is an autonomous offensive security framework that combines LLM-driven analysis with deterministic exploitation tools. Unlike passive analysis tools, BugTraceAI-CLI actively exploits vulnerabilities using real payloads, SQLMap integration, and browser-based validation to deliver confirmed, actionable findings.

The core philosophy is **"Think like a pentester, execute like a machine, validate like an auditor"** - using AI for intelligent hypothesis generation, but relying on real tools for exploitation and validation.

## Terminal workspace (v4.0.16-beta)

Launch the interactive workspace from this checkout:

```bash
./bugtraceai-cli
```

Enter your target in the top panel, choose **Depth** (1–10) and **Max URLs**
(1–5000), then press **Start**. Defaults come from your CLI configuration. You
can also open a complete scan directly. The TUI always runs the full pipeline:

```bash
./bugtraceai-cli full https://target.example
```

The real scanner uses the same purple/coral pipeline view as the preview, with
five focused tabs: **Pipeline → Findings → Agents → Timeline → Logs**.
Inspect six stages and their timings, browse evidence, follow specialist queues,
review scan milestones, or search engine logs. Runtime details expand inside
Agents; pause/stop controls remain available above. Use **Provider** (F7) to select a provider and enter a masked API key before
starting a real scan. Keys stay in the session unless you select Save in .env.
Use **Auth** (F8 or `/auth`) for the target website: paste a masked **Bearer token**
or load a **login YAML** using the WEB/CLI schema, including optional TOTP/2FA.
Apply validates and loads a snapshot for subsequent scans in this TUI session;
credentials are not saved by the TUI. Reapply the YAML to reload edits. Selecting
None removes supplied Authorization/Cookie headers and login settings while
keeping other custom headers. Authentication is editable before a scan or after
it ends. In Docker, the YAML path must be accessible inside the container.
`./bugtraceai-cli tui --demo` is the optional offline
preview with sample data. Redirected commands continue to produce ordinary text.
See [installation and terminal controls](INSTALLATION.md).

## Engine highlights

- **Anthropic direct-API provider**: Anthropic is now a first-class LLM provider using an API key (`x-api-key`, Messages API), selectable via the `anthropic` preset. A new `api_format` preset field decouples the wire format from the OAuth path, so `generate`, threaded generation, vision, and connectivity all route to the Anthropic Messages API when active. Existing OpenRouter/Z.ai behaviour is unchanged.
- **Integrated Model Lab (model-eval)**: benchmark and compare OpenRouter models from BugTraceAI-WEB through the CLI API (`/api/model-eval`, `/api/model-eval/models`, `/api/model-eval/test-key`) with a per-request OpenRouter key, live WebSocket progress, cost visibility, and a key-validation check before a run. The recalibration adds a quality-dominant composite (median latency as a side axis), per-slot leaderboards (MUTATION / SKEPTICAL / ANALYSIS / REPORTING), the `quick-v3` / `advanced-v2` suites, and an opt-in MUTATION payload-diversity probe.
- **Reporting/enrichment failover**: when a PoC or CVSS enrichment call on the active provider fails or degrades (circuit-breaker fallback, timeout, saturation), the reporting layer falls back to a secondary provider for that single enrichment call only — it never changes the scan's active provider. Configurable via `REPORTING_FAILOVER_ENABLED` / `REPORTING_FAILOVER_PROVIDER` (default: Anthropic), with provenance telemetry (`poc_enrichment_provenance`, `reporting_failover_count`) so reporting saturation is visible in the deliverable instead of silently degrading.
- **Deliverable parity for pending findings**: pending (POTENTIAL) findings now appear in `validated_findings.json`, and the "Findings by Severity" totals plus manual-review ordering match across the Markdown, JSON, and HTML deliverables.
- **Detection & dedup fixes**: a command injection detected two ways on the same endpoint no longer double-counts as two CRITICALs, a genuine IDOR with strong evidence routes to MANUAL_REVIEW instead of being buried in PENDING, and boolean-blind SQLi response diffing is capped and offloaded off the event loop to prevent stalls on large/hostile pages.
- **Visible authentication discovery**: live scan events now report AuthDiscovery start, per-URL progress, and JWT/cookie totals.
- **Bounded JavaScript endpoint mining**: first-party scripts are mined for API endpoints under strict count, size, timeout, and origin limits while `.js` assets remain excluded from normal DAST targets.
- **Decoupled CDP validation stage**: an `AgenticValidator` Phase-5 stage confirms browser-executed findings (XSS/CSTI/SSTI) over the Chrome DevTools Protocol as a real pipeline stage.
- **Sharper detection, fewer false positives**: multi-round false-positive discipline across all specialists — SQLi error-based and mass-assignment now require a real differential (not mere reflection), and confirmation relies on genuine error/behavioral signatures instead of static content.
- **Higher-fidelity reports**: confirmed findings are never silently dropped, evidence panels are populated, CVSS/severity/impact are made consistent, and a reproduction `curl` is synthesized only for genuine injection findings.
- **Broader coverage**: revived Out-of-Band (interactsh) confirmation for blind SSRF/XXE/RCE/SSTI, generic stored-XSS and POST-only XXE endpoint discovery, cookie-based SQLi, and reliable reflected-DOM XSS.
- **Target-agnostic**: removed the last practice-target-specific hardcoded values so detection generalizes to any target.
- **YAML Authentication + TOTP**: `--auth-config` loads login flows, credentials, environment-variable substitutions, and optional TOTP/2FA secrets for authenticated scans.
- **Scan Resumption**: `--resume` and recoverable scan state tracking allow interrupted scans to continue without losing context or duplicating completed work.

> **Local beta:** keep the CLI API on your machine or a trusted LAN. Do not expose it directly to the Internet. Model Lab uses your configured OpenRouter API key and provider charges may apply.

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

Real tools, real payloads, real results — 15 autonomous specialist agents:

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
| 📤 **FileUploadAgent**         | Unrestricted File Upload              | Extension/content-type bypass, path-based write to RCE            |

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

- 🔀 **LLM Shifting**: Automatic fallback through model tiers (Qwen primary → DeepSeek → Claude → Gemini)
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
│  │  GoSpider  │   │ DASTySAST  │   │ ThinkingAg.│   │ 15 Agents  │   │
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
- **AI Providers**: OpenRouter (Gemini, Claude, DeepSeek, Qwen), Anthropic (direct API — `x-api-key` / Messages API), and Z.ai
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

**Installation choices:**

First choose **TUI**, **API + MCP**, or **both**. Then choose **local Python** or **Docker**. The engine is shared; Textual is installed for TUI, FastAPI/Uvicorn/WebSockets/MCP for API. Docker TUI builds an interactive scanner container without starting a server or publishing ports.

```bash
./install.sh --interface tui --runtime local
./install.sh --interface api --runtime docker
./install.sh --interface both --runtime docker
./install.sh --reuse  # update/repair using the saved selection
```

Choices are stored in `.bugtrace-install.env`, without API keys. Existing environments retain previously installed packages; changing profiles does not remove them automatically.

Start local TUI with `./bugtraceai-cli tui`, local API with `./bugtraceai-cli serve`, Docker TUI with `docker compose -f docker-compose.tui.yml run --rm scanner`, or TUI in a combined deployment with `docker compose exec api python3 -m bugtrace tui`.

### Install with your AI coding agent

Copy this prompt into an agent with terminal access, such as Claude Code,
Cursor or Codex. The default installs the real TUI and a global `btai` command
on Linux/macOS. To deploy a server instead, change the first line to specify
**API + MCP** or **both**, and **local** or **Docker**.

```text
Install the current public BugTraceAI-CLI 4.x on this machine: local TUI,
with the user-global btai command. Perform the installation, not just a plan.

Check the OS, Python version and available tools. Read README.md,
INSTALLATION.md and ./install.sh --help from
https://github.com/BugTraceAI/BugTraceAI-CLI.git before installing.

Clone into a suitable user-owned directory. If an installation already exists,
preserve its configuration, credentials and uncommitted changes. Reuse its
saved profile with ./install.sh --reuse unless I request a profile change.
Do not replace an existing checkout or change its repository/branch silently.

For a fresh local TUI installation, run:
./install.sh --interface tui --runtime local --global yes
If I request API + MCP or both, use --interface api or both and my selected
--runtime local or docker. Use --global no for API-only installations.
Handle the installer's prompts, install the required dependencies and resolve
setup errors using the repository instructions. Do not switch runtime without
asking. Keep any system privilege/password prompt in my local terminal.

I will configure the LLM key later through Provider/F7 in the TUI; do not ask
me to paste credentials into chat or print existing secrets. Target login
credentials are configured separately through Auth/F8.

Verify the installed version, saved profile and selected interface. For TUI,
check startup and quit in an interactive terminal if available; otherwise
verify imports and report that the visual check is still pending. When requested, verify btai
registration and PATH in a fresh shell. For an API installation, check /health
using the actual configured port. Do not start a scan as part of installation.

Finish with the installation directory, selected profile, verification results
and exact commands to open the TUI or API. Tell me whether a new terminal is
needed for btai.
```

See [INSTALLATION.md](INSTALLATION.md) for profiles, Provider/F7, Auth/F8 and
troubleshooting. Installation does not require running a scan.

### 📖 Manual Installation

<details>
<summary>Click to expand manual installation instructions</summary>

#### Local Installation

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[tui]"  # use .[api] or .[tui,api] for server support

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

# Authenticated scan (YAML config with optional TOTP)
./bugtraceai-cli scan https://target.com --auth-config auth_config.yaml

# Start API server (for Web UI)
./bugtraceai-cli serve --port 8000

# Open ModelLab from BugTraceAI-WEB after starting the API
# /bugtraceai/modellab
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

Use the [agent installation prompt](#install-with-your-ai-coding-agent),
changing its first line to: **Install BugTraceAI-CLI with API + MCP using Docker,
without the global TUI command.** The installer command for that profile is
`./install.sh --interface api --runtime docker --global no`.

After setup, connect your MCP client to `http://localhost:<MCP_PORT>/sse` using
the actual port reported by the installer (default 8001). Configure the provider
key locally in `.env` before scanning; keep it out of chat and client configs.

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
| `explain_finding` | Get detailed explanation and remediation for a finding|

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
DEFAULT_MODEL = qwen/qwen3-coder
SKEPTICAL_MODEL = anthropic/claude-haiku-4.5
VISION_MODEL = google/gemini-3-flash-preview
```

### Authenticated Scanning (YAML + TOTP/2FA)

BugTraceAI-CLI supports authenticated scans via a YAML configuration file. This enables scanning login-protected applications with optional TOTP (Time-Based One-Time Password) token generation.

**`auth_config.yaml` example:**

```yaml
login_url: https://target.com/login
username: pentester@example.com
password: your_password_here
totp_secret: BASE32TOTPSECRETHERE   # optional — for 2FA/TOTP protected logins
success_condition: "Welcome"        # string that confirms successful login
```

**Usage:**

```bash
./bugtraceai-cli scan https://target.com --auth-config auth_config.yaml
```

The scanner will:
1. Navigate to `login_url`
2. Fill in credentials automatically
3. Generate a TOTP token in real-time if `totp_secret` is provided
4. Confirm login success via `success_condition`
5. Reuse the authenticated session across all scan phases

> The `auth_config.yaml` file is automatically included in the report download ZIP for audit traceability.

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

Apache-2.0 License. See [LICENSE](LICENSE).

Copyright (c) 2026 BugTraceAI

See [LICENSE](LICENSE) for details.

---

Made with ❤️ by Albert C. [@yz9yt](https://x.com/yz9yt)

[bugtraceai.com](https://bugtraceai.com)

### Global terminal command (macOS / Linux)

After choosing TUI or both and local or Docker, the installer asks whether to install **`btai`** for the current user. It creates `~/.local/bin/btai` without sudo and adds that directory to Bash/Zsh's startup PATH if needed. Open a new terminal, then run `btai` from any folder to open the real TUI. `btai --demo` explicitly opens the preview.

The command targets the selected checkout and local/Docker profile. Keep the checkout at that path, or run the installer again after moving it. API-only installs do not offer the TUI command. An unrelated existing `btai` file is preserved.

```bash
./install.sh --interface tui --runtime local --global yes
./install.sh --reuse  # also remembers the global command choice
# Register the command for an already installed profile, without reinstalling:
./install.sh --interface both --runtime docker --global yes --global-only
```
