# BugtraceAI-CLI 🛡️🤖

**Autonomous Offensive Security Framework v1.2.0**
*Powered by Visual "Thinking" Intelligence, Multi-Agent Orchestration, and Strategy Shifting.*

BugtraceAI-CLI is a next-generation offensive security tool designed to think, see, and adapt like a professional pentester. It moves beyond simple pattern matching into deep, LLM-driven reasoning for vulnerability discovery and exploitatiaon.

## 🚀 Key Features

* **Multi-Agent Team Orchestration**:
  * `Recon Agent`: Deep visual discovery and asset mapping.
  * `Exploit Agent`: Strategy Shifting and mutant payload generation.
  * `Skeptical Agent`: Visual verification of findings to eliminate false positives.
* **Thinking Visual Intelligence**: Uses `Qwen 3 VL` and Thinking Models to analyze screenshots, identify attack surfaces, and confirm XSS triggers.
* **Intelligence Shifting**: Dynamic fallback through a tiered list of high-performance models:
  * `Gemini 2.0 Thinking` (Planning)
  * `Grok-Code` / `Qwen 2.5 Coder` (Bypass Generation)
  * `DeepSeek` / `Claude 3.5 Haiku` (WAF Analysis)
* **Real-time Dashboard**: Dynamic terminal UI built with `Rich` featuring:
  * **Live Engagement Panel**: Track active payloads and URLs in real-time.
  * **Agent "Thoughts"**: See the reasoning process behind every action.
* **Professional HTML Reporting**: Automatic generation of executive and technical reports in `/reports`.
* **Diagnostic Suite**: Auto-health checks for Docker (Nuclei/SQLMap), API connectivity, and Visual Browser status.

## 🛠️ Installation

```bash
# 1. Clone the repo
git clone https://github.com/your-org/bugtrace-cli
cd bugtrace-cli

# 2. Setup environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium

# 3. Configure
cp .env.example .env
# REQUIRED: Add OPENROUTER_API_KEY to .env for AI features
```

## 💻 Usage

> **📖 READ THE QUICKSTART GUIDE FIRST:** [.ai-context/QUICKSTART_GUIDE.md](.ai-context/QUICKSTART_GUIDE.md)

### Standard Scan

```bash
# Scan a target (Asset Discovery -> Vulnerability Hunting -> Validation)
./bugtraceai-cli "https://ginandjuice.shop"
```

### Resume / Validate Only

```bash
# Resume validation for existing findings in DB
./bugtraceai-cli audit "https://ginandjuice.shop"
```

### Targeted Single URL Scan

1. Edit `bugtraceaicli.conf`: Set `MAX_URLS = 1`
2. Run: `./bugtraceai-cli "https://ginandjuice.shop/catalog?category=vulnerable"`

## 📊 Observability

* **Audit Journal**: `logs/llm_audit.jsonl` - Every prompt and AI response is logged for transparency.
* **Execution Logs**: `logs/bugtrace.jsonl` - Detailed process logging.
* **Visual Evidence**: Screenshots of confirmed vulnerabilities saved automatically.
* **Final Reports**: Check the `/reports` folder after a scan is complete.

## 🏗️ Architecture (v1.2)

1. **TeamOrchestrator**: Asynchronously coordinates specialized agents.
2. **LLMClient**: High-performance multi-model gateway with automatic fallback (Shift).
3. **Memory Manager (GraphRAG)**: Combines NetworkX (Knowledge Graph) with LanceDB (Vector) for long-term intelligence.
4. **Diagnostic System**: Ensures the environment is ready for industrial-grade pentesting.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Usage against targets without prior mutual consent is illegal. The developers assume no liability for misuse.
