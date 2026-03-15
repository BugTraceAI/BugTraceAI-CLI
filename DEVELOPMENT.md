# 🛠️ Development Guide - BugTraceAI-CLI

This guide covers local development setup, debugging, contributing code, and running tests for BugTraceAI-CLI.

## Table of Contents

- [Quick Start](#quick-start)
- [Development Environment](#development-environment)
- [Running Locally](#running-locally)
- [Debugging](#debugging)
- [Testing](#testing)
- [Contributing](#contributing)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### Prerequisites
- Python 3.10+
- Docker (for GoSpider, SQLMap, Nuclei integration)
- Git

### Clone & Setup (5 minutes)

```bash
# Clone repository
git clone https://github.com/BugTraceAI/BugTraceAI-CLI.git
cd BugTraceAI-CLI

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies (dev mode)
pip install -e ".[dev]"
pip install pytest pytest-asyncio pytest-cov black isort flake8

# Install Playwright browsers
playwright install chromium

# Copy env template and configure
cp .env.example .env
# Edit .env and add your OPENROUTER_API_KEY
nano .env
```

**Verify setup:**
```bash
python -m bugtrace --help
python3 -c "from bugtrace import __version__; print(f'✓ Version: {__version__}')"
```

---

## Development Environment

### IDE Setup (VS Code)

**Recommended Extensions:**
```
ms-python.python              # Python
ms-python.vscode-pylance      # Type checking
ms-python.black-formatter     # Code formatting
charliermarsh.ruff            # Linting
eamodio.gitlens               # Git history
```

**Workspace Settings** (`.vscode/settings.json`):
```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
  "python.formatting.provider": "black",
  "[python]": {
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
      "source.organizeImports": "explicit"
    }
  }
}
```

### Code Quality Tools

**Format code (Black):**
```bash
black bugtrace tests --line-length 120
```

**Sort imports (isort):**
```bash
isort bugtrace tests
```

**Lint (Flake8):**
```bash
flake8 bugtrace --max-line-length=120 --ignore=E501,W503
```

**All-in-one (recommended):**
```bash
black bugtrace tests && isort bugtrace tests && flake8 bugtrace
```

---

## Running Locally

### CLI Mode (No API)

```bash
# Activate venv
source .venv/bin/activate

# Scan a target (hunter phase only)
python -m bugtrace scan https://example.com

# Full scan (hunter + auditor)
python -m bugtrace full https://example.com

# XSS-focused mode
python -m bugtrace scan https://example.com --xss

# With URL list
python -m bugtrace scan --url-list-file urls.txt

# Resume previous scan
python -m bugtrace scan https://example.com --resume

# Clean previous state and restart
python -m bugtrace scan https://example.com --clean
```

### API Server Mode (Development)

```bash
# Start API on http://localhost:8000
python -m bugtrace serve --host 127.0.0.1 --port 8000

# Auto-reload on code changes (development)
python -m bugtrace serve --reload

# Bind to all interfaces (LAN access)
python -m bugtrace serve --host 0.0.0.0 --port 8000

# Access SwaggerUI
open http://localhost:8000/docs

# Access ReDoc
open http://localhost:8000/redoc
```

### MCP Server Mode (Claude/Cursor Integration)

```bash
# STDIO transport (local Claude/Cursor only)
python -m bugtrace mcp

# SSE transport (remote AI clients, network access)
python -m bugtrace mcp --sse --host 0.0.0.0 --port 8001
```

### Terminal UI (Interactive Dashboard)

```bash
# Launch TUI without target
python -m bugtrace tui

# Launch TUI and start scanning
python -m bugtrace tui https://example.com

# Demo mode (animated fake data for testing UI)
python -m bugtrace tui --demo
```

---

## Debugging

### Enable Debug Logs

```bash
# Set DEBUG=true in .env or export
export BUGTRACE_DEBUG=1
python -m bugtrace scan https://example.com

# Or modify .env
echo "DEBUG=true" >> .env
```

### Log Files

```bash
# CLI logs
tail -f logs/cli.log

# API logs
tail -f logs/api.log

# All agent activity
tail -f logs/agents.log

# Database operations
tail -f logs/database.log
```

### Python Debugger (pdb)

**Add breakpoint in code:**
```python
# In bugtrace/agents/xss_agent.py
def analyze_url(self, url):
    breakpoint()  # Execution will pause here
    # ... rest of function
```

**Run with debugger:**
```bash
python -m bugtrace scan https://example.com
# At breakpoint, use:
#   n (next line)
#   s (step into)
#   c (continue)
#   p variable_name (print)
#   l (list code)
```

### Database Inspection

```bash
# Connect to SQLite database
sqlite3 bugtrace.db

# List tables
.tables

# Inspect scans
SELECT id, status, target, created_at FROM scan ORDER BY id DESC LIMIT 5;

# View findings for a scan
SELECT scan_id, url, vuln_type, severity FROM finding WHERE scan_id=1;

# Export findings as CSV
.mode csv
.output findings.csv
SELECT * FROM finding;
.quit
```

### API Request Debugging

```bash
# Monitor real-time events via WebSocket
wscat -c ws://localhost:8000/ws/global

# Test specific endpoint with curl
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url":"https://example.com"}' | jq .

# Check API health
curl http://localhost:8000/health | jq .

# Get scan status
curl http://localhost:8000/api/scans/1/status | jq .
```

---

## Testing

### Run Test Suite

```bash
# All tests
pytest tests/ -v

# Specific test file
pytest tests/test_bugtrace_sanity.py -v

# Specific test function
pytest tests/test_xss_agent.py::TestXSSAgent::test_payload_execution -v

# With coverage report
pytest tests/ --cov=bugtrace --cov-report=html

# Fast tests only (skip integration)
pytest tests/ -m "not integration" -v

# Test a specific agent
pytest tests/ -k "xss" -v
```

### Unit vs Integration Tests

**Unit tests** (fast, no external deps):
```bash
pytest tests/unit/ -v
```

**Integration tests** (require Docker, full setup):
```bash
pytest tests/integration/ -v
```

**Agent-specific smoke tests:**
```bash
pytest tests/test_integration_new_agents.py -v
```

### Write New Tests

**Template for agent tests:**
```python
# tests/test_my_agent.py
import pytest
from bugtrace.agents.my_agent import MyAgent
from bugtrace.services.event_bus import ServiceEventBus

@pytest.fixture
def agent():
    event_bus = ServiceEventBus()
    return MyAgent(event_bus=event_bus)

def test_agent_initialization(agent):
    assert agent.name == "MyAgent"
    assert agent.event_bus is not None

@pytest.mark.asyncio
async def test_agent_analyze(agent):
    result = await agent.analyze(url="https://example.com", param="test")
    assert result is not None
```

**Run your new test:**
```bash
pytest tests/test_my_agent.py -v
```

---

## Contributing

### Branch Workflow

```bash
# Update main
git checkout main
git pull origin main

# Create feature branch
git checkout -b feature/my-feature

# Make changes and commit
git add bugtrace/agents/my_agent.py
git commit -m "feat(agents): add MyAgent for new vulnerability type"

# Push and create PR
git push origin feature/my-feature
```

### Commit Message Format

Format: `<type>(<scope>): <subject>`

**Types:**
- `feat:` New feature or agent
- `fix:` Bug fix
- `refactor:` Code restructuring (no functional change)
- `docs:` Documentation
- `test:` New tests
- `chore:` Dependencies, CI/CD setup

**Examples:**
```
feat(agents): add JWTAgent for JWT vulnerabilities
fix(api): handle concurrent scan limit correctly
refactor(core): improve queue performance
docs(setup): add local development guide
test(xss): add edge case payloads
```

### PR Checklist

Before submitting PR:
- [ ] Code passes linting: `black bugtrace && isort bugtrace && flake8 bugtrace`
- [ ] Tests pass: `pytest tests/ -q`
- [ ] New code is tested (add corresponding test file)
- [ ] Commit messages follow format
- [ ] README/DEVELOPMENT.md updated if needed
- [ ] No API keys or secrets in commits (use .env)

---

## Troubleshooting

### Issue: Import errors after code changes

```bash
# Clear Python cache
find . -type d -name __pycache__ -exec rm -r {} + 2>/dev/null
find . -type f -name "*.pyc" -delete

# Reinstall in dev mode
pip install -e .
```

### Issue: Playwright browser not found

```bash
# Reinstall Playwright
python -m pip uninstall playwright
playwright install chromium
playwright install-deps chromium
```

### Issue: Port 8000 already in use

```bash
# Find process on port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>

# Or use different port
python -m bugtrace serve --port 8001
```

### Issue: Database locked

```bash
# Remove stale database
rm bugtrace.db bugtrace.db-shm bugtrace.db-wal

# Restart
python -m bugtrace scan https://example.com
```

### Issue: Slow agent execution

**Check for parallelization:**
```python
# In bugtrace/core/config.py
WORKER_POOL_DEFAULT_SIZE: int = 5  # Increase for more parallelism
MAX_CONCURRENT_SPECIALISTS: int = 10  # Adjust concurrency
```

**Profile execution:**
```bash
python -m cProfile -s cumtime -m bugtrace scan https://example.com 2>&1 | head -20
```

### Issue: LLM API errors

```bash
# Verify API key
python -c "from bugtrace.core.config import settings; \
           print(f'Provider: {settings.PROVIDER}'); \
           print(f'API Key set: {bool(settings.OPENROUTER_API_KEY)}')"

# Test connectivity
python -c "from bugtrace.core.llm_client import llm_client; \
           import asyncio; \
           asyncio.run(llm_client.verify_connectivity())"
```

---

## Resources

- **API Docs**: http://localhost:8000/docs (when API running)
- **OpenAPI Spec**: [openapi.yaml](openapi.yaml)
- **Configuration**: [bugtrace/core/config.py](bugtrace/core/config.py)
- **Architecture**: [BugTraceAI/README.md](../BugTraceAI/README.md)
- **Issues**: [GitHub Issues](https://github.com/BugTraceAI/BugTraceAI-CLI/issues)

---

## Questions?

- Check existing issues: https://github.com/BugTraceAI/BugTraceAI-CLI/issues
- Review logs: `tail -f logs/*.log`
- Test setup: `python -m pytest tests/test_bugtrace_sanity.py -v`

Happy hacking! 🔓
