# External Integrations

**Analysis Date:** 2026-02-03

## APIs & External Services

**LLM API (OpenRouter):**
- OpenRouter - Multi-model LLM provider
  - Endpoint: `https://api.openrouter.ai`
  - Client: `openai>=1.0.0` (OpenRouter-compatible)
  - Auth: `OPENROUTER_API_KEY` environment variable (format: `sk-or-v1-[64 hex]`)
  - Features: Circuit breaker, fallback models, request throttling (src: `bugtrace/core/llm_client.py`)
  - Default models: google/gemini-3-flash-preview, qwen/qwen-2.5-coder-32b-instruct, x-ai/grok-code-fast-1
  - Health monitoring: Built-in connectivity checks, token balance tracking

**Vulnerability Scanning Tools (Docker-based):**
- Nuclei (ProjectDiscovery) - Tech detection + auto vulnerability scanning
  - Image: `projectdiscovery/nuclei:latest`
  - Runs in Docker container with resource limits (512MB RAM, 1 CPU)
  - Two-phase scan: Phase 1 tech detection (-tags tech), Phase 2 auto scan (-as)
  - Output: JSON lines format
  - Execution: `bugtrace/tools/external.py:ExternalToolManager.run_nuclei()`

- SQLMap - SQL injection detection & exploitation
  - Image: `googlesky/sqlmap:latest`
  - Docker container execution with session persistence
  - Supports technique hints (E/B/U/S/T/Q) for targeted scanning
  - Output parsing for vulnerability confirmation
  - Execution: `bugtrace/tools/external.py:ExternalToolManager.run_sqlmap()`

- GoSpider - Web crawler for URL discovery
  - Image: `trickest/gospider:latest`
  - Discovers URLs from target with depth control
  - Form detection for parameter extraction
  - Execution: `bugtrace/tools/external.py:ExternalToolManager.run_gospider()`

**Data Storage**

**Databases:**
- SQLite
  - Connection: `sqlite:///bugtrace.db` (local file)
  - Client: SQLModel (Pydantic-based ORM)
  - Models: `bugtrace/schemas/db_models.py` (TargetTable, ScanTable, FindingTable, ScanStateTable)
  - Schema management: Alembic migrations in `alembic/` directory
  - Use: Scan history, findings storage, state persistence

- LanceDB (Vector Database)
  - Purpose: Semantic embeddings for finding deduplication & similarity search
  - Location: `logs/lancedb/`
  - Model: BAAI/bge-small-en-v1.5 (384-dimensional embeddings)
  - Client: `lancedb>=0.4.0`
  - Execution: `bugtrace/core/embeddings.py:EmbeddingManager`

**File Storage:**
- Local filesystem only
  - Logs: `logs/` directory (configurable via `LOG_DIR_PATH`)
  - Reports: `reports/` directory (configurable via `REPORT_DIR_PATH`)
  - Tool outputs: Temporary files in `/tmp` during tool execution
  - No cloud storage integration

**Caching:**
- Memory-based queue system
  - Default mode: `QUEUE_PERSISTENCE_MODE=memory` (in-memory queues)
  - Optional Redis support: `QUEUE_REDIS_URL=redis://localhost:6379/0` (not default)
  - Usage: Finding queues, task distribution across agents

## Authentication & Identity

**Auth Provider:**
- None (custom header-based API authentication)
- FastAPI API: No built-in auth (assumes deployment behind auth gateway)
- WebSocket auth: Correlation ID tracking for event subscription
- JWT support: `PyJWT` available for custom implementations in agents

**Secrets Management:**
- Environment variables (.env file)
  - `OPENROUTER_API_KEY` - LLM API access
  - `GLM_API_KEY` - Backup LLM provider (optional)
- Masked secrets: Config export masks API keys (first 8 + last 4 chars visible)
- No secrets manager integration (Vault, AWS Secrets, etc.)

## Monitoring & Observability

**Error Tracking:**
- None (no Sentry, Rollbar, or error aggregation service)
- Errors logged to file and console via Loguru

**Logs:**
- Loguru structured logging
  - Default level: INFO
  - Debug mode: Detailed config logging (`DEBUG=true`)
  - File location: `logs/bugtrace.log` (configurable)
  - Module-based logging: Each component has named logger (`get_logger("module.name")`)
  - Sanitization: Sensitive data (API keys, credentials) redacted from logs

**Observability:**
- OpenTelemetry foundation installed (api + sdk) but not actively used
- Request/response telemetry available via `bugtrace/core/llm_client.py:TokenUsageTracker`
  - Tracks: Token usage per model, cost estimation, request latency
  - Models: Pricing configured for Google Gemini, OpenAI, DeepSeek, and others

## CI/CD & Deployment

**Hosting:**
- FastAPI on Uvicorn (port 8000) - self-hosted
- No cloud platform integration (AWS Lambda, Google Cloud Run, etc.)
- Docker containerization available (`Dockerfile`, `docker-compose.yml`)

**CI Pipeline:**
- None (no GitHub Actions, GitLab CI, etc. configured)
- Local testing: pytest + pytest-asyncio
- Code quality: black, isort, flake8 (manual execution)

**Deployment:**
- Docker Compose for local multi-service setup
- Dockerfile for containerized execution
- Scaling: FastAPI can handle multiple workers via Uvicorn
- No orchestration (Kubernetes, Docker Swarm)

## Webhooks & Callbacks

**Incoming Webhooks:**
- None configured

**Outgoing Webhooks/OOB Callbacks:**
- Interactsh - Out-of-band callback server for blind vulnerability detection
  - Default server: `oast.fun`
  - Supported servers (whitelist): oast.pro, oast.live, oast.site, oast.online, oast.fun, oast.me, interact.sh, interactsh.com
  - Purpose: XSS payload callbacks, SSRF detection, header injection verification
  - Protocol: HTTP/HTTPS
  - Polling: Default 5 minutes, max 10 minutes timeout
  - Client: `bugtrace/tools/interactsh.py:InteractshClient`
  - Configuration: `INTERACTSH_SERVER`, `INTERACTSH_POLL_INTERVAL` (in seconds)

**Event Bus (Internal):**
- Event-driven architecture via `bugtrace/services/event_bus.py`
- Service event bus instance: `service_event_bus`
- Events: vulnerability_detected, work_queued, task_updated, phase_transitioned
- WebSocket subscribers: Real-time client event streaming (src: `bugtrace/api/routes/websocket.py`)

## Browser Automation Integrations

**Playwright (Browser Control):**
- Version: 1.40.0+
- Purpose: Interactive XSS validation, JavaScript execution
- Headless mode: Configurable (`HEADLESS_BROWSER=true/false`)
- Browsers installed: Chromium (default)
- Location: `bugtrace/tools/headless/`
- Features: Cookie injection, form submission, DOM interaction

**Chrome DevTools Protocol (CDP - Preferred for XSS):**
- Direct websocket connection to Chrome debugging port (9222)
- Purpose: More reliable XSS detection than Playwright
  - Console log monitoring (catches all console output)
  - JavaScript execution with return values
  - Screenshot capture
  - Network monitoring
- Implementation: `bugtrace/core/cdp_client.py:CDPClient`
- Configuration: `CDP_ENABLED=true`, `CDP_PORT=9222`, `CDP_TIMEOUT=5.0` seconds
- Advantages: Avoids dialog event race conditions, direct access to runtime

## External Tool Integration Configuration

**Docker Image Whitelist (Security):**
- Trusted images: projectdiscovery/nuclei, googlesky/sqlmap, trickest/gospider
- Validation: `bugtrace/tools/external.py:_validate_docker_image()`
- Network mode: `bridge` (isolated, no host network access)
- Resource constraints:
  - Memory: 512MB per container
  - CPU: 1 core per container
  - Temp FS: 100MB for scratch space
  - PID limit: 100 max processes

**Output Sanitization:**
- ANSI escape code removal
- Control character filtering
- JSON depth validation (max 20 levels)
- Size limits: 10MB max output per tool

## Vision/Image Analysis

**Vision Models (Optional):**
- Qwen VL - Vision language model for screenshot analysis
  - Model: `qwen/qwen3-vl-8b-thinking`
  - Purpose: XSS validation via visual inspection
  - Configuration: `VALIDATION_VISION_MODEL`, `VALIDATION_VISION_ENABLED`
  - Limit: Max 3 vision calls per URL

**Screenshot Capture:**
- Via CDP client (native Chrome capability)
- Purpose: Evidence collection for findings

## Analysis & Reporting

**Tech Stack Detection:**
- Nuclei templates (via Nuclei scanning)
- WhatRuns patterns (if integrated)
- Evidence extraction: `bugtrace/agents/reporting.py:_nuclei_extract_tech_stack()`

**Report Generation:**
- Template engine: Jinja2 3.1.0+
- Markdown rendering: markdown 3.5.0+
- Output formats: JSON, HTML (via templates)
- Location: `bugtrace/reporting/generator.py`

## Rate Limiting & Throttling

**Global Rate Limiting (Manipulator System):**
- Component: `bugtrace/tools/manipulator/global_rate_limiter.py`
- Config: `MANIPULATOR_GLOBAL_RATE_LIMIT=2.0` (req/s across XSS/CSTI payloads)
- Purpose: Prevent WAF triggers during intelligent payload mutation

**OpenRouter API Throttling:**
- Circuit breaker: CB_FAILURE_THRESHOLD=3 (opens after 3 consecutive failures)
- Degraded mode: 2-second delay between requests when API is unstable
- Recovery: CB_COOLDOWN_SECONDS=60, CB_SUCCESS_THRESHOLD=2 successes to recover
- Timeout: LLM_TOTAL_TIMEOUT=90s, LLM_CONNECT_TIMEOUT=10s

**Queue Rate Limiting:**
- `QUEUE_DEFAULT_RATE_LIMIT=100.0` items/second per queue
- Per-phase concurrency: MAX_CONCURRENT_SPECIALISTS, MAX_CONCURRENT_ANALYSIS, etc.

---

*Integration audit: 2026-02-03*
