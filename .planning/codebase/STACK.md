# Technology Stack

**Analysis Date:** 2026-02-03

## Languages

**Primary:**
- Python 3.12 - Full codebase implementation, CLI tool, agents, API server
- Go - Fast fuzzer binaries for XSS/SSRF/LFI/IDOR detection (bridged via `bugtrace/tools/go_bridge.py`)

**Secondary:**
- JavaScript/TypeScript - Frontend application (separate WEB submodule)

## Runtime

**Environment:**
- Python 3.12 (specified in pyproject.toml)
- Docker - External tool execution (Nuclei, SQLMap, GoSpider)

**Package Manager:**
- `pip` (via setuptools/pyproject.toml)
- Lockfile: `pyproject.toml` (uses setuptools build system, no poetry.lock)

## Frameworks

**Core CLI:**
- Typer 0.9.0+ - Command-line interface framework (src: `bugtrace/__main__.py`)

**API Server:**
- FastAPI - REST API (src: `bugtrace/api/main.py`, runs on port 8000)
- Uvicorn - ASGI server for FastAPI
- WebSockets - Real-time event streaming (src: `bugtrace/api/routes/websocket.py`)

**Browser Automation:**
- Playwright 1.40.0+ - Browser control for XSS validation (src: `bugtrace/tools/headless/`)
- Chrome DevTools Protocol (CDP) - Direct XSS validation via Chrome (src: `bugtrace/core/cdp_client.py`)

**Testing:**
- pytest - Unit tests
- pytest-asyncio - Async test support

**Code Quality:**
- black - Code formatting
- isort - Import sorting
- flake8 - Linting

## Key Dependencies

**Critical - LLM Integration:**
- OpenAI 1.0.0+ - OpenRouter API compatibility (src: `bugtrace/core/llm_client.py`)
- OpenRouter - Multi-model LLM provider with circuit breaker, fallback support

**Critical - Data & Storage:**
- SQLModel - ORM for SQLite database (src: `bugtrace/core/database.py`)
- SQLAlchemy - SQL toolkit for database operations
- LanceDB 0.4.0+ - Vector database for semantic embeddings (src: `bugtrace/core/embeddings.py`)
- Sentence-transformers - Embedding model (BAAI/bge-small-en-v1.5, 384-dim)

**Critical - Configuration:**
- Pydantic 2.0.0+ - Data validation
- Pydantic-settings 2.0.0+ - Configuration management (src: `bugtrace/core/config.py`)
- python-dotenv 1.0.0+ - .env file loading

**Infrastructure:**
- httpx 0.25.0+ - Async HTTP client (src: `bugtrace/core/llm_client.py`, payload delivery)
- aiohttp 3.9.0+ - Async HTTP for CDP websocket, external tool communication
- aiofiles 23.0.0+ - Async file I/O
- tenacity - Retry logic with exponential backoff (src: `bugtrace/core/database.py`, `bugtrace/core/llm_client.py`)

**UI & Reporting:**
- Rich 13.0.0+ - Terminal UI formatting (src: `bugtrace/core/ui.py`, dashboard output)
- Jinja2 3.1.0+ - Report template rendering
- Markdown 3.5.0+ - Report generation
- PyYAML - Configuration parsing
- BeautifulSoup4 - HTML parsing (form extraction)

**Security & Validation:**
- PyJWT - JWT token handling
- Cryptography - SSL/certificate handling
- NetworkX - Dependency graph analysis

**Observability:**
- Loguru 0.7.0+ - Structured logging (src: `bugtrace/utils/logger.py`)
- OpenTelemetry API - Distributed tracing foundation (installed, not actively used in v1.6)
- OpenTelemetry SDK - Tracing implementation

**External Tool Support:**
- sqlparse 0.4.4+ - SQL parsing for SQLi detection
- filelock - File-based locking for concurrent access

**ML/AI:**
- torch (CPU) - PyTorch CPU-only install (lightweight)
- sentence_transformers - Semantic embeddings

**Development:**
- google-generativeai - Optional Gemini API support (fallback)
- psutil - Process/resource monitoring
- websockets - WebSocket protocol implementation

## Configuration

**Environment Variables (.env):**
- `OPENROUTER_API_KEY` - OpenRouter API key (REQUIRED, validated format: sk-or-v1-[64 hex])
- `GLM_API_KEY` - Backup LLM provider (optional)
- `BUGTRACE_CORS_ORIGINS` - CORS allowed origins (default: `http://localhost:3000,http://localhost:5173`)
- `BUGTRACE_WATCH_CONFIG` - Enable config hot-reload (1/true to enable)

**Configuration File (bugtraceaicli.conf):**
- INI format with sections:
  - `[LLM_MODELS]` - Model selections and concurrency
  - `[PARALLELIZATION]` - Phase-specific concurrency limits
  - `[SCAN]` - Scanning behavior (depth, URLs, timeouts)
  - `[ANALYSIS]` - Analysis thresholds and models
  - `[THINKING]` - Consolidation agent configuration
  - `[AUTHORITY]` - Self-validation thresholds
  - `[CRAWLER]` - URL filtering patterns
  - `[SCANNER]` - WAF detection, critical type definitions
  - `[PATHS]` - Custom log/report directories
  - `[URL_PRIORITIZATION]` - URL scoring configuration
  - `[ADVANCED]` - Tracing, OAST servers, optimization flags

**Database Configuration:**
- SQLite: `sqlite:///bugtrace.db` (default, local file)
- Vector DB: LanceDB at `logs/lancedb/` (auto-created)

## Build & Runtime Configuration

**Build:**
- Build system: setuptools (PEP 517/518 compliant)
- Entry point: `bugtrace = "bugtrace.__main__:app"` (CLI via Typer)
- No native extensions (pure Python + Docker dependencies)

**Docker Support:**
- `Dockerfile` - CLI containerization (defines image for external tool execution)
- `docker-compose.yml` - Multi-service orchestration

**Alembic Migrations:**
- Location: `alembic/` directory
- Config: `alembic.ini`
- Purpose: Database schema versioning

## Platform Requirements

**Development:**
- Python 3.12+
- Docker daemon (for external tool execution: Nuclei, SQLMap, GoSpider)
- Chrome/Chromium binary (for headless browser testing)
- Port 8000 - FastAPI server
- Port 9222 - Chrome DevTools Protocol (CDP) remote debugging port
- Port 5173 - Vite dev server (frontend, when running integrated)

**Production:**
- Python 3.12+ runtime
- Docker (essential for Nuclei/SQLMap/GoSpider)
- Chrome/Chromium with debugging enabled
- HTTP/HTTPS network access to:
  - OpenRouter API (openrouter.ai)
  - OAST servers (oast.fun, oast.pro, etc.)
  - Target web applications

**Resource Constraints:**
- RAM: 2GB minimum (4GB+ recommended for concurrent scans)
- Disk: Vector DB + logs can grow; `logs/` should be monitored
- Network: Unrestricted outbound for API calls, payloads, tool communication

---

*Stack analysis: 2026-02-03*
