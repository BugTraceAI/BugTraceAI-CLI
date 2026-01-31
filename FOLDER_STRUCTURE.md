# BugTraceAI-CLI Folder Structure

## Overview

BugTraceAI-CLI is a multi-agent security scanning framework that detects web application vulnerabilities using a combination of SAST, DAST, and AI-powered analysis. The codebase is organized into clear functional modules to support maintainability and extensibility.

## Directory Structure

```
BugTraceAI-CLI/
├── bugtrace/                  # Main source code
│   ├── agents/                # Vulnerability detection agents
│   ├── api/                   # FastAPI REST API
│   ├── core/                  # Core orchestration and models
│   ├── mcp/                   # Model Context Protocol server
│   ├── memory/                # Database and state management
│   ├── reporting/             # Report generation (JSON, HTML, MD)
│   ├── schemas/               # Pydantic schemas and data models
│   ├── services/              # Business logic services
│   ├── skills/                # Agent skills and capabilities
│   ├── tools/                 # Utility tools and helpers
│   └── utils/                 # Shared utilities
├── bin/                       # Go fuzzer binaries
├── docs/                      # Documentation
│   ├── agents/                # Agent-specific documentation
│   └── architecture/          # Architecture diagrams and docs
├── lab/                       # Vulnerable test applications
├── protocol/                  # Protocol definitions
├── testing/                   # Testing utilities
├── tests/                     # Test suite
├── tools/                     # External tool integrations
├── .agent/                    # MCP agent configuration
│   ├── skills/                # Agent skill definitions
│   └── workflows/             # Agent workflows
├── .ai-context/               # AI assistant context
│   ├── architecture/          # Architecture documentation
│   ├── examples/              # Code examples
│   ├── roadmap/               # Feature roadmap
│   └── technical_specs/       # Technical specifications
├── .github/                   # GitHub workflows
├── .planning/                 # GSD project planning artifacts
├── alembic/                   # Database migrations
│   └── versions/              # Migration version files
├── bugtraceai-cli             # Main entry point script
├── bugtraceaicli.conf         # Configuration file
├── requirements.txt           # Python dependencies
├── .env.example               # Environment variable template
├── .gitignore                 # Git ignore patterns
├── Dockerfile                 # Docker build configuration
├── README.md                  # Project overview and quickstart
├── DEPLOYMENT.md              # Deployment guide
├── MCP_TOOLS.md               # MCP server documentation
└── REFACTORING_PROGRESS.md   # Refactoring status
```

## Key Directories

### bugtrace/

The main source code directory, organized by functional layer:

#### bugtrace/agents/
Core vulnerability detection agents implementing specific attack techniques:

- **analysis.py** - SAST/DAST analysis coordination
- **exploit.py** - Exploitation orchestration
- **recon.py** - Reconnaissance coordination
- **reporting.py** - Report generation agent
- **skeptic.py** - False positive reduction agent

**Specialist Agents:**
- **sqli_agent.py** - SQL injection detection (SQLMap integration)
- **xss_agent.py** - Cross-site scripting detection
- **csti_agent.py** - Client-side template injection
- **lfi_agent.py** - Local file inclusion
- **idor_agent.py** - Insecure direct object references
- **rce_agent.py** - Remote code execution
- **ssrf_agent.py** - Server-side request forgery
- **xxe_agent.py** - XML external entity injection
- **jwt_agent.py** - JWT security issues
- **openredirect_agent.py** - Open redirect vulnerabilities
- **prototype_pollution_agent.py** - JavaScript prototype pollution
- **header_injection_agent.py** - Header injection attacks
- **fileupload_agent.py** - File upload vulnerabilities

**Advanced Agents:**
- **agentic_validator.py** - CDP-based validation for edge cases
- **chain_discovery_agent.py** - Vulnerability chain discovery
- **api_security_agent.py** - API-specific security analysis
- **asset_discovery_agent.py** - Asset enumeration
- **gospider_agent.py** - URL discovery agent
- **nuclei_agent.py** - Nuclei template scanner integration

**Supporting Components:**
- **skills/** - Agent skill definitions (markdown knowledge base)
- **system_prompts/** - LLM system prompts for agents

#### bugtrace/api/
FastAPI REST API for remote scanning:

- **main.py** - API entry point
- **routes/** - API route handlers

#### bugtrace/core/
Core orchestration and domain models:

- Pipeline orchestration
- Event bus
- Work queue management
- Validation status tracking
- Agent coordination

#### bugtrace/mcp/
Model Context Protocol server implementation for Claude integration:

- MCP tool definitions
- Server configuration
- Context providers

#### bugtrace/memory/
Database and state management:

- SQLAlchemy models
- Database session management
- State persistence
- LanceDB vector storage integration

#### bugtrace/reporting/
Report generation in multiple formats:

- **templates/** - HTML/Markdown report templates
- JSON output
- HTML output with screenshots
- Markdown output
- Deduplication and aggregation

#### bugtrace/schemas/
Pydantic schemas for data validation:

- Request/response models
- Configuration schemas
- Validation models

#### bugtrace/services/
Business logic services:

- Scan coordination
- Result processing
- Configuration management

#### bugtrace/skills/
Agent skills and capabilities (runtime skill loading)

#### bugtrace/tools/
Utility tools organized by purpose:

- **exploitation/** - Exploitation utilities
- **headless/** - Browser automation (Playwright/CDP)
- **manipulator/** - Request manipulation tools
- **recon/** - Reconnaissance tools
- **visual/** - Screenshot and visual analysis
- **waf/** - WAF detection and bypass

#### bugtrace/utils/
Shared utilities:

- Logging configuration
- HTTP helpers
- String parsing
- File I/O utilities

### bin/

Compiled Go fuzzers for high-performance payload testing:

- **go-xss-fuzzer** - XSS payload fuzzer
- **go-lfi-fuzzer** - LFI payload fuzzer
- **go-ssrf-fuzzer** - SSRF payload fuzzer
- **go-idor-fuzzer** - IDOR payload fuzzer

These binaries are pre-compiled for Linux x64 and provide significant performance improvements over Python-based fuzzing.

### docs/

Project documentation:

- **agents/** - Individual agent documentation
- **architecture/** - System architecture, pipeline design, testing guides

### lab/

Vulnerable test applications for development and validation:

- **app.py** - Flask file upload vulnerability lab
- **index.php** - PHP vulnerability examples
- **server.py** - Python vulnerable web server

These are intentional vulnerable applications used for testing BugTraceAI's detection capabilities.

### tests/

Comprehensive test suite:

- Unit tests for individual agents
- Integration tests for agent pipelines
- Queue and event bus tests
- Validation flow tests
- E2E pipeline tests

### .agent/

MCP agent configuration:

- **skills/** - MCP skill definitions
- **workflows/** - Automated workflows for common tasks

### .ai-context/

Documentation and context for AI assistants (Claude, etc.):

- **architecture/** - Architecture documentation
- **examples/** - Code examples and patterns
- **roadmap/** - Feature roadmap and planning
- **technical_specs/** - Technical specifications
- **ARCHITECTURE_V4.md** - Latest architecture overview
- **BUGTRACE_MASTER_DOC.md** - Master documentation
- **QUICKSTART_GUIDE.md** - Quick start guide

### .planning/

GSD (Get Shit Done) project planning artifacts:

- Phase planning documents
- Execution summaries
- Project state tracking
- Milestone definitions

This directory is tracked to preserve project history and planning context.

### alembic/

Database migration framework:

- **versions/** - Migration version files
- **env.py** - Migration environment configuration

Database schema evolution is managed through Alembic migrations.

## Configuration Files

### bugtraceai-cli
Main entry point script - executes the BugTraceAI CLI application.

### bugtraceaicli.conf
Default configuration file with scanning parameters:
- Target configuration
- Agent settings
- Timeouts and limits
- Output preferences

### .env.example
Template for environment variables:
- API keys (OpenAI, Anthropic)
- Database connection strings
- CORS origins
- Feature flags

Copy to `.env` and customize for your environment.

### requirements.txt
Python dependencies for the project. Install with:
```bash
pip install -r requirements.txt
```

### Dockerfile
Multi-stage Docker build configuration for containerized deployments.

## Development Workflow

### Running Tests
```bash
# All tests
pytest

# Specific test file
pytest tests/test_agent_name.py

# With coverage
pytest --cov=bugtrace --cov-report=html
```

### Database Migrations
```bash
# Create new migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

### Running the CLI
```bash
# Direct execution
python3 -m bugtrace --target https://example.com

# Via entry point script
./bugtraceai-cli --target https://example.com
```

### Running the API
```bash
# Development
python3 -m uvicorn bugtrace.api.main:app --reload --host 0.0.0.0 --port 8000

# Production
python3 -m uvicorn bugtrace.api.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Running the MCP Server
```bash
# Start MCP server
python3 -m bugtrace.mcp

# Use with Claude Desktop - configure in claude_desktop_config.json
```

## Excluded from Git

The following directories are gitignored for security and cleanliness:

- **archive/** - Old code and documents
- **backups/** - Database and file backups
- **data/** - Runtime data (LanceDB, monitoring state)
- **logs/** - Log files
- **reports/** - Generated scan reports
- **scripts/** - Development scripts
- **state/** - Runtime state files
- **uploads/** - Uploaded files
- **.venv/, venv/** - Python virtual environments
- **.ralph/** - Test artifacts

Sensitive files are also excluded:
- `.env` - Environment variables with secrets
- `*.key`, `*.pem` - Cryptographic keys
- `credentials.json` - API credentials
- `bugtrace.db` - SQLite database (contains scan data)

## Getting Started

For setup instructions, see **README.md**.

For deployment options, see **DEPLOYMENT.md**.

For MCP server integration, see **MCP_TOOLS.md**.

For architecture details, see **docs/architecture/** and **.ai-context/**.

## Contributing

When adding new features:

1. Place agent code in `bugtrace/agents/`
2. Add tests in `tests/`
3. Update documentation in `docs/`
4. Add migrations if schema changes
5. Update this file if adding new top-level directories

Maintain the established directory structure to preserve code organization and maintainability.
