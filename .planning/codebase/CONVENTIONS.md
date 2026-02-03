# Coding Conventions

**Analysis Date:** 2026-02-03

## Naming Patterns

**Files:**
- Modules: `snake_case.py`
  - Examples: `xss_agent.py`, `llm_client.py`, `config.py`
  - Agent files: `{vulnerability_type}_agent.py` (e.g., `jwt_agent.py`, `sqli_agent.py`)
- Packages: lowercase with underscores
  - Core: `bugtrace/core/`, `bugtrace/agents/`, `bugtrace/api/`, `bugtrace/tools/`

**Functions:**
- Function names: `snake_case`
  - Examples: `sanitize_text()`, `record_usage()`, `validate_json_response()`
  - Private functions: Prefixed with `_` (e.g., `_ensure_protocol_exists()`, `_parse_frontmatter()`)
  - Async functions: Same convention (e.g., `async def run_jwt_analysis()`)

**Variables:**
- Local variables: `snake_case`
  - Dataclass fields: `snake_case` (e.g., `injection_context`, `xss_type`, `validated`)
  - Context variables: `snake_case_var` (e.g., `correlation_id_var`)
  - Dict keys: `snake_case` for constants and config, full_description for descriptive keys

**Types & Classes:**
- Class names: `PascalCase`
  - Examples: `BaseAgent`, `ValidationCache`, `ConductorV2`, `XSSAgent`
  - Data classes: `PascalCase` (e.g., `InjectionContext`, `XSSFinding`, `ProbeResult`)
  - Enum classes: `PascalCase` (e.g., `ValidationMethod`, `EscalationReason`)
  - Exception classes: `PascalCase` + "Error" suffix (convention, see error handling)

**Constants:**
- All caps with underscores: `CONSTANT_NAME`
  - Examples: `API_KEY_PLACEHOLDERS`, `PROTOCOL_DIR`, `LOG_DIR`
  - Enum members: ALL_CAPS (e.g., `INTERACTSH = "interactsh"`, `VISION = "vision"`)

## Code Style

**Formatting:**
- No explicit formatter configuration found (black/autopep8 not detected)
- Indentation: 4 spaces (Python standard)
- Line length: No strict limit enforced, but files generally keep reasonable width

**Linting:**
- No ESLint/Flake8 config detected
- Imports are organized but not strictly enforced

## Import Organization

**Order:**
1. Standard library imports (e.g., `import asyncio`, `from typing import ...`)
2. Third-party imports (e.g., `from pydantic import BaseModel`, `from loguru import logger`)
3. Local application imports (e.g., `from bugtrace.core.config import settings`)

**Examples from codebase:**
```python
# config.py
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, Field
from typing import Optional, List, Dict, Any
from pathlib import Path
import os
import re
import json
from datetime import datetime
from dotenv import load_dotenv

from bugtrace.utils.logger import get_logger
```

```python
# xss_agent.py
import asyncio
import aiohttp
import json
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import re
import urllib.parse
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
```

**Path Aliases:**
- No import aliases detected in configuration files
- All imports use full relative paths from `bugtrace/` root

## Error Handling

**Patterns:**
- Try/except blocks with explicit error logging
- Logger passed errors with `exc_info=True` for stack traces
  - Example: `logger.error(f"Error loading {path}: {e}", exc_info=True)`
- Graceful degradation: Fallback values when features not available
  - Example in `manager.py`: Catches ImportError for `sentence_transformers` and sets `EMBEDDINGS_AVAILABLE = False`
- Guard clauses for file existence and validation
  - Example in `base.py`: `if not prompt_path.exists(): return`
- Exception info included in structured logs (JSON formatter)

**Common patterns:**
```python
# Pattern 1: Guard with early return
try:
    with open(prompt_path, "r", encoding="utf-8") as f:
        return f.read()
except Exception:
    return None

# Pattern 2: Detailed logging with context
except Exception as e:
    logger.warning(f"[{self.name}] Failed to load external prompt: {e}")

# Pattern 3: Graceful degradation
try:
    from sentence_transformers import SentenceTransformer
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False
    logger.warning("sentence-transformers not installed...")
```

## Logging

**Framework:** Python `logging` module with `loguru` patterns
- Primary logger: `from bugtrace.utils.logger import get_logger`
- Alternative: `from loguru import logger` (used in some agents)

**Logger creation:**
```python
logger = get_logger("module.name")  # Preferred in most files
```

**Log levels used:**
- `logger.debug()`: Low-level debugging info (e.g., "Loaded protocol file: {key}")
- `logger.info()`: Important lifecycle events (e.g., "Conductor V2 initialized")
- `logger.warning()`: Anomalies or fallbacks (e.g., "Unknown protocol key: {key}")
- `logger.error()`: Errors with full stack trace (e.g., when file loading fails)

**Patterns:**
- Module-level logger: `logger = get_logger("module_path")`
  - Examples: `logger = get_logger("core.conductor")`, `logger = get_logger("agents.xss_v4")`
- Contextual messages with brackets: `logger.info(f"[{component_name}] Message")`
- Sensitive data sanitization: `sanitize_text()` redacts API keys, passwords, tokens
- Structured logging to JSON: RotatingFileHandler writes to `bugtrace.jsonl`
- Correlation ID support: Context var `correlation_id_var` set per request/thread

**Log output:**
- Console: RichHandler with tracebacks
- File (JSONL): Structured JSON logs with timestamp, correlation_id, level, module, message
- Execution log: Plain text rotation (10MB max, 5 backups)

## Comments

**When to Comment:**
- Class and function docstrings required for public APIs
  - Classes: Describe purpose and key responsibilities
  - Functions: What it does, key parameters, return value
  - Examples: `"""Validates findings before emission using protocol files."""`
- Inline comments for non-obvious logic
  - Guard clauses: Optional
  - Complex calculations: Required
  - Unusual patterns: Required

**JSDoc/TSDoc:**
- Not used (Python project)
- Docstrings follow docstring format (triple-quoted strings)
- Parameter descriptions in docstring body or inline

**Examples from codebase:**
```python
def _ensure_protocol_exists(self):
    """Create protocol directory and default files if missing."""

def _parse_frontmatter(self, frontmatter_text, yaml):
    """Parse YAML frontmatter."""

# Inline comments for complex logic
# Guard: file must exist
if not prompt_path.exists():
    return

# =========================================================
# SHARED CONTEXT: Cross-agent communication (Phase 3 v1.5)
# =========================================================
self.shared_context: Dict[str, Any] = {...}
```

## Function Design

**Size:** Functions are typically short to medium
- Most utility functions: 5-30 lines
- Complex agents: 50-200 lines (larger due to async state machines)
- Principle: Prefer composition over large monolithic functions

**Parameters:**
- Type hints required for public APIs
  - Example: `def record_usage(self, model: str, agent: str, input_tokens: int, output_tokens: int)`
- Dataclasses used for complex parameter groups
  - Example: `@dataclass class XSSFinding` with 15+ fields
- Optional parameters use `Optional[T]` with defaults
  - Example: `screenshot_path: Optional[str] = None`

**Return Values:**
- Explicit return types in signatures
  - Example: `def get_summary(self) -> Dict[str, Any]`
- Dataclass returns for complex results
  - Example: Returns `XSSFinding` objects
- Generator returns use `Generator[T, None, None]` (e.g., in conftest.py)

## Module Design

**Exports:**
- Modules export main classes and public functions
- Private utilities prefixed with `_` (convention, not enforced)
- No explicit `__all__` lists detected in most modules

**Barrel Files:**
- Package `__init__.py` files mostly empty or minimal
  - Examples: `bugtrace/__init__.py` (0 lines), `bugtrace/core/__init__.py` (minimal)
  - No star imports or re-exports

**Package Structure:**
- Clear domain separation: agents, core, api, services, tools, reporting
- Circular dependency prevention: Deferred imports in BaseAgent
  - Example: Comments note `# Deferred imports to avoid circular dependencies`
- Services pattern: Core utilities in `bugtrace/core/` (config, database, llm_client, etc.)

## Pydantic & Data Validation

**Schemas:**
- Pydantic BaseModel for API request/response validation
  - Location: `bugtrace/api/schemas.py`
  - Example: `class CreateScanRequest(BaseModel)` with Field descriptions
- Pydantic Settings for configuration
  - Location: `bugtrace/core/config.py`
  - Inherits from `BaseSettings`, uses `SettingsConfigDict`
  - Validators: `@field_validator` for custom validation

**Field definitions:**
```python
class CreateScanRequest(BaseModel):
    target_url: str = Field(..., description="Target URL to scan")
    scan_type: str = Field(default="full", description="Scan type: full, hunter, etc.")
    safe_mode: Optional[bool] = Field(default=None, description="Override global safe mode")
```

## Async/Await Patterns

**Usage:**
- Async functions prefixed with `async def`
- Asyncio event loops in tests: conftest.py provides session-scoped event_loop fixture
- AsyncMock for testing async functions
- Coroutines awaited with `await` keyword

---

*Convention analysis: 2026-02-03*
