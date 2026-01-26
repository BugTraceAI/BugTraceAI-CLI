# Configuration Management - Audit Fix Tasks

## Feature Overview
Configuration management using:
- **Pydantic Settings**: Type-safe configuration
- **.env Files**: Secret management
- **bugtraceaicli.conf**: User configuration
- **Runtime Validation**: Config validation on load

---

## 🟠 HIGH Priority Tasks (2)

### TASK-118: Add API Key Format Validation
**Severity**: 🟠 HIGH
**File**: `bugtrace/core/config.py:25-26`
**Issue**: No validation that API keys follow expected format
**Impact**: Silent failures if keys malformed, security risk

**Current Code**:
```python
# Lines 25-26
OPENROUTER_API_KEY: Optional[str] = None
GLM_API_KEY: Optional[str] = None
```

**Proposed Fix**:
```python
from pydantic import validator, Field
import re

class Settings(BaseSettings):
    # API Keys with validation
    OPENROUTER_API_KEY: Optional[str] = Field(default=None, min_length=32)
    GLM_API_KEY: Optional[str] = Field(default=None, min_length=20)

    @validator('OPENROUTER_API_KEY')
    def validate_openrouter_key(cls, v):
        if v is None:
            return v

        # OpenRouter keys typically: sk-or-v1-[64 hex chars]
        if not re.match(r'^sk-or-v1-[a-f0-9]{64}$', v):
            logger.warning("OPENROUTER_API_KEY format looks incorrect")
            # Don't fail, just warn (format may change)

        return v

    @validator('GLM_API_KEY')
    def validate_glm_key(cls, v):
        if v is None:
            return v

        # GLM keys are typically alphanumeric
        if not re.match(r'^[a-zA-Z0-9]{32,}$', v):
            logger.warning("GLM_API_KEY format looks incorrect")

        return v

    @validator('OPENROUTER_API_KEY', 'GLM_API_KEY')
    def check_key_not_placeholder(cls, v, field):
        """Ensure key is not a placeholder."""
        if v is None:
            return v

        placeholders = ['your-key-here', 'placeholder', 'xxx', 'changeme', 'test']
        if v.lower() in placeholders:
            raise ValueError(f"{field.name} appears to be a placeholder, not a real key")

        return v
```

**Additional Security**:
```python
# Mask API keys in logs
class Settings(BaseSettings):
    def mask_secrets(self):
        """Return config with masked secrets."""
        masked = self.dict()
        for key in ['OPENROUTER_API_KEY', 'GLM_API_KEY']:
            if masked.get(key):
                masked[key] = masked[key][:8] + '...' + masked[key][-4:]
        return masked

# Usage in logging
logger.info(f"Config loaded: {settings.mask_secrets()}")
```

**Priority**: P1 - Fix within 1 week

---

### TASK-119: Add Model Name Format Validation
**Severity**: 🟠 HIGH
**File**: `bugtrace/core/config.py:29-49`
**Issue**: Model names accepted without format validation
**Impact**: Runtime errors if invalid model specified

**Current Code**:
```python
# Lines 29-49
DEFAULT_MODEL: str = "google/gemini-3-flash-preview"
CODE_MODEL: str = "qwen/qwen-2.5-coder-32b-instruct"
ANALYSIS_MODEL: str = "x-ai/grok-code-fast-1"
```

**Proposed Fix**:
```python
from pydantic import validator

class Settings(BaseSettings):
    DEFAULT_MODEL: str = "google/gemini-3-flash-preview"

    @validator('DEFAULT_MODEL', 'CODE_MODEL', 'ANALYSIS_MODEL', 'MUTATION_MODEL')
    def validate_model_name(cls, v, field):
        """Validate model name format."""
        if not v:
            raise ValueError(f"{field.name} cannot be empty")

        # OpenRouter format: provider/model-name
        if '/' not in v:
            raise ValueError(f"Invalid model name format: {v} (expected: provider/model)")

        provider, model = v.split('/', 1)

        # Validate provider
        valid_providers = [
            'google', 'openai', 'anthropic', 'meta', 'mistral',
            'qwen', 'deepseek', 'x-ai', 'cohere', 'perplexity'
        ]

        if provider not in valid_providers:
            logger.warning(f"Unknown provider: {provider}")

        # Validate model name format
        if not re.match(r'^[a-z0-9\-\.]+$', model):
            raise ValueError(f"Invalid model name format: {model}")

        return v

    @validator('PRIMARY_MODELS', 'WAF_DETECTION_MODELS')
    def validate_model_list(cls, v):
        """Validate comma-separated model list."""
        if not v:
            return v

        models = [m.strip() for m in v.split(',')]

        for model in models:
            if '/' not in model:
                raise ValueError(f"Invalid model in list: {model}")

        return v
```

**Priority**: P1 - Fix within 1 week

---

## 🟡 MEDIUM Priority Tasks (5)

### TASK-120: Add Configuration Validation on Load
**Severity**: 🟡 MEDIUM
**File**: `bugtrace/core/config.py`
**Issue**: Invalid configurations not detected until runtime

**Proposed Fix**:
```python
class Settings(BaseSettings):
    def validate_config(self):
        """Validate entire configuration."""
        errors = []

        # Check required keys
        if not self.OPENROUTER_API_KEY:
            errors.append("OPENROUTER_API_KEY is required")

        # Check numeric bounds
        if self.MAX_DEPTH < 1:
            errors.append("MAX_DEPTH must be >= 1")

        if self.MAX_URLS < 1:
            errors.append("MAX_URLS must be >= 1")

        if self.MAX_CONCURRENT_REQUESTS < 1:
            errors.append("MAX_CONCURRENT_REQUESTS must be >= 1")

        # Check confidence thresholds
        if not 0.0 <= self.CONDUCTOR_MIN_CONFIDENCE <= 1.0:
            errors.append("CONDUCTOR_MIN_CONFIDENCE must be 0.0-1.0")

        if not 0.0 <= self.ANALYSIS_CONFIDENCE_THRESHOLD <= 1.0:
            errors.append("ANALYSIS_CONFIDENCE_THRESHOLD must be 0.0-1.0")

        # Check file paths
        if not self.BASE_DIR.exists():
            errors.append(f"BASE_DIR does not exist: {self.BASE_DIR}")

        if errors:
            raise ValueError(f"Configuration errors:\n" + "\n".join(f"  - {e}" for e in errors))

# Validate on load
settings = Settings()
settings.load_from_conf()
settings.validate_config()  # Add this
```

**Priority**: P2 - Fix before release

---

### TASK-121: Add Config Change Notification
**Severity**: 🟡 MEDIUM
**Issue**: No way to reload config without restart

**Proposed Fix**:
```python
import watchdog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class ConfigWatcher(FileSystemEventHandler):
    def __init__(self, config_path, callback):
        self.config_path = config_path
        self.callback = callback

    def on_modified(self, event):
        if event.src_path == str(self.config_path):
            logger.info("Config file changed, reloading...")
            self.callback()

# Usage
def reload_config():
    global settings
    settings = Settings()
    settings.load_from_conf()
    settings.validate_config()
    logger.info("Config reloaded")

observer = Observer()
observer.schedule(
    ConfigWatcher(settings.BASE_DIR / "bugtraceaicli.conf", reload_config),
    path=str(settings.BASE_DIR),
    recursive=False
)
observer.start()
```

**Priority**: P2 - Fix before release

---

### TASK-122: Add Debug Logging for Config
**Severity**: 🟡 MEDIUM
**File**: `bugtrace/core/config.py`
**Issue**: No visibility into which config values are used

**Proposed Fix**:
```python
def log_config(self):
    """Log configuration (with masked secrets)."""
    if not self.DEBUG:
        return

    logger.debug("Configuration loaded:")
    for key, value in self.mask_secrets().items():
        if not key.startswith('_'):
            logger.debug(f"  {key}: {value}")
```

**Priority**: P2 - Fix before release

---

### TASK-123: Add Config Schema Documentation
**Severity**: 🟡 MEDIUM
**Issue**: No auto-generated config documentation

**Proposed Fix**:
```python
def generate_config_docs(self):
    """Generate configuration documentation."""
    docs = []

    for field_name, field in self.__fields__.items():
        docs.append(f"## {field_name}")
        docs.append(f"Type: {field.type_}")
        docs.append(f"Default: {field.default}")

        if field.field_info.description:
            docs.append(f"Description: {field.field_info.description}")

        docs.append("")

    return "\n".join(docs)

# Generate docs
with open("CONFIG_REFERENCE.md", "w") as f:
    f.write(settings.generate_config_docs())
```

**Priority**: P2 - Fix before release

---

### TASK-124: Add Environment-Specific Configs
**Severity**: 🟡 MEDIUM
**Issue**: No support for dev/staging/prod configs

**Proposed Fix**:
```python
class Settings(BaseSettings):
    ENV: str = Field(default="production", env="BUGTRACE_ENV")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Load environment-specific config
        env_file = f".env.{self.ENV}"
        if os.path.exists(env_file):
            load_dotenv(env_file, override=True)
```

**Priority**: P3 - Next release

---

## 🟢 LOW Priority Tasks (3)

### TASK-125: Add Config Export/Import
**Severity**: 🟢 LOW
**Issue**: No way to export/import config

**Priority**: P4 - Technical debt

---

### TASK-126: Add Config Diffing
**Severity**: 🟢 LOW
**Issue**: No way to compare configs

**Priority**: P4 - Technical debt

---

### TASK-127: Add Config Versioning
**Severity**: 🟢 LOW
**Issue**: No tracking of config changes

**Priority**: P4 - Technical debt

---

## Summary

**Total Tasks**: 10
- 🔴 Critical: 0
- 🟠 High: 2 (API key validation, model validation)
- 🟡 Medium: 5 (Validation, reload, logging)
- 🟢 Low: 3 (Technical debt)

**Estimated Effort**: 1 week for P0-P1 tasks
