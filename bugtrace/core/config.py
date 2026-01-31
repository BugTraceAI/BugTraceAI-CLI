from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, Field
from typing import Optional, List, Dict, Any
from pathlib import Path
import os
import re
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv() # Force load .env

from bugtrace.utils.logger import get_logger

logger = get_logger("core.config")

# Known valid providers for OpenRouter
VALID_PROVIDERS = [
    'google', 'openai', 'anthropic', 'meta', 'mistral',
    'qwen', 'deepseek', 'x-ai', 'cohere', 'perplexity',
    'nvidia', 'ai21', 'together', 'fireworks', 'groq'
]

# Placeholder values that should be rejected
API_KEY_PLACEHOLDERS = ['your-key-here', 'placeholder', 'xxx', 'changeme', 'test', 'sk-xxx']

class Settings(BaseSettings):
    """
    Unified Configuration Management using Pydantic Settings.
    Loads from .env file and environment variables.
    """
    # --- Project Metadata ---
    APP_NAME: str = "BugtraceAI-CLI"
    VERSION: str = "2.0.0"  # Phoenix Edition
    DEBUG: bool = False
    SAFE_MODE: bool = False # Default to False, override via CLI

    # --- Environment (TASK-124) ---
    ENV: str = Field(default="production", description="Environment: development, staging, production")

    # --- API Keys (Secrets) with validation (TASK-118) ---
    OPENROUTER_API_KEY: Optional[str] = Field(default=None, min_length=32, description="OpenRouter API key")
    GLM_API_KEY: Optional[str] = Field(default=None, min_length=20, description="GLM API key")
    
    # --- LLM Models ---
    DEFAULT_MODEL: str = "google/gemini-3-flash-preview"
    CODE_MODEL: str = "qwen/qwen-2.5-coder-32b-instruct"
    ANALYSIS_MODEL: str = "x-ai/grok-code-fast-1"
    
    # Ordered list (Shifts if one fails)
    PRIMARY_MODELS: str = ""
    
    # Vision
    VISION_MODEL: str = ""
    
    # WAF
    WAF_DETECTION_MODELS: str = ""
    
    # Model for payload mutation (DeepSeek has fewer safety restrictions)
    MUTATION_MODEL: str = "deepseek/deepseek-chat"
    
    MIN_CREDITS: float = 2.0
    MAX_CONCURRENT_REQUESTS: int = 1
    LLM_REQUEST_TIMEOUT: float = 120.0  # Seconds to wait for LLM API response (prevent indefinite hang)

    # Model for skeptical analysis in DASTySAST agent
    SKEPTICAL_MODEL: str = "google/gemini-3-flash-preview"

    # Skeptical Review Thresholds (0-10 scale)
    # CRITICAL vulns have LOWER thresholds to avoid missing them
    SKEPTICAL_THRESHOLDS: dict = {
        "RCE": 4,      # Critical - don't miss
        "SQL": 4,      # Critical - don't miss
        "XXE": 5,      # High risk
        "SSRF": 5,     # High risk
        "LFI": 5,      # High risk
        "XSS": 5,      # Medium, easy to verify
        "JWT": 6,      # Medium
        "FILE_UPLOAD": 6,  # Medium
        "IDOR": 6,     # Lower risk
        "DEFAULT": 5   # Fallback
    }

    # --- False Positive Filtering (Phase 17: v2.3) ---
    FP_CONFIDENCE_THRESHOLD: float = 0.5  # Minimum fp_confidence to pass filtering (0.0-1.0)
    FP_SKEPTICAL_WEIGHT: float = 0.4  # Weight of skeptical_score in fp_confidence calc
    FP_VOTES_WEIGHT: float = 0.3  # Weight of votes in fp_confidence calc
    FP_EVIDENCE_WEIGHT: float = 0.3  # Weight of evidence quality in fp_confidence calc

    # --- ThinkingConsolidationAgent settings (Phase 18: v2.3) ---
    THINKING_MODE: str = "streaming"  # "streaming" | "batch"
    THINKING_BATCH_SIZE: int = 50  # Max findings per batch in batch mode
    THINKING_BATCH_TIMEOUT: float = 5.0  # Seconds to wait before processing incomplete batch
    THINKING_DEDUP_WINDOW: int = 1000  # Max dedup keys to track (LRU eviction)
    THINKING_FP_THRESHOLD: float = 0.5  # Min fp_confidence to forward to specialists
    THINKING_BACKPRESSURE_RETRIES: int = 3  # Max retries on queue full
    THINKING_BACKPRESSURE_DELAY: float = 0.5  # Seconds between retries
    THINKING_EMIT_EVENTS: bool = True  # Emit work_queued events

    # --- Worker Pool Configuration (Phase 19: v2.3) ---
    WORKER_POOL_DEFAULT_SIZE: int = 5  # Default workers per specialist
    WORKER_POOL_XSS_SIZE: int = 8  # XSS-specific (high volume)
    WORKER_POOL_SQLI_SIZE: int = 5  # SQLi-specific
    WORKER_POOL_SHUTDOWN_TIMEOUT: float = 30.0  # Max seconds to drain on shutdown
    WORKER_POOL_DEQUEUE_TIMEOUT: float = 5.0  # Seconds to wait for queue item
    WORKER_POOL_EMIT_EVENTS: bool = True  # Emit vulnerability_detected events

    # --- Validation Optimization Configuration (Phase 21: v2.3) ---
    VALIDATION_METRICS_ENABLED: bool = True  # Track validation load metrics
    CDP_LOAD_TARGET: float = 0.01  # Target <1% findings go to CDP validation
    VALIDATION_LOG_INTERVAL: int = 100  # Log metrics every N findings

    # --- Pipeline Orchestration Configuration (Phase 23: v2.3) ---
    PIPELINE_PHASE_TIMEOUT: int = 600  # 10 min max per phase
    PIPELINE_DRAIN_TIMEOUT: int = 30  # 30s to drain queues on shutdown
    PIPELINE_PAUSE_CHECK_INTERVAL: float = 0.5  # Pause check frequency
    PIPELINE_DISCOVERY_COMPLETION_DELAY: float = 2.0  # Wait for late findings
    PIPELINE_AUTO_TRANSITION: bool = True  # Automatic phase transitions

    # --- Performance Metrics Configuration (Phase 24: v2.3) ---
    PERF_CDP_LOG_ENABLED: bool = True  # Log CDP reduction summary after each scan
    PERF_CDP_LOG_INTERVAL: int = 50  # Log interim CDP metrics every N findings (0 to disable)
    PERF_DEDUP_LOG_ENABLED: bool = True  # Log deduplication metrics during and after scans
    PERF_DEDUP_LOG_INTERVAL: int = 25  # Log dedup stats every N duplicates (0 to disable)
    PERF_PARALLEL_LOG_ENABLED: bool = True  # Log parallelization metrics during and after scans
    PERF_PARALLEL_LOG_INTERVAL: int = 10  # Log parallelization stats every N worker operations (0 to disable)

    # --- Pipeline V3 Batch Processing Configuration (Phase 31: v2.5) ---
    BATCH_PROCESSING_ENABLED: bool = True  # Enable batch DAST mode
    BATCH_DAST_CONCURRENCY: int = 5  # Max concurrent DAST agents
    BATCH_QUEUE_DRAIN_TIMEOUT: float = 300.0  # Seconds to wait for queues
    BATCH_QUEUE_CHECK_INTERVAL: float = 2.0  # Seconds between queue depth checks

    def get_threshold_for_type(self, vuln_type: str) -> int:
        """Get the skeptical threshold for a vulnerability type."""
        vuln_upper = vuln_type.upper()
        for key in self.SKEPTICAL_THRESHOLDS:
            if key in vuln_upper:
                return self.SKEPTICAL_THRESHOLDS[key]
        return self.SKEPTICAL_THRESHOLDS.get("DEFAULT", 5)

    # --- Validators (TASK-118, TASK-119) ---
    @field_validator('OPENROUTER_API_KEY')
    @classmethod
    def validate_openrouter_key(cls, v):
        """Validate OpenRouter API key format."""
        if v is None:
            return v
        # Check for placeholder values
        if v.lower() in API_KEY_PLACEHOLDERS:
            raise ValueError("OPENROUTER_API_KEY appears to be a placeholder, not a real key")
        # OpenRouter keys typically: sk-or-v1-[64 hex chars]
        if not re.match(r'^sk-or-v1-[a-f0-9]{64}$', v):
            logger.warning("OPENROUTER_API_KEY format looks incorrect (expected: sk-or-v1-[64 hex])")
        return v

    @field_validator('GLM_API_KEY')
    @classmethod
    def validate_glm_key(cls, v):
        """Validate GLM API key format."""
        if v is None:
            return v
        # Check for placeholder values
        if v.lower() in API_KEY_PLACEHOLDERS:
            raise ValueError("GLM_API_KEY appears to be a placeholder, not a real key")
        # GLM keys are typically alphanumeric
        if not re.match(r'^[a-zA-Z0-9_\-]{20,}$', v):
            logger.warning("GLM_API_KEY format looks incorrect")
        return v

    @field_validator('DEFAULT_MODEL', 'CODE_MODEL', 'ANALYSIS_MODEL', 'MUTATION_MODEL',
                     'SKEPTICAL_MODEL', 'VISION_MODEL', 'ANALYSIS_PENTESTER_MODEL',
                     'ANALYSIS_BUG_BOUNTY_MODEL', 'ANALYSIS_AUDITOR_MODEL', 'VALIDATION_VISION_MODEL')
    @classmethod
    def validate_model_name(cls, v, info):
        """Validate model name format (TASK-119)."""
        if not v:
            return v  # Allow empty for optional models
        # OpenRouter format: provider/model-name
        if '/' not in v:
            raise ValueError(f"Invalid model name format: {v} (expected: provider/model)")
        provider, model = v.split('/', 1)
        # Warn about unknown providers (don't fail - new providers may appear)
        if provider not in VALID_PROVIDERS:
            logger.warning(f"Unknown provider '{provider}' in {info.field_name}")
        # Validate model name format (alphanumeric, dashes, dots)
        if not re.match(r'^[a-zA-Z0-9\-\.]+$', model):
            raise ValueError(f"Invalid model name format: {model}")
        return v

    @field_validator('PRIMARY_MODELS', 'WAF_DETECTION_MODELS')
    @classmethod
    def validate_model_list(cls, v):
        """Validate comma-separated model list (TASK-119)."""
        if not v:
            return v
        models = [m.strip() for m in v.split(',')]
        for model in models:
            if model and '/' not in model:
                raise ValueError(f"Invalid model in list: {model} (expected: provider/model)")
        return v

    @field_validator('QUEUE_PERSISTENCE_MODE')
    @classmethod
    def validate_queue_mode(cls, v):
        """Validate queue persistence mode."""
        valid_modes = ['memory', 'redis']
        if v not in valid_modes:
            raise ValueError(f"QUEUE_PERSISTENCE_MODE must be one of: {valid_modes}")
        return v

    @field_validator('FP_CONFIDENCE_THRESHOLD')
    @classmethod
    def validate_fp_threshold(cls, v):
        """Validate FP confidence threshold is between 0 and 1."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("FP_CONFIDENCE_THRESHOLD must be between 0.0 and 1.0")
        return v

    @field_validator('THINKING_MODE')
    @classmethod
    def validate_thinking_mode(cls, v):
        """Validate thinking mode is valid."""
        if v not in ("streaming", "batch"):
            raise ValueError("THINKING_MODE must be 'streaming' or 'batch'")
        return v

    @field_validator('PIPELINE_PHASE_TIMEOUT', 'PIPELINE_DRAIN_TIMEOUT')
    @classmethod
    def validate_pipeline_timeouts(cls, v, info):
        """Validate pipeline timeout values are positive."""
        if v <= 0:
            raise ValueError(f"{info.field_name} must be positive (got {v})")
        return v

    @field_validator('PIPELINE_PAUSE_CHECK_INTERVAL', 'PIPELINE_DISCOVERY_COMPLETION_DELAY')
    @classmethod
    def validate_pipeline_intervals(cls, v, info):
        """Validate pipeline interval values are positive."""
        if v <= 0:
            raise ValueError(f"{info.field_name} must be positive (got {v})")
        return v

    # --- OpenRouter Configuration ---
    OPENROUTER_ONLINE: bool = True  # Enable internet access for models
    
    # --- Conductor V2 Anti-Hallucination Configuration ---
    CONDUCTOR_DISABLE_VALIDATION: bool = False
    CONDUCTOR_CONTEXT_REFRESH_INTERVAL: int = 300  # seconds
    CONDUCTOR_MIN_CONFIDENCE: float = 0.6
    CONDUCTOR_ENABLE_FP_DETECTION: bool = True
    
    # --- CRAWLER Configuration (URL Filtering) ---
    CRAWLER_EXCLUDE_EXTENSIONS: str = ".js,.css,.jpg,.jpeg,.png,.gif,.svg,.ico,.woff,.woff2,.ttf,.eot,.pdf,.zip,.rar,.mp3,.mp4,.webm,.webp"
    CRAWLER_INCLUDE_EXTENSIONS: str = ""  # Empty = analyze any URL not in EXCLUDE
    
    # --- SCANNING Configuration (Stop-on-Critical) ---
    STOP_ON_CRITICAL: bool = True
    CRITICAL_TYPES: str = "SQLi,RCE,XXE"
    MANDATORY_SQLMAP_VALIDATION: bool = True
    SKIP_VALIDATED_PARAMS: bool = True
    
    # --- ANALYSIS Configuration (Multi-Model URL Analysis) ---
    ANALYSIS_ENABLE: bool = True
    # Using Gemini 2.5 Flash for testing - consistent JSON output
    ANALYSIS_PENTESTER_MODEL: str = "google/gemini-3-flash-preview"
    ANALYSIS_BUG_BOUNTY_MODEL: str = "google/gemini-3-flash-preview"
    ANALYSIS_AUDITOR_MODEL: str = "google/gemini-3-flash-preview"
    ANALYSIS_CONFIDENCE_THRESHOLD: float = 0.7
    ANALYSIS_SKIP_THRESHOLD: float = 0.3
    ANALYSIS_CONSENSUS_VOTES: int = 2
    
    # --- VALIDATION Configuration (Vision-Based XSS Validation) ---
    VALIDATION_VISION_MODEL: str = "qwen/qwen3-vl-8b-thinking"
    VALIDATION_VISION_ENABLED: bool = True
    VALIDATION_VISION_ONLY_FOR_XSS: bool = True
    VALIDATION_MAX_VISION_CALLS_PER_URL: int = 3

    # --- CDP Configuration (Chrome DevTools Protocol for XSS Validation) ---
    # Use CDP instead of Playwright for more reliable XSS detection
    CDP_ENABLED: bool = True  # Enable CDP as primary verification method
    CDP_PORT: int = 9222  # Chrome remote debugging port
    CDP_TIMEOUT: float = 5.0  # Time to wait for XSS execution (seconds)

    # --- Queue Configuration (Phase 16: v2.3) ---
    QUEUE_PERSISTENCE_MODE: str = "memory"  # "memory" or "redis"
    QUEUE_DEFAULT_MAX_DEPTH: int = 1000  # Max items per queue
    QUEUE_DEFAULT_RATE_LIMIT: float = 100.0  # Max items/second (0 = unlimited)
    QUEUE_REDIS_URL: str = "redis://localhost:6379/0"  # For future Redis mode

    # --- SSL/TLS Configuration (TASK-66) ---
    # Enable SSL certificate verification by default for security
    VERIFY_SSL_CERTIFICATES: bool = True
    # Allow self-signed certs only for authorized testing environments
    ALLOW_SELF_SIGNED_CERTS: bool = False

    # --- WAF Q-Learning Configuration (TASK-68, TASK-75) ---
    # Epsilon-greedy exploration parameters
    WAF_QLEARNING_INITIAL_EPSILON: float = 0.3  # Initial exploration rate
    WAF_QLEARNING_MIN_EPSILON: float = 0.05  # Minimum exploration rate
    WAF_QLEARNING_DECAY_RATE: float = 0.995  # Epsilon decay per episode
    # UCB exploration constant (higher = more exploration)
    WAF_QLEARNING_UCB_CONSTANT: float = 2.0
    # Backup settings
    WAF_QLEARNING_MAX_BACKUPS: int = 5

    # --- REPORT Configuration ---
    # Only include validated findings in final report (per report_quality_evaluation.md)
    REPORT_ONLY_VALIDATED: bool = True

    # --- OPTIMIZATION Configuration ---
    # Early exit after first finding per URL (saves 70%+ scan time)
    # When True: Stop testing remaining params after first vuln found
    # When False: Test ALL params for comprehensive coverage
    EARLY_EXIT_ON_FINDING: bool = True

    # --- TRACING & OOB Configuration (v1.6) ---
    TRACING_ENABLED: bool = True
    INTERACTSH_SERVER: str = "oast.fun"
    INTERACTSH_POLL_INTERVAL: int = 60 # seconds



    def _load_crawler_config(self, config):
        """Load CRAWLER section config."""
        if "CRAWLER" not in config:
            return
        if "EXCLUDE_EXTENSIONS" in config["CRAWLER"]:
            self.CRAWLER_EXCLUDE_EXTENSIONS = config["CRAWLER"]["EXCLUDE_EXTENSIONS"]
        if "INCLUDE_EXTENSIONS" in config["CRAWLER"]:
            self.CRAWLER_INCLUDE_EXTENSIONS = config["CRAWLER"]["INCLUDE_EXTENSIONS"]

    def _load_scan_config(self, config):
        """Load SCAN section config."""
        if "SCAN" not in config:
            return
        if "MAX_DEPTH" in config["SCAN"]:
            self.MAX_DEPTH = config["SCAN"].getint("MAX_DEPTH")
        if "MAX_URLS" in config["SCAN"]:
            self.MAX_URLS = config["SCAN"].getint("MAX_URLS")
        if "MAX_CONCURRENT_URL_AGENTS" in config["SCAN"]:
            self.MAX_CONCURRENT_URL_AGENTS = config["SCAN"].getint("MAX_CONCURRENT_URL_AGENTS")
        if "GOSPIDER_NO_REDIRECT" in config["SCAN"]:
            self.GOSPIDER_NO_REDIRECT = config["SCAN"].getboolean("GOSPIDER_NO_REDIRECT")

    def _load_parallelization_config(self, config):
        """Load PARALLELIZATION section config for granular per-phase concurrency."""
        if "PARALLELIZATION" not in config:
            return
        section = config["PARALLELIZATION"]
        if "MAX_CONCURRENT_DISCOVERY" in section:
            self.MAX_CONCURRENT_DISCOVERY = section.getint("MAX_CONCURRENT_DISCOVERY")
        if "MAX_CONCURRENT_ANALYSIS" in section:
            self.MAX_CONCURRENT_ANALYSIS = section.getint("MAX_CONCURRENT_ANALYSIS")
        if "MAX_CONCURRENT_SPECIALISTS" in section:
            self.MAX_CONCURRENT_SPECIALISTS = section.getint("MAX_CONCURRENT_SPECIALISTS")
        # NOTE: MAX_CONCURRENT_VALIDATION is NOT loaded from config
        # CDP client only supports 1 concurrent session - hardcoded in defaults

    def _load_url_prioritization_config(self, config):
        """Load URL_PRIORITIZATION section config for intelligent URL ordering."""
        if "URL_PRIORITIZATION" not in config:
            return
        section = config["URL_PRIORITIZATION"]
        if "ENABLED" in section:
            self.URL_PRIORITIZATION_ENABLED = section.getboolean("ENABLED")
        if "LOG_SCORES" in section:
            self.URL_PRIORITIZATION_LOG_SCORES = section.getboolean("LOG_SCORES")
        if "CUSTOM_PATHS" in section:
            self.URL_PRIORITIZATION_CUSTOM_PATHS = section["CUSTOM_PATHS"].strip()
        if "CUSTOM_PARAMS" in section:
            self.URL_PRIORITIZATION_CUSTOM_PARAMS = section["CUSTOM_PARAMS"].strip()

    def _load_llm_models_config(self, config):
        """Load LLM_MODELS section config."""
        if "LLM_MODELS" not in config:
            return
        section = config["LLM_MODELS"]
        if "DEFAULT_MODEL" in section: self.DEFAULT_MODEL = section["DEFAULT_MODEL"]
        if "PRIMARY_MODELS" in section: self.PRIMARY_MODELS = section["PRIMARY_MODELS"]
        if "VISION_MODEL" in section: self.VISION_MODEL = section["VISION_MODEL"]
        if "WAF_DETECTION_MODELS" in section: self.WAF_DETECTION_MODELS = section["WAF_DETECTION_MODELS"]
        if "CODE_MODEL" in section: self.CODE_MODEL = section["CODE_MODEL"]
        if "MUTATION_MODEL" in section: self.MUTATION_MODEL = section["MUTATION_MODEL"]
        if "ANALYSIS_MODEL" in section: self.ANALYSIS_MODEL = section["ANALYSIS_MODEL"]
        if "SKEPTICAL_MODEL" in section: self.SKEPTICAL_MODEL = section["SKEPTICAL_MODEL"]
        if "MAX_CONCURRENT_REQUESTS" in section:
            self.MAX_CONCURRENT_REQUESTS = section.getint("MAX_CONCURRENT_REQUESTS")

    def _load_conductor_and_scanning_config(self, config):
        """Load CONDUCTOR and SCANNING sections."""
        if "OPENROUTER" in config:
            if "ONLINE" in config["OPENROUTER"]:
                self.OPENROUTER_ONLINE = config["OPENROUTER"].getboolean("ONLINE")

        if "CONDUCTOR" in config:
            section = config["CONDUCTOR"]
            if "DISABLE_VALIDATION" in section:
                self.CONDUCTOR_DISABLE_VALIDATION = section.getboolean("DISABLE_VALIDATION")
            if "CONTEXT_REFRESH_INTERVAL" in section:
                self.CONDUCTOR_CONTEXT_REFRESH_INTERVAL = section.getint("CONTEXT_REFRESH_INTERVAL")
            if "MIN_CONFIDENCE" in section:
                self.CONDUCTOR_MIN_CONFIDENCE = section.getfloat("MIN_CONFIDENCE")
            if "ENABLE_FP_DETECTION" in section:
                self.CONDUCTOR_ENABLE_FP_DETECTION = section.getboolean("ENABLE_FP_DETECTION")

        if "SCANNING" in config:
            section = config["SCANNING"]
            if "STOP_ON_CRITICAL" in section:
                self.STOP_ON_CRITICAL = section.getboolean("STOP_ON_CRITICAL")
            if "CRITICAL_TYPES" in section: self.CRITICAL_TYPES = section["CRITICAL_TYPES"]
            if "MANDATORY_SQLMAP_VALIDATION" in section:
                self.MANDATORY_SQLMAP_VALIDATION = section.getboolean("MANDATORY_SQLMAP_VALIDATION")
            if "SKIP_VALIDATED_PARAMS" in section:
                self.SKIP_VALIDATED_PARAMS = section.getboolean("SKIP_VALIDATED_PARAMS")

    def _load_analysis_and_misc_config(self, config):
        """Load ANALYSIS, BROWSER, ADVANCED, REPORT, OPTIMIZATION sections."""
        if "ANALYSIS" in config:
            section = config["ANALYSIS"]
            if "ENABLE_ANALYSIS" in section:
                self.ANALYSIS_ENABLE = section.getboolean("ENABLE_ANALYSIS")
            if "PENTESTER_MODEL" in section:
                self.ANALYSIS_PENTESTER_MODEL = section["PENTESTER_MODEL"]
            if "BUG_BOUNTY_MODEL" in section:
                self.ANALYSIS_BUG_BOUNTY_MODEL = section["BUG_BOUNTY_MODEL"]
            if "AUDITOR_MODEL" in section:
                self.ANALYSIS_AUDITOR_MODEL = section["AUDITOR_MODEL"]
            if "CONFIDENCE_THRESHOLD" in section:
                self.ANALYSIS_CONFIDENCE_THRESHOLD = section.getfloat("CONFIDENCE_THRESHOLD")
            if "SKIP_THRESHOLD" in section:
                self.ANALYSIS_SKIP_THRESHOLD = section.getfloat("SKIP_THRESHOLD")
            if "CONSENSUS_VOTES" in section:
                self.ANALYSIS_CONSENSUS_VOTES = section.getint("CONSENSUS_VOTES")

        if "BROWSER" in config:
            if "HEADLESS" in config["BROWSER"]:
                self.HEADLESS_BROWSER = config["BROWSER"].getboolean("HEADLESS")

        if "ADVANCED" in config:
            if "TRACING_ENABLED" in config["ADVANCED"]:
                self.TRACING_ENABLED = config["ADVANCED"].getboolean("TRACING_ENABLED")
            if "INTERACTSH_SERVER" in config["ADVANCED"]:
                self.INTERACTSH_SERVER = config["ADVANCED"]["INTERACTSH_SERVER"]

        if "REPORT" in config:
            if "ONLY_VALIDATED" in config["REPORT"]:
                self.REPORT_ONLY_VALIDATED = config["REPORT"].getboolean("ONLY_VALIDATED")

        if "OPTIMIZATION" in config:
            if "EARLY_EXIT_ON_FINDING" in config["OPTIMIZATION"]:
                self.EARLY_EXIT_ON_FINDING = config["OPTIMIZATION"].getboolean("EARLY_EXIT_ON_FINDING")

        if "SKEPTICAL_THRESHOLDS" in config:
            for key in config["SKEPTICAL_THRESHOLDS"]:
                self.SKEPTICAL_THRESHOLDS[key.upper()] = config["SKEPTICAL_THRESHOLDS"].getint(key)

    def load_from_conf(self):
        """Overrides settings with values from bugtraceaicli.conf"""
        import configparser
        config = configparser.ConfigParser()
        conf_path = self.BASE_DIR / "bugtraceaicli.conf"

        if not conf_path.exists():
            return

        config.read(conf_path)
        self._load_crawler_config(config)
        self._load_scan_config(config)
        self._load_parallelization_config(config)
        self._load_url_prioritization_config(config)
        self._load_llm_models_config(config)
        self._load_conductor_and_scanning_config(config)
        self._load_analysis_and_misc_config(config)

    # --- Configuration Validation (TASK-120) ---
    def validate_config(self) -> List[str]:
        """
        Validate entire configuration.
        Returns list of errors (empty if valid).
        Raises ValueError if critical errors found.
        """
        errors = []
        warnings = []

        # Check required API key
        if not self.OPENROUTER_API_KEY:
            errors.append("OPENROUTER_API_KEY is required")

        # Check numeric bounds
        if self.MAX_DEPTH < 1:
            errors.append("MAX_DEPTH must be >= 1")
        if self.MAX_URLS < 1:
            errors.append("MAX_URLS must be >= 1")
        if self.MAX_CONCURRENT_REQUESTS < 1:
            errors.append("MAX_CONCURRENT_REQUESTS must be >= 1")
        if self.MAX_CONCURRENT_URL_AGENTS < 1:
            errors.append("MAX_CONCURRENT_URL_AGENTS must be >= 1")

        # Granular phase concurrency validators
        if self.MAX_CONCURRENT_DISCOVERY < 1:
            errors.append("MAX_CONCURRENT_DISCOVERY must be >= 1")
        if self.MAX_CONCURRENT_ANALYSIS < 1:
            errors.append("MAX_CONCURRENT_ANALYSIS must be >= 1")
        if self.MAX_CONCURRENT_SPECIALISTS < 1:
            errors.append("MAX_CONCURRENT_SPECIALISTS must be >= 1")
        # MAX_CONCURRENT_VALIDATION is hardcoded to 1 (CDP limitation) - no validation needed

        # Check confidence thresholds (0.0 - 1.0)
        if not 0.0 <= self.CONDUCTOR_MIN_CONFIDENCE <= 1.0:
            errors.append("CONDUCTOR_MIN_CONFIDENCE must be 0.0-1.0")
        if not 0.0 <= self.ANALYSIS_CONFIDENCE_THRESHOLD <= 1.0:
            errors.append("ANALYSIS_CONFIDENCE_THRESHOLD must be 0.0-1.0")
        if not 0.0 <= self.ANALYSIS_SKIP_THRESHOLD <= 1.0:
            errors.append("ANALYSIS_SKIP_THRESHOLD must be 0.0-1.0")

        # Check file paths
        if not self.BASE_DIR.exists():
            errors.append(f"BASE_DIR does not exist: {self.BASE_DIR}")

        # Log warnings
        for w in warnings:
            logger.warning(f"Config warning: {w}")

        if errors:
            error_msg = "Configuration errors:\n" + "\n".join(f"  - {e}" for e in errors)
            logger.error(error_msg)
            raise ValueError(error_msg)

        return warnings

    # --- Secret Masking (TASK-118 additional) ---
    def mask_secrets(self) -> Dict[str, Any]:
        """Return config dict with masked secrets for safe logging."""
        masked = self.model_dump()
        secret_fields = ['OPENROUTER_API_KEY', 'GLM_API_KEY']
        for key in secret_fields:
            if masked.get(key):
                val = masked[key]
                if len(val) > 12:
                    masked[key] = val[:8] + '...' + val[-4:]
                else:
                    masked[key] = '***'
        return masked

    # --- Debug Logging (TASK-122) ---
    def log_config(self):
        """Log configuration with masked secrets (only in DEBUG mode)."""
        if not self.DEBUG:
            return
        logger.debug("Configuration loaded:")
        for key, value in self.mask_secrets().items():
            if not key.startswith('_') and key != 'model_config':
                logger.debug(f"  {key}: {value}")

    # --- Config Schema Documentation (TASK-123) ---
    def generate_config_docs(self) -> str:
        """Generate markdown documentation for all configuration fields."""
        docs = ["# BugTraceAI Configuration Reference\n"]
        docs.append(f"Generated: {datetime.now().isoformat()}\n")
        docs.append("---\n")

        for field_name, field_info in self.model_fields.items():
            if field_name.startswith('_'):
                continue
            docs.append(f"## {field_name}")
            docs.append(f"- **Type**: `{field_info.annotation}`")
            docs.append(f"- **Default**: `{field_info.default}`")
            if field_info.description:
                docs.append(f"- **Description**: {field_info.description}")
            docs.append("")

        return "\n".join(docs)

    # --- Config Export/Import (TASK-125) ---
    def export_config(self, path: Path = None) -> str:
        """Export configuration to JSON file."""
        config_data = {
            '_meta': {
                'version': self.VERSION,
                'exported_at': datetime.now().isoformat(),
                'env': self.ENV
            },
            'config': self.mask_secrets()  # Never export real secrets
        }
        json_str = json.dumps(config_data, indent=2, default=str)

        if path:
            path.write_text(json_str)
            logger.info(f"Config exported to {path}")

        return json_str

    def import_config(self, path: Path) -> Dict[str, Any]:
        """
        Import configuration from JSON file.
        Returns dict of changes that would be applied.
        Does NOT auto-apply - caller must decide.
        """
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        data = json.loads(path.read_text())
        config_data = data.get('config', data)

        changes = {}
        for key, value in config_data.items():
            if hasattr(self, key) and not key.startswith('_'):
                current = getattr(self, key)
                if current != value:
                    changes[key] = {'from': current, 'to': value}

        return changes

    # --- Config Diffing (TASK-126) ---
    def diff_config(self, other: 'Settings') -> Dict[str, Dict[str, Any]]:
        """Compare two configurations and return differences."""
        diff = {}
        for field_name in self.model_fields:
            if field_name.startswith('_'):
                continue
            self_val = getattr(self, field_name)
            other_val = getattr(other, field_name)
            if self_val != other_val:
                diff[field_name] = {
                    'self': self_val,
                    'other': other_val
                }
        return diff

    # --- Config Versioning (TASK-127) ---
    _config_history: List[Dict[str, Any]] = []

    def snapshot(self, label: str = None) -> Dict[str, Any]:
        """Take a snapshot of current configuration for versioning."""
        snapshot_data = {
            'timestamp': datetime.now().isoformat(),
            'label': label or f"snapshot_{len(self._config_history)}",
            'config': self.model_dump()
        }
        self._config_history.append(snapshot_data)
        logger.debug(f"Config snapshot taken: {snapshot_data['label']}")
        return snapshot_data

    def get_config_history(self) -> List[Dict[str, Any]]:
        """Get all configuration snapshots."""
        return self._config_history.copy()

    def restore_snapshot(self, index: int) -> Dict[str, str]:
        """
        Restore configuration from a snapshot.
        Returns dict of fields that were changed.
        """
        if index >= len(self._config_history):
            raise IndexError(f"Snapshot index {index} not found")

        snapshot = self._config_history[index]
        changes = {}

        for key, value in snapshot['config'].items():
            if hasattr(self, key) and not key.startswith('_'):
                current = getattr(self, key)
                if current != value:
                    changes[key] = f"{current} -> {value}"
                    object.__setattr__(self, key, value)

        logger.info(f"Restored config from snapshot: {snapshot['label']}")
        return changes

    # --- Environment-Specific Config Loading (TASK-124) ---
    def load_env_specific(self):
        """Load environment-specific .env file if exists."""
        env_file = f".env.{self.ENV}"
        env_path = self.BASE_DIR / env_file

        if env_path.exists():
            load_dotenv(env_path, override=True)
            logger.info(f"Loaded environment config: {env_file}")
        elif self.ENV != "production":
            logger.debug(f"No environment-specific config found: {env_file}")

    # --- Scan Configuration (Mapped from [SCAN] in conf) ---
    MAX_DEPTH: int = 2
    MAX_URLS: int = 20
    MAX_CONCURRENT_URL_AGENTS: int = 10  # Parallel URLMasterAgents (legacy, alias for SPECIALISTS)
    GOSPIDER_NO_REDIRECT: bool = False  # Don't follow redirects (catches .env, .htaccess leaks)

    # --- Granular Phase Concurrency (Phase 31: v2.4) ---
    MAX_CONCURRENT_DISCOVERY: int = 1      # GoSpider (single-threaded by design)
    MAX_CONCURRENT_ANALYSIS: int = 5       # DAST/SAST per URL
    MAX_CONCURRENT_SPECIALISTS: int = 10   # SQLi, XSS, CSTI paralelos
    # HARDCODED: CDP client only supports 1 concurrent session (crashes with more)
    # Playwright can handle multiple, but AgenticValidator uses CDP exclusively
    MAX_CONCURRENT_VALIDATION: int = 1     # DO NOT CHANGE - CDP limitation

    # --- URL Prioritization (Phase 38: v3.0) ---
    URL_PRIORITIZATION_ENABLED: bool = True   # Enable/disable URL prioritization
    URL_PRIORITIZATION_LOG_SCORES: bool = True  # Log priority scores for each URL
    URL_PRIORITIZATION_CUSTOM_PATHS: str = ""   # Custom high-priority paths (comma-separated)
    URL_PRIORITIZATION_CUSTOM_PARAMS: str = ""  # Custom high-priority params (comma-separated)

    # --- Visual / Browser ---
    HEADLESS_BROWSER: bool = True
    
    # --- Paths ---
    # Calculated relative to this file: bugtrace/core/config.py -> bugtrace/core -> bugtrace -> Root
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    
    # These can be overridden by env vars, but default to standard relative paths
    LOG_DIR_PATH: str = "logs"
    REPORT_DIR_PATH: str = "reports"
    
    # Database
    DATABASE_URL: str = "sqlite:///bugtrace.db"
    VECTOR_DB_PATH: str = "logs/lancedb"

    @property
    def LOG_DIR(self) -> Path:
        start = Path(self.LOG_DIR_PATH)
        if start.is_absolute(): return start
        return self.BASE_DIR / start

    @property
    def REPORT_DIR(self) -> Path:
        start = Path(self.REPORT_DIR_PATH)
        if start.is_absolute(): return start
        return self.BASE_DIR / start
        
    @property
    def database(self):
        """Compat helper for legacy access"""
        class DBConfig:
            url = self.DATABASE_URL
            vector_path = str(self.BASE_DIR / self.VECTOR_DB_PATH)
        return DBConfig()
        
    @property
    def global_config(self):
        """Self-reference for legacy compatibility where settings.global_config was used"""
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # Browser Advanced
    USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    VIEWPORT_WIDTH: int = 1280
    VIEWPORT_HEIGHT: int = 720
    TIMEOUT_MS: int = 15000
    
    # Crawler
    SPA_WAIT_MS: int = 1000
    MAX_QUEUE_SIZE: int = 100


# Singleton Instance
settings = Settings()
# Load environment-specific config first (TASK-124)
settings.load_env_specific()
# Load configuration from bugtraceaicli.conf
settings.load_from_conf()
# Log config in debug mode (TASK-122)
settings.log_config()


# --- Config File Watcher (TASK-121) ---
# Optional: Enable config hot-reload by setting BUGTRACE_WATCH_CONFIG=1
_config_watcher = None

def start_config_watcher():
    """Start watching config file for changes (requires watchdog package)."""
    global _config_watcher
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class ConfigFileHandler(FileSystemEventHandler):
            def __init__(self, config_path, callback):
                self.config_path = str(config_path)
                self.callback = callback

            def on_modified(self, event):
                if event.src_path == self.config_path:
                    logger.info("Config file changed, reloading...")
                    self.callback()

        def reload_config():
            settings.load_from_conf()
            settings.log_config()
            logger.info("Configuration reloaded successfully")

        conf_path = settings.BASE_DIR / "bugtraceaicli.conf"
        observer = Observer()
        observer.schedule(
            ConfigFileHandler(conf_path, reload_config),
            path=str(settings.BASE_DIR),
            recursive=False
        )
        observer.start()
        _config_watcher = observer
        logger.info("Config file watcher started")
        return observer
    except ImportError:
        logger.debug("watchdog not installed, config hot-reload disabled")
        return None

def stop_config_watcher():
    """Stop the config file watcher."""
    global _config_watcher
    if _config_watcher:
        _config_watcher.stop()
        _config_watcher.join()
        _config_watcher = None
        logger.info("Config file watcher stopped")

# Auto-start watcher if enabled
if os.environ.get('BUGTRACE_WATCH_CONFIG', '').lower() in ('1', 'true', 'yes'):
    start_config_watcher()
