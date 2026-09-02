from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, Field
from typing import Optional, List, Dict, Any
from pathlib import Path
import os
import re
import json
from datetime import datetime
from dotenv import load_dotenv

from bugtrace import __version__
from bugtrace.core.runtime_paths import (
    resolve_package_base_dir,
    resolve_runtime_root,
    test_mode_enabled,
    truthy_env as _truthy_env,
)
from bugtrace.utils.logger import get_logger

logger = get_logger("core.config")

# Re-export path helpers for existing callers (tests, boot, harnesses).
__all_runtime_path_exports__ = (
    "test_mode_enabled",
    "resolve_package_base_dir",
    "resolve_runtime_root",
)


# Load process .env only outside hermetic test mode. Tests inject env explicitly.
if not test_mode_enabled():
    load_dotenv()  # Force load .env

# Known valid providers for OpenRouter
VALID_PROVIDERS = [
    'google', 'openai', 'anthropic', 'meta', 'mistral',
    'qwen', 'deepseek', 'x-ai', 'cohere', 'perplexity',
    'nvidia', 'ai21', 'together', 'fireworks', 'groq',
    'moonshotai',
]

# Placeholder values that should be rejected
API_KEY_PLACEHOLDERS = ['your-key-here', 'placeholder', 'xxx', 'changeme', 'test', 'sk-xxx']

from bugtrace.core.config_loaders import SettingsLoadersMixin
from bugtrace.core.config_ops import SettingsOpsMixin

class Settings(SettingsLoadersMixin, SettingsOpsMixin, BaseSettings):
    """
    Unified Configuration Management using Pydantic Settings.
    Loads from .env file and environment variables.
    """
    # --- Project Metadata ---
    APP_NAME: str = "BugTraceAI-CLI"
    VERSION: str = __version__  # Synced from bugtrace.__version__
    # DEBUG used to read from the bare `DEBUG` env var, which collides with
    # Ubuntu's kernel `DEBUG=release` marker (set by the distribution when a
    # release kernel is booted). Pydantic v2 rejects "release" as a bool and
    # the entire Settings() init fails — taking the whole CLI down on stock
    # Ubuntu. We use validation_alias so the env var is now BUGTRACE_DEBUG and
    # the in-code attribute stays DEBUG (no caller has to change).
    DEBUG: bool = Field(default=False, validation_alias="BUGTRACE_DEBUG")
    SAFE_MODE: bool = False # Default to False, override via CLI

    # --- Environment (TASK-124) ---
    ENV: str = Field(default="production", description="Environment: development, staging, production")

    # --- LLM Provider Selection ---
    PROVIDER: str = "openrouter"  # Active provider preset id

    # --- API Keys (Secrets) with validation (TASK-118) ---
    OPENROUTER_API_KEY: Optional[str] = Field(default=None, min_length=32, description="OpenRouter API key")
    GLM_API_KEY: Optional[str] = Field(default=None, min_length=20, description="GLM API key")
    ANTHROPIC_API_KEY: Optional[str] = Field(default=None, min_length=20, description="Anthropic API key (sk-ant-...)")
    OPENAI_API_KEY: Optional[str] = Field(default=None, description="OpenAI-compatible API key (sk-... for OpenAI)")
    MINIMAX_API_KEY: Optional[str] = Field(default=None, description="MiniMax API key")
    
    # --- LLM Models ---
    DEFAULT_MODEL: str = "qwen/qwen3-coder"
    CODE_MODEL: str = "qwen/qwen3-coder"
    ANALYSIS_MODEL: str = "qwen/qwen3-coder"
    
    # --- AUTHORITY Configuration ---
    ENABLE_SELF_VALIDATION: bool = True
    XSS_SELF_VALIDATE: bool = True
    SQLI_SELF_VALIDATE: bool = True
    RCE_SELF_VALIDATE: bool = True

    # Number of models required to agree for "consensus"
    # 1 = highest sensitivity, 2 = more balanced, 3 = maximum precision
    CONSENSUS_VOTES: int = 1
    
    # Ordered list (Shifts if one fails)
    PRIMARY_MODELS: str = ""
    
    # Vision
    VISION_MODEL: str = ""
    
    # WAF
    WAF_DETECTION_MODELS: str = ""
    
    # Model for payload mutation (DeepSeek has fewer safety restrictions)
    MUTATION_MODEL: str = "x-ai/grok-4.3"
    
    MIN_CREDITS: float = 2.0
    MAX_CONCURRENT_REQUESTS: int = 1
    LLM_REQUEST_TIMEOUT: float = 30.0  # Seconds to wait for LLM API response (fail fast on slow models)

    # Model for skeptical analysis in DASTySAST agent
    SKEPTICAL_MODEL: str = "anthropic/claude-haiku-4.5"

    # Model for reporting (PoC enrichment, CVSS scoring - needs uncensored analysis)
    REPORTING_MODEL: str = "anthropic/claude-haiku-4.5"
    REPORTING_FAILOVER_ENABLED: bool = True         # reporting/enrichment falls back to a 2nd provider on primary failure
    REPORTING_FAILOVER_PROVIDER: str = "anthropic"  # provider preset id used ONLY for reporting failover (not scan-time)

    # Batch PoC enrichment (Phase 6: grouped by vuln type)
    REPORTING_POC_BATCH_SIZE: int = 10       # Max findings per LLM call within a group
    REPORTING_POC_TOKENS_PER_FINDING: int = 600  # Output tokens budget per finding
    REPORTING_POC_MIN_TOKENS: int = 2000     # Minimum max_tokens per batch call
    REPORTING_POC_MAX_TOKENS: int = 8000     # Ceiling to prevent overflow

    # ── Model Lab (model-eval benchmark) scoring calibration ──
    # The composite that ranks candidate models is QUALITY-DOMINANT. Weights are
    # normalized to sum 1.0 at read time, so partial/misconfigured sets stay safe.
    # Calibrated 2026-07-24 from real-scan ground truth: the previous perf-heavy
    # weighting (performance 0.35 > correctness 0.30) turned the ranking into a
    # pure latency sort whenever the rubric saturated (history run#5/#7). Latency
    # and cost are honest side axes now, not the decider. Bump SCORING_VERSION
    # whenever a weight/threshold changes so persisted runs stay self-describing.
    MODELLAB_SCORING_VERSION: str = "v2-quality"
    MODELLAB_W_CORRECTNESS: float = 0.40
    MODELLAB_W_SKEPTICISM: float = 0.30
    MODELLAB_W_COMPLIANCE: float = 0.15
    MODELLAB_W_PERFORMANCE: float = 0.15
    # Gate min correctness 6.0 (not 7.0): the re-anchored strict rubric lands a solid
    # "correct-and-complete" answer at ~6.5, so 7.0 wrongly failed 3/4 good models in the
    # 2026-07-24 validation run. 6.0 = "clearly below solid" without rejecting competent ones.
    MODELLAB_GATE_MIN_CORRECTNESS: float = 6.0
    MODELLAB_GATE_MIN_SKEPTICISM: float = 7.0
    MODELLAB_GATE_MIN_COMPLIANCE: float = 6.0
    MODELLAB_FAILURE_PENALTY: float = 3.0     # composite -= failure_rate * this
    MODELLAB_LATENCY_STAT: str = "median"     # central tendency for perf scoring: median | p95
    # MUTATION slot pick blends judge quality with payload diversity (the signal that
    # actually predicts real-scan MUTATION recall). Weight = diversity share, quality = 1-weight.
    MODELLAB_MUTATION_DIVERSITY_WEIGHT: float = 0.6

    # Skeptical Review Thresholds (0-10 scale)
    # CRITICAL vulns have LOWER thresholds to avoid missing them
    SKEPTICAL_THRESHOLDS: dict = {
        "RCE": 4,      # Critical - don't miss
        "SQL": 4,      # Critical - don't miss
        "XXE": 5,      # High risk
        "SSRF": 5,     # High risk
        "LFI": 5,      # High risk
        "XSS": 5,      # Medium, easy to verify
        "CSTI": 3,     # v3.2.1: Low threshold - needs specialist validation to confirm
        "SSTI": 3,     # v3.2.1: Low threshold - needs specialist validation to confirm
        "TEMPLATE": 3, # v3.2.1: Catch-all for template injection types
        "JWT": 6,      # Medium
        "FILE_UPLOAD": 6,  # Medium
        "IDOR": 6,     # Lower risk
        "DEFAULT": 5   # Fallback
    }

    # --- Anthropic OAuth (direct API, $0 on Pro/Max) ---
    ANTHROPIC_OAUTH_ENABLED: bool = False
    ANTHROPIC_TOKEN_FILE: str = "~/.bugtrace/auth.json"

    # --- False Positive Filtering (Phase 17: v2.3) ---
    FP_CONFIDENCE_THRESHOLD: float = 0.5  # Minimum fp_confidence to pass filtering (0.0-1.0)
    FP_SKEPTICAL_WEIGHT: float = 0.4  # Weight of skeptical_score in fp_confidence calc
    FP_VOTES_WEIGHT: float = 0.3  # Weight of votes in fp_confidence calc
    FP_EVIDENCE_WEIGHT: float = 0.3  # Weight of evidence quality in fp_confidence calc

    # --- LanceDB Embeddings ---
    LANCEDB_ENABLED: bool = True  # Store finding embeddings in LanceDB for cross-scan learning

    # --- DAST Analysis Timeout (Phase 38: v3.2) ---
    DAST_ANALYSIS_TIMEOUT: float = 180.0  # Seconds per URL analysis (probes + LLM)
    DAST_MAX_RETRIES: int = 5  # Max retry rounds for URLs missing dastysast JSON (pipeline stops if still missing)
    DAST_CONSECUTIVE_TIMEOUT_LIMIT: int = 5  # Auto-pause after N consecutive timeouts (target may be down)
    DAST_TIMEOUT_PERCENT_LIMIT: int = 75  # Auto-pause if >N% of URLs timeout (target unreliable)
    DAST_AUTO_RESUME_DELAY: int = 300  # Seconds to wait before auto-resuming after pause (0 = wait forever)

    # --- ThinkingConsolidationAgent settings (Phase 18: v2.3) ---
    THINKING_MODE: str = "streaming"  # "streaming" | "batch"
    THINKING_BATCH_SIZE: int = 50  # Max findings per batch in batch mode
    THINKING_BATCH_TIMEOUT: float = 5.0  # Seconds to wait before processing incomplete batch
    THINKING_DEDUP_WINDOW: int = 1000  # Max dedup keys to track (LRU eviction)
    THINKING_FP_THRESHOLD: float = 0.5  # Min fp_confidence to forward to specialists (configurable in .conf)
    THINKING_BACKPRESSURE_RETRIES: int = 3  # Max retries on queue full
    THINKING_BACKPRESSURE_DELAY: float = 0.5  # Seconds between retries
    THINKING_EMIT_EVENTS: bool = True  # Emit work_queued events

    # --- Embeddings Classification Configuration (Phase 42: v3.3) ---
    USE_EMBEDDINGS_CLASSIFICATION: bool = False  # Feature flag (start disabled for safety)
    EMBEDDINGS_CONFIDENCE_THRESHOLD: float = 0.75  # Min similarity to trust embeddings
    EMBEDDINGS_MANUAL_REVIEW_THRESHOLD: float = 0.60  # Flag for manual review
    EMBEDDINGS_LOG_CONFIDENCE: bool = True  # Log classification confidence scores

    # --- Semantic Dedup (in-scan near-duplicate collapse via bge embeddings) ---
    # Second, OPTIONAL dedup pass AFTER the exact-string key cache: collapses
    # near-duplicate findings the key missed (e.g. "Reflected XSS" vs "XSS",
    # "q" vs "query"), within the SAME specialist only, keeping the stronger
    # finding. Additive precision lever — zero behaviour change while OFF.
    SEMANTIC_DEDUP_ENABLED: bool = False  # Default OFF (skipped entirely on mock model)
    SEMANTIC_DEDUP_THRESHOLD: float = 0.92  # Cosine sim >= this => near-duplicate (high = only true dups)

    # --- Worker Pool Configuration (Phase 19: v2.3) ---
    WORKER_POOL_DEFAULT_SIZE: int = 5  # Default workers per specialist
    WORKER_POOL_XSS_SIZE: int = 8  # XSS-specific (high volume)
    WORKER_POOL_SQLI_SIZE: int = 5  # SQLi-specific
    WORKER_POOL_SHUTDOWN_TIMEOUT: float = 30.0  # Max seconds to drain on shutdown
    WORKER_POOL_DEQUEUE_TIMEOUT: float = 5.0  # Seconds to wait for queue item
    WORKER_POOL_EMIT_EVENTS: bool = True  # Emit vulnerability_detected events

    # --- Specialist Concurrency Control (Phase 20: WET→DRY) ---
    # REMOVED: SPECIALIST_MAX_CONCURRENT (duplicate of MAX_CONCURRENT_SPECIALISTS)
    # Use MAX_CONCURRENT_SPECIALISTS from .conf instead (loaded at line 388-389)

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
                     'ANALYSIS_BUG_BOUNTY_MODEL', 'ANALYSIS_AUDITOR_MODEL',
                     'ANALYSIS_RED_TEAM_MODEL', 'ANALYSIS_RESEARCHER_MODEL',
                     'VALIDATION_VISION_MODEL')
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

    @field_validator('DEFAULT_HEADERS_JSON')
    @classmethod
    def validate_default_headers_json(cls, v):
        """Validate DEFAULT_HEADERS_JSON parses cleanly. Empty string is OK.

        We refuse to start a scan if the configured global headers are
        malformed: silently ignoring the failure would make the user believe
        the headers are being sent when they are not, which can mask
        authentication and produce silent misconfiguration.
        """
        if not v:
            return v
        # Late import: config.py is loaded very early; utils may not be ready.
        from bugtrace.utils.headers import parse_default_headers_json, InvalidHeaderError
        try:
            parse_default_headers_json(v)
        except InvalidHeaderError as e:
            raise ValueError(str(e)) from e
        return v

    # --- OpenRouter Configuration ---
    OPENROUTER_ONLINE: bool = True  # Enable internet access for models
    
    # --- Conductor V2 Anti-Hallucination Configuration ---
    CONDUCTOR_DISABLE_VALIDATION: bool = False
    CONDUCTOR_CONTEXT_REFRESH_INTERVAL: int = 300  # seconds
    CONDUCTOR_MIN_CONFIDENCE: float = 0.6
    CONDUCTOR_ENABLE_FP_DETECTION: bool = True
    
    # --- CRAWLER Configuration (URL Filtering) ---
    CRAWLER_EXCLUDE_EXTENSIONS: str = ".js,.mjs,.css,.jpg,.jpeg,.png,.gif,.svg,.ico,.woff,.woff2,.ttf,.eot,.pdf,.zip,.rar,.mp3,.mp4,.webm,.webp"
    CRAWLER_INCLUDE_EXTENSIONS: str = ""  # Empty = analyze any URL not in EXCLUDE
    CRAWLER_JS_ENDPOINT_MINING: bool = True
    CRAWLER_JS_MAX_SCRIPTS: int = 10
    CRAWLER_JS_MAX_ENDPOINTS: int = 100
    CRAWLER_JS_MAX_RESPONSE_BYTES: int = 1048576
    CRAWLER_JS_FETCH_TIMEOUT: float = 10.0
    
    # --- SCANNING Configuration (Stop-on-Critical) ---
    STOP_ON_CRITICAL: bool = True
    CRITICAL_TYPES: str = "SQLi,RCE,XXE"
    MANDATORY_SQLMAP_VALIDATION: bool = True
    SKIP_VALIDATED_PARAMS: bool = True
    SCAN_DEPTH: str = "standard"  # quick, standard, thorough

    # --- Custom HTTP Headers ---
    # Global default headers sent with every scan request. Must be a JSON object.
    # Values may reference environment variables via ${VAR} syntax.
    # Sensitive headers (Authorization, Cookie) should NOT be set here — use
    # per-scan custom_headers or auth discovery instead.
    # Example: {"X-Bug-Bounty": "MyProgram", "X-Forwarded-For": "203.0.113.42"}
    DEFAULT_HEADERS_JSON: str = ""

    # --- XSS COVERAGE (negative evidence) ---
    # The escalation pipeline returns None both for "tested hard, found nothing" and for
    # "never tested". These write one AGGREGATED record per parameter — probes sent, marker
    # reflected, context set, payloads reflected, exit reason, rung reached — so the two are
    # distinguishable after the fact. Diagnostics only: never loaded as findings.
    XSS_COVERAGE_ENABLED: bool = True
    # Deliberately NOT specialists/{results,dry,wet} (four loaders ingest those as findings)
    # and not specialists/*_report.json (reporting.py globs that).
    XSS_COVERAGE_SUBDIR: str = "specialists/xss"
    XSS_COVERAGE_FILENAME: str = "xss_coverage.json"
    # Bound the artifact size — the report ZIP ships every byte to the customer. Truncation
    # is stated in the document itself and logged; it is never silent.
    XSS_COVERAGE_MAX_PARAMS: int = 500

    # --- ANALYSIS Configuration (Multi-Model URL Analysis) ---
    ANALYSIS_ENABLE: bool = True
    ANALYSIS_APPROACH_PENTESTER: bool = True
    ANALYSIS_APPROACH_BUG_BOUNTY: bool = True
    ANALYSIS_APPROACH_CODE_AUDITOR: bool = True
    ANALYSIS_APPROACH_RED_TEAM: bool = True
    ANALYSIS_APPROACH_RESEARCHER: bool = True
    APPROACH_MODE: str = "ALL"  # ALL = run all enabled, AUTO = wave-based (2+2, skip researcher)
    ANALYSIS_PENTESTER_MODEL: str = "qwen/qwen3-coder"
    ANALYSIS_BUG_BOUNTY_MODEL: str = "qwen/qwen3-coder"
    ANALYSIS_AUDITOR_MODEL: str = "qwen/qwen3-coder"
    ANALYSIS_RED_TEAM_MODEL: str = "google/gemini-3-flash-preview"
    ANALYSIS_RESEARCHER_MODEL: str = "google/gemini-3-flash-preview"
    ANALYSIS_CONFIDENCE_THRESHOLD: float = 0.7
    ANALYSIS_SKIP_THRESHOLD: float = 0.3
    ANALYSIS_CONSENSUS_VOTES: int = 2
    
    # --- VALIDATION Configuration (Vision-Based XSS Validation) ---
    VALIDATION_VISION_MODEL: str = "google/gemini-3-flash-preview"
    VALIDATION_VISION_ENABLED: bool = True
    VALIDATION_VISION_ONLY_FOR_XSS: bool = True
    VALIDATION_MAX_VISION_CALLS_PER_URL: int = 3

    # --- CDP Configuration (Chrome DevTools Protocol for XSS Validation) ---
    # Use CDP instead of Playwright for more reliable XSS detection
    CDP_ENABLED: bool = True  # Enable CDP as primary verification method
    CDP_PORT: int = 9222  # Chrome remote debugging port
    CDP_TIMEOUT: float = 5.0  # Time to wait for XSS execution (seconds)

    # --- JWT Agent Rate Limiting ---
    JWT_RATE_LIMIT_DELAY: float = 0.5  # Seconds to wait between JWT attack requests (prevents WAF triggers)

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

    # Detection Evidence panel budgets. Both are BOUNDS ON PRINTING, never on detection:
    # whatever they cut is still present verbatim in raw_findings.json, and the report
    # states the loss in-band rather than dropping it silently. 0 = unbounded.
    REPORT_EVIDENCE_MAX_FIELDS: int = 12    # evidence keys rendered per finding
    REPORT_EVIDENCE_VALUE_CHARS: int = 400  # characters rendered per evidence value

    # --- OPTIMIZATION Configuration ---
    # Early exit after first finding per URL (saves 70%+ scan time)
    # When True: Stop testing remaining params after first vuln found
    # When False: Test ALL params for comprehensive coverage
    # CHANGED (2026-02-01): Default to False for Burp-equivalent coverage
    EARLY_EXIT_ON_FINDING: bool = False

    # --- TRACING & OOB Configuration (v1.6) ---
    TRACING_ENABLED: bool = True
    INTERACTSH_SERVER: str = "oast.fun"
    INTERACTSH_POLL_INTERVAL: int = 60 # seconds

    # --- ANALYSIS STRATEGY Configuration (v2.7) ---
    # When True: Include raw reflection probe results in analysis reports
    # This forces analysis to be based on CONCRETE evidence, not speculation
    RAW_REFLECTIONS_IN_STRATEGY: bool = True

    # Run active reconnaissance probes BEFORE LLM analysis
    # Sends Omni-Probe to each parameter to detect reflection context
    ACTIVE_RECON_PROBES: bool = True

    # Omni-Probe marker for detecting reflections (unique string unlikely to exist)
    OMNI_PROBE_MARKER: str = "bugtraceomni7x9z"

    # Require evidence in analysis reports (prohibit vague statements)
    REQUIRE_EVIDENCE_IN_ANALYSIS: bool = True






        # NOTE: MAX_CONCURRENT_VALIDATION is NOT loaded from config
        # CDP client only supports 1 concurrent session - hardcoded in defaults



















    # --- Configuration Validation (TASK-120) ---

    # --- Secret Masking (TASK-118 additional) ---

    # --- Debug Logging (TASK-122) ---

    # --- Config Schema Documentation (TASK-123) ---

    # --- Config Export/Import (TASK-125) ---


    # --- Config Diffing (TASK-126) ---

    # --- Provider Config (loaded from preset JSON) ---
    _provider_config: Dict[str, Any] = {}

    # --- Config Versioning (TASK-127) ---
    _config_history: List[Dict[str, Any]] = []




    # --- Environment-Specific Config Loading (TASK-124) ---

    # --- Scan Configuration (Mapped from [SCAN] in conf) ---
    MAX_DEPTH: int = 2
    MAX_URLS: int = 20
    MAX_CONCURRENT_URL_AGENTS: int = 10  # Parallel URLMasterAgents (legacy, alias for SPECIALISTS)
    GOSPIDER_NO_REDIRECT: bool = False  # Don't follow redirects (catches .env, .htaccess leaks)
    GOSPIDER_USE_ARCHIVES: bool = True   # Query external archives (Wayback, CommonCrawl, VirusTotal) — disable for consistent results
    GOSPIDER_CONCURRENCY: int = 5        # GoSpider thread count (-c flag). Lower = more deterministic, higher = faster

    # --- Granular Phase Concurrency (Phase 31: v2.4) ---
    MAX_CONCURRENT_DISCOVERY: int = 1      # GoSpider (single-threaded by design)
    MAX_CONCURRENT_ANALYSIS: int = 5       # DAST/SAST per URL
    MAX_CONCURRENT_SPECIALISTS: int = 10   # SQLi, XSS, CSTI paralelos
    # JWT specialist head-start before other specialists (stable 891f012)
    JWT_HEAD_START_TIMEOUT: int = 300      # Seconds for JWTAgent crack/forge before Phase 4 pool
    # HARDCODED: CDP client only supports 1 concurrent session (crashes with more)
    # Playwright can handle multiple, but AgenticValidator uses CDP exclusively
    MAX_CONCURRENT_VALIDATION: int = 1     # DO NOT CHANGE - CDP limitation

    # --- Asset Discovery Configuration ---
    ENABLE_ASSET_DISCOVERY: bool = False
    ENABLE_DNS_ENUMERATION: bool = True
    ENABLE_CERTIFICATE_TRANSPARENCY: bool = True
    ENABLE_WAYBACK_DISCOVERY: bool = True
    ENABLE_CLOUD_STORAGE_ENUM: bool = True
    ENABLE_COMMON_PATHS: bool = True
    MAX_SUBDOMAINS: int = 50

    # --- URL Pattern Dedup ---
    URL_PATTERN_DEDUP: bool = True  # Collapse /products/1, /products/2 → keep 1 per pattern

    # --- URL Prioritization (Phase 38: v3.0) ---
    URL_PRIORITIZATION_ENABLED: bool = True   # Enable/disable URL prioritization
    URL_PRIORITIZATION_LOG_SCORES: bool = True  # Log priority scores for each URL
    URL_PRIORITIZATION_CUSTOM_PATHS: str = ""   # Custom high-priority paths (comma-separated)
    URL_PRIORITIZATION_CUSTOM_PARAMS: str = ""  # Custom high-priority params (comma-separated)

    # --- Visual / Browser ---
    HEADLESS_BROWSER: bool = True
    
    # --- Paths ---
    # Package/project root (conf, bugtrace/data). Writable runtime may use RUNTIME_ROOT.
    BASE_DIR: Path = Field(default_factory=resolve_package_base_dir)
    # When set (via BUGTRACE_TEST_ROOT / apply_runtime_root), data/logs/reports go here.
    RUNTIME_ROOT: Optional[Path] = Field(default_factory=resolve_runtime_root)

    # These can be overridden by env vars, but default to standard relative paths
    LOG_DIR_PATH: str = "logs"
    REPORT_DIR_PATH: str = "reports"
    
    # Database
    DATABASE_URL: str = "sqlite:///bugtrace.db"
    VECTOR_DB_PATH: str = "logs/lancedb"

    @property
    def LOG_DIR(self) -> Path:
        start = Path(self.LOG_DIR_PATH)
        if start.is_absolute():
            return start
        root = self.RUNTIME_ROOT or self.BASE_DIR
        return Path(root) / start

    @property
    def REPORT_DIR(self) -> Path:
        start = Path(self.REPORT_DIR_PATH)
        if start.is_absolute():
            return start
        root = self.RUNTIME_ROOT or self.BASE_DIR
        return Path(root) / start

    @property
    def DATA_DIR(self) -> Path:
        """SQLite and other mutable store directory (never package source tree under test)."""
        root = self.RUNTIME_ROOT or self.BASE_DIR
        return Path(root) / "data"
        
    @property
    def database(self):
        """Compat helper for legacy access"""
        class DBConfig:
            url = self.DATABASE_URL
            vector_path = str(self.LOG_DIR / "lancedb")
        return DBConfig()
        
    @property
    def global_config(self):
        """Self-reference for legacy compatibility where settings.global_config was used"""
        return self

    @field_validator("DEBUG", mode="before")
    @classmethod
    def _accept_bare_DEBUG_env_with_fallback(cls, v):
        """Backwards-compat: accept the bare `DEBUG` env var when BUGTRACE_DEBUG
        is unset. Lets users keep their existing .env files working.

        We tolerate values that aren't strict bools ("release", "1", "yes",
        etc.) so Ubuntu's kernel DEBUG marker doesn't crash Settings init.
        Only explicit BUGTRACE_DEBUG=true / =1 / =yes forces debug on.

        Precedence: BUGTRACE_DEBUG > DEBUG > False.
        """
        import os
        has_bugtrace = "BUGTRACE_DEBUG" in os.environ

        # v arrives already coerced by Pydantic's env adapter:
        # - BUGTRACE_DEBUG="true" → True
        # - BUGTRACE_DEBUG=""    → "0" (string) after Pydantic coercion
        # - BUGTRACE_DEBUG missing → False (the field default)
        if has_bugtrace:
            # User explicitly set the new alias. Use that value strictly.
            if isinstance(v, bool):
                return v
            lowered = str(v).strip().lower()
            if lowered in ("true", "1", "yes", "on"):
                return True
            if lowered in ("false", "0", "no", "off", "", "none", "null"):
                return False
            # Unrecognised string → False + one warning.
            import warnings
            warnings.warn(
                f"BUGTRACE_DEBUG={os.environ.get('BUGTRACE_DEBUG')!r} is not a "
                f"recognised bool; ignoring. Use BUGTRACE_DEBUG=true/1/yes or "
                f"false/0/no.",
                stacklevel=2,
            )
            return False

        # BUGTRACE_DEBUG is NOT set. Fall back to the legacy DEBUG env var.
        legacy = os.environ.get("DEBUG")
        if legacy is None:
            return False  # default
        lowered = str(legacy).strip().lower()
        if lowered in ("true", "1", "yes", "on"):
            return True
        # Anything else ("release", "0", etc.) → False. "release" is Ubuntu's
        # kernel debug marker — silently ignore it; a user who genuinely wants
        # debug on Ubuntu must set BUGTRACE_DEBUG=1.
        return False

    model_config = SettingsConfigDict(
        # In test mode, do not auto-read a worktree .env (credentials / live keys).
        env_file=None if test_mode_enabled() else ".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # Browser Advanced
    USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    VIEWPORT_WIDTH: int = 1280
    VIEWPORT_HEIGHT: int = 720
    TIMEOUT_MS: int = 15000

    # --- DOM Click Strategy (Open Redirect Phase B.2) ---
    DOM_CLICK_MAX_LINKS: int = 5       # Max onclick/hash links to click per strategy
    DOM_CLICK_MAX_TEXT_LINKS: int = 10  # Max text-based navigation links to click
    DOM_CLICK_WAIT_SEC: float = 2.0     # Seconds to wait after each click for JS redirect
    DOM_CLICK_INITIAL_WAIT_SEC: float = 1.0  # Seconds to wait after page load before clicking
    
    # Browser Advanced (v3.4)
    NAVIGATION_TIMEOUT_MS: int = 45000
    NETWORKIDLE_TIMEOUT_MS: int = 30000
    PAYLOAD_EXECUTION_WAIT_MS: int = 3000
    SCREENSHOT_TIMEOUT_MS: int = 5000
    SCREENSHOT_MAX_RETRIES: int = 3
    WAIT_STRATEGY: str = "simple"
    STAGGERED_WAIT_INITIAL: int = 3000
    STAGGERED_WAIT_EXTRA: int = 2000
    SCREENSHOT_FULL_PAGE: bool = False
    SCREENSHOT_ON_ERROR: bool = True

    # Crawler
    SPA_WAIT_MS: int = 1000
    MAX_QUEUE_SIZE: int = 100

    # --- MANIPULATOR Configuration (Intelligent Breakouts System) ---
    # Global rate limiting across XSS/CSTI Skills
    MANIPULATOR_GLOBAL_RATE_LIMIT: float = 2.0  # req/s total
    MANIPULATOR_RATE_LIMIT_MIN: float = 0.2  # Minimum req/s floor when throttled by 429
    MANIPULATOR_RATE_RECOVERY_THRESHOLD: int = 10  # Successful requests before rate recovery
    MANIPULATOR_USE_GLOBAL_RATE_LIMITER: bool = True
    MANIPULATOR_ENABLE_LLM_EXPANSION: bool = True
    MANIPULATOR_ENABLE_AGENTIC_FALLBACK: bool = False
    MANIPULATOR_BREAKOUT_PRIORITY_LEVEL: int = 3
    MANIPULATOR_MAX_LLM_PAYLOADS: int = 100

    # --- LONEWOLF Autonomous Agent Configuration ---
    LONEWOLF_ENABLED: bool = True            # Override via .conf [LONEWOLF] ENABLED
    LONEWOLF_MODEL: str = "moonshotai/kimi-k2.5"  # LLM for reasoning
    LONEWOLF_RATE_LIMIT: float = 1.0       # HTTP requests per second
    LONEWOLF_MAX_CONTEXT: int = 20         # Sliding window size (actions remembered)
    LONEWOLF_RESPONSE_TRUNCATE: int = 2000 # Max chars kept from HTTP responses
    LONEWOLF_MAX_CYCLES: int = 120         # Hard cap on reasoning cycles per scan
    LONEWOLF_NO_PROGRESS_LIMIT: int = 18   # Stop after N cycles with no new surface/finding
    LONEWOLF_RECENT_WINDOW: int = 6        # Raw-action tail size (KB carries persistent state)

    # --- IDOR Agent Configuration ---
    IDOR_ID_RANGE: str = "1-1000"  # Range of IDs to test (e.g., "1-1000", "1-500", "100-200")
    IDOR_CUSTOM_IDS: str = ""  # Comma-separated list of custom IDs (UUIDs, hashes, etc.)
    IDOR_QUEUE_BATCH_SIZE: int = 100  # Max items to process in one batch (streaming queue drain)
    IDOR_QUEUE_MAX_WAIT: float = 300.0  # Max seconds to wait for queue items
    IDOR_ENABLE_COOKIE_TAMPERING: bool = False  # Enable horizontal privilege escalation tests
    IDOR_SMART_ID_DETECTION: bool = True  # Auto-detect ID format and generate similar IDs
    IDOR_ENABLE_LLM_PREDICTION: bool = True  # Use LLM to predict likely IDOR target IDs
    IDOR_LLM_PREDICTION_COUNT: int = 20  # Number of IDs to generate via LLM
    IDOR_PREDICTION_PRIORITY: str = "llm_first"  # "llm_first" | "fuzzing_first" | "parallel"
    IDOR_ENABLE_LLM_VALIDATION: bool = True  # Use LLM to validate MEDIUM severity findings

    # --- IDOR Deep Exploitation Configuration ---
    IDOR_ENABLE_DEEP_EXPLOITATION: bool = True
    """Enable deep exploitation analysis for CRITICAL/HIGH IDOR findings."""

    IDOR_EXPLOITER_MODE: str = "full"
    """Exploitation mode: 'full' (phases 1-6), 'quick' (phases 1-3), 'safe' (phase 1 only)."""

    IDOR_EXPLOITER_ENABLE_WRITE_TESTS: bool = False
    """⚠️ DANGEROUS: Allow PUT/PATCH tests (can modify server data)."""

    IDOR_EXPLOITER_ENABLE_DELETE_TESTS: bool = False
    """⚠️ DANGEROUS: Allow DELETE tests (can delete server data)."""

    IDOR_EXPLOITER_MAX_HORIZONTAL_ENUM: int = 50
    """Maximum number of IDs to enumerate in horizontal escalation."""

    IDOR_EXPLOITER_SEVERITY_THRESHOLD: str = "HIGH"
    """Only exploit findings >= this severity. Options: CRITICAL, HIGH, MEDIUM."""

    IDOR_EXPLOITER_RATE_LIMIT: float = 0.5
    """Seconds between requests during exploitation (avoid WAF)."""

    IDOR_EXPLOITER_TIMEOUT: float = 10.0
    """HTTP request timeout during exploitation phases."""


from bugtrace.core.config_runtime import (
    ensure_runtime_directories,
    apply_runtime_root,
    start_config_watcher,
    stop_config_watcher,
)

# Singleton Instance
settings = Settings()
ensure_runtime_directories(settings.RUNTIME_ROOT)
# Load environment-specific config first (TASK-124)
settings.load_env_specific()
# Load configuration from bugtraceaicli.conf
settings.load_from_conf()
# Log config in debug mode (TASK-122)
settings.log_config()

# Auto-start watcher if enabled (never in hermetic test mode)
if not test_mode_enabled() and _truthy_env("BUGTRACE_WATCH_CONFIG"):
    start_config_watcher()
