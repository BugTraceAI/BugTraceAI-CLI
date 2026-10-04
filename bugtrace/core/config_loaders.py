"""Settings loaders extracted from config.Settings for LOC policy."""

from __future__ import annotations

import configparser
import json
from typing import Any, Dict, List, Optional
from pathlib import Path

from dotenv import load_dotenv

from bugtrace.core.runtime_paths import test_mode_enabled
from bugtrace.utils.logger import get_logger

logger = get_logger("core.config")


class SettingsLoadersMixin:
    """Config file / provider / section loaders for Settings."""

    def _load_core_config(self, config):
        """Load CORE section config (DEBUG, SAFE_MODE)."""
        if "CORE" not in config:
            return
        section = config["CORE"]
        if "DEBUG" in section:
            self.DEBUG = section.getboolean("DEBUG")
        if "SAFE_MODE" in section:
            self.SAFE_MODE = section.getboolean("SAFE_MODE")
    def _load_crawler_config(self, config):
        """Load CRAWLER section config."""
        if "CRAWLER" not in config:
            return
        section = config["CRAWLER"]
        if "EXCLUDE_EXTENSIONS" in section:
            self.CRAWLER_EXCLUDE_EXTENSIONS = section["EXCLUDE_EXTENSIONS"]
        if "INCLUDE_EXTENSIONS" in section:
            self.CRAWLER_INCLUDE_EXTENSIONS = section["INCLUDE_EXTENSIONS"]
        if "SPA_WAIT_MS" in section:
            self.SPA_WAIT_MS = section.getint("SPA_WAIT_MS")
        if "MAX_QUEUE_SIZE" in section:
            self.MAX_QUEUE_SIZE = section.getint("MAX_QUEUE_SIZE")
        if "JS_ENDPOINT_MINING" in section:
            self.CRAWLER_JS_ENDPOINT_MINING = section.getboolean("JS_ENDPOINT_MINING")
        if "JS_MAX_SCRIPTS" in section:
            self.CRAWLER_JS_MAX_SCRIPTS = section.getint("JS_MAX_SCRIPTS")
        if "JS_MAX_ENDPOINTS" in section:
            self.CRAWLER_JS_MAX_ENDPOINTS = section.getint("JS_MAX_ENDPOINTS")
        if "JS_MAX_RESPONSE_BYTES" in section:
            self.CRAWLER_JS_MAX_RESPONSE_BYTES = section.getint("JS_MAX_RESPONSE_BYTES")
        if "JS_FETCH_TIMEOUT" in section:
            self.CRAWLER_JS_FETCH_TIMEOUT = section.getfloat("JS_FETCH_TIMEOUT")
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
        if "GOSPIDER_USE_ARCHIVES" in config["SCAN"]:
            self.GOSPIDER_USE_ARCHIVES = config["SCAN"].getboolean("GOSPIDER_USE_ARCHIVES")
        if "GOSPIDER_CONCURRENCY" in config["SCAN"]:
            self.GOSPIDER_CONCURRENCY = config["SCAN"].getint("GOSPIDER_CONCURRENCY")
        if "URL_PATTERN_DEDUP" in config["SCAN"]:
            self.URL_PATTERN_DEDUP = config["SCAN"].getboolean("URL_PATTERN_DEDUP")
        if "DEFAULT_HEADERS_JSON" in config["SCAN"]:
            # Pydantic's field_validator ran at construction time and the value
            # was empty; now that the .conf has been parsed, re-validate the
            # value. parse_default_headers_json() raises InvalidHeaderError on
            # malformed input, but the validator already cleared the .conf value
            # if it was present at import time. Re-running it here re-surfaces
            # the user's .conf value (and any failure) for the real scan start.
            raw = config["SCAN"]["DEFAULT_HEADERS_JSON"].strip()
            if raw:
                from bugtrace.utils.headers import parse_default_headers_json
                try:
                    parsed = parse_default_headers_json(raw)
                    # Serialise back the canonical form so get_effective_headers
                    # can re-parse it via the same path.
                    self.DEFAULT_HEADERS_JSON = raw
                except Exception as exc:
                    # Fail loudly: a malformed .conf header MUST stop the scan,
                    # not be silently ignored. The user wrote a bad config; the
                    # right thing to do is refuse to start.
                    raise ValueError(
                        f"DEFAULT_HEADERS_JSON in [SCAN] is invalid: {exc}. "
                        f"Refusing to start: a malformed global header config "
                        f"could mask missing authentication and produce silent "
                        f"scan misconfiguration."
                    ) from exc
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
        if "JWT_HEAD_START_TIMEOUT" in section:
            self.JWT_HEAD_START_TIMEOUT = section.getint("JWT_HEAD_START_TIMEOUT")
        if "LANCEDB_ENABLED" in section:
            self.LANCEDB_ENABLED = section.getboolean("LANCEDB_ENABLED")
        if "DAST_ANALYSIS_TIMEOUT" in section:
            self.DAST_ANALYSIS_TIMEOUT = section.getfloat("DAST_ANALYSIS_TIMEOUT")
        if "DAST_MAX_RETRIES" in section:
            self.DAST_MAX_RETRIES = section.getint("DAST_MAX_RETRIES")
        if "DAST_CONSECUTIVE_TIMEOUT_LIMIT" in section:
            self.DAST_CONSECUTIVE_TIMEOUT_LIMIT = section.getint("DAST_CONSECUTIVE_TIMEOUT_LIMIT")
        if "DAST_TIMEOUT_PERCENT_LIMIT" in section:
            self.DAST_TIMEOUT_PERCENT_LIMIT = section.getint("DAST_TIMEOUT_PERCENT_LIMIT")
        if "DAST_AUTO_RESUME_DELAY" in section:
            self.DAST_AUTO_RESUME_DELAY = section.getint("DAST_AUTO_RESUME_DELAY")
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
    def _load_thinking_config(self, config):
        """Load THINKING section config for ThinkingConsolidationAgent."""
        if "THINKING" not in config:
            return
        section = config["THINKING"]
        if "FP_THRESHOLD" in section:
            self.THINKING_FP_THRESHOLD = section.getfloat("FP_THRESHOLD")
        if "MODE" in section:
            self.THINKING_MODE = section["MODE"].strip()
        if "BATCH_SIZE" in section:
            self.THINKING_BATCH_SIZE = section.getint("BATCH_SIZE")
        if "DEDUP_WINDOW" in section:
            self.THINKING_DEDUP_WINDOW = section.getint("DEDUP_WINDOW")
        # NEW: Embeddings classification settings
        if "USE_EMBEDDINGS_CLASSIFICATION" in section:
            self.USE_EMBEDDINGS_CLASSIFICATION = section.getboolean("USE_EMBEDDINGS_CLASSIFICATION")
        if "EMBEDDINGS_CONFIDENCE_THRESHOLD" in section:
            self.EMBEDDINGS_CONFIDENCE_THRESHOLD = section.getfloat("EMBEDDINGS_CONFIDENCE_THRESHOLD")
        if "EMBEDDINGS_MANUAL_REVIEW_THRESHOLD" in section:
            self.EMBEDDINGS_MANUAL_REVIEW_THRESHOLD = section.getfloat("EMBEDDINGS_MANUAL_REVIEW_THRESHOLD")
        if "EMBEDDINGS_LOG_CONFIDENCE" in section:
            self.EMBEDDINGS_LOG_CONFIDENCE = section.getboolean("EMBEDDINGS_LOG_CONFIDENCE")
    def _load_provider_section(self, config):
        """Load [PROVIDER] section — sets self.PROVIDER."""
        if "PROVIDER" not in config:
            return
        section = config["PROVIDER"]
        if "ACTIVE" in section:
            self.PROVIDER = section["ACTIVE"].strip().lower()
    def _load_provider_preset(self):
        """Load provider preset JSON and set model defaults.

        Called BEFORE _load_llm_models_config so user overrides in
        [LLM_MODELS] take precedence over preset defaults.
        """
        preset_path = self.BASE_DIR / "bugtrace" / "data" / "providers" / f"{self.PROVIDER}.json"
        if not preset_path.exists():
            logger.warning(f"Provider preset not found: {preset_path} — using defaults")
            self._provider_config = {}
            return

        try:
            preset = json.loads(preset_path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to load provider preset {preset_path}: {e}")
            self._provider_config = {}
            return

        self._provider_config = preset

        # Apply model defaults from preset
        models = preset.get("models", {})
        for field, value in models.items():
            if hasattr(self, field):
                object.__setattr__(self, field, value)

        # Vision validation must run on a model the ACTIVE provider actually serves:
        # a slug belonging to another provider is rejected outright (HTTP 404), not
        # degraded, which silently disables visual XSS proof. Presets that do not pin
        # VALIDATION_VISION_MODEL inherit their own VISION_MODEL rather than keeping
        # whatever the previous provider left behind.
        if "VALIDATION_VISION_MODEL" not in models and "VISION_MODEL" in models:
            object.__setattr__(self, "VALIDATION_VISION_MODEL", models["VISION_MODEL"])

        logger.info(f"Provider preset loaded: {preset.get('name', self.PROVIDER)} ({len(models)} model defaults)")
    def _load_llm_models_config(self, config):
        """Load LLM_MODELS section config.

        When a non-default provider is active, model overrides from [LLM_MODELS]
        are skipped — the provider preset already set the correct models.
        Only numeric/non-model settings (MIN_CREDITS, batch sizes) still apply.
        """
        if "LLM_MODELS" not in config:
            return
        section = config["LLM_MODELS"]

        # Skip model overrides when a provider preset is active —
        # the preset already configured the right models for this provider.
        # Users can still override via env vars if needed.
        if not self._provider_config:
            # No preset loaded, apply conf overrides as before
            model_fields = [
                "DEFAULT_MODEL", "PRIMARY_MODELS", "VISION_MODEL",
                "WAF_DETECTION_MODELS", "CODE_MODEL", "MUTATION_MODEL",
                "ANALYSIS_MODEL", "SKEPTICAL_MODEL", "REPORTING_MODEL",
            ]
            for field in model_fields:
                if field in section:
                    setattr(self, field, section[field])
        else:
            logger.debug(f"Skipping [LLM_MODELS] overrides — provider preset '{self.PROVIDER}' is active")
        if "MIN_CREDITS" in section:
            self.MIN_CREDITS = section.getfloat("MIN_CREDITS")
        if "MAX_CONCURRENT_REQUESTS" in section:
            self.MAX_CONCURRENT_REQUESTS = section.getint("MAX_CONCURRENT_REQUESTS")
        if "REPORTING_POC_BATCH_SIZE" in section:
            self.REPORTING_POC_BATCH_SIZE = section.getint("REPORTING_POC_BATCH_SIZE")
        if "REPORTING_POC_TOKENS_PER_FINDING" in section:
            self.REPORTING_POC_TOKENS_PER_FINDING = section.getint("REPORTING_POC_TOKENS_PER_FINDING")
        if "REPORTING_POC_MIN_TOKENS" in section:
            self.REPORTING_POC_MIN_TOKENS = section.getint("REPORTING_POC_MIN_TOKENS")
        if "REPORTING_POC_MAX_TOKENS" in section:
            self.REPORTING_POC_MAX_TOKENS = section.getint("REPORTING_POC_MAX_TOKENS")
        if "REPORTING_FAILOVER_ENABLED" in section:
            self.REPORTING_FAILOVER_ENABLED = section.getboolean("REPORTING_FAILOVER_ENABLED")
        if "REPORTING_FAILOVER_PROVIDER" in section:
            self.REPORTING_FAILOVER_PROVIDER = section["REPORTING_FAILOVER_PROVIDER"].strip()
    def _load_modellab_config(self, config):
        """Load [MODELLAB] section: model-eval benchmark scoring calibration.

        These knobs are independent of provider presets (ModelLab may run with its
        own key), so they are always applied when present. Weights are normalized
        downstream in the runner, so any non-negative set is safe.
        """
        if "MODELLAB" not in config:
            return
        section = config["MODELLAB"]
        float_fields = [
            "MODELLAB_W_CORRECTNESS", "MODELLAB_W_SKEPTICISM",
            "MODELLAB_W_COMPLIANCE", "MODELLAB_W_PERFORMANCE",
            "MODELLAB_GATE_MIN_CORRECTNESS", "MODELLAB_GATE_MIN_SKEPTICISM",
            "MODELLAB_GATE_MIN_COMPLIANCE", "MODELLAB_FAILURE_PENALTY",
            "MODELLAB_MUTATION_DIVERSITY_WEIGHT",
        ]
        for field in float_fields:
            if field in section:
                try:
                    setattr(self, field, section.getfloat(field))
                except ValueError:
                    logger.warning(f"[MODELLAB] {field} is not a number; keeping default")
        if "MODELLAB_SCORING_VERSION" in section:
            self.MODELLAB_SCORING_VERSION = section["MODELLAB_SCORING_VERSION"].strip()
        if "MODELLAB_LATENCY_STAT" in section:
            stat = section["MODELLAB_LATENCY_STAT"].strip().lower()
            self.MODELLAB_LATENCY_STAT = stat if stat in ("median", "p95") else self.MODELLAB_LATENCY_STAT
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
            if "SCAN_DEPTH" in section:
                val = section["SCAN_DEPTH"].strip().lower()
                if val in ("quick", "standard", "thorough"):
                    self.SCAN_DEPTH = val
            if "XSS_COVERAGE_ENABLED" in section:
                self.XSS_COVERAGE_ENABLED = section.getboolean("XSS_COVERAGE_ENABLED")
            if "XSS_COVERAGE_SUBDIR" in section:
                self.XSS_COVERAGE_SUBDIR = section["XSS_COVERAGE_SUBDIR"].strip()
            if "XSS_COVERAGE_FILENAME" in section:
                self.XSS_COVERAGE_FILENAME = section["XSS_COVERAGE_FILENAME"].strip()
            if "XSS_COVERAGE_MAX_PARAMS" in section:
                self.XSS_COVERAGE_MAX_PARAMS = section.getint("XSS_COVERAGE_MAX_PARAMS")
    def _load_authority_config(self, config):
        """Load AUTHORITY section config."""
        if "AUTHORITY" not in config:
            return
        section = config["AUTHORITY"]
        if "ENABLE_SELF_VALIDATION" in section:
            self.ENABLE_SELF_VALIDATION = section.getboolean("ENABLE_SELF_VALIDATION")
        if "XSS_SELF_VALIDATE" in section:
            self.XSS_SELF_VALIDATE = section.getboolean("XSS_SELF_VALIDATE")
        if "SQLI_SELF_VALIDATE" in section:
            self.SQLI_SELF_VALIDATE = section.getboolean("SQLI_SELF_VALIDATE")
        if "RCE_SELF_VALIDATE" in section:
            self.RCE_SELF_VALIDATE = section.getboolean("RCE_SELF_VALIDATE")
    def _load_lonewolf_config(self, config):
        """Load LONEWOLF section config."""
        if "LONEWOLF" not in config:
            return
        section = config["LONEWOLF"]
        if "ENABLED" in section:
            self.LONEWOLF_ENABLED = section.getboolean("ENABLED")
        if "MODEL" in section:
            self.LONEWOLF_MODEL = section["MODEL"]
        if "RATE_LIMIT" in section:
            self.LONEWOLF_RATE_LIMIT = section.getfloat("RATE_LIMIT")
        if "MAX_CONTEXT" in section:
            self.LONEWOLF_MAX_CONTEXT = section.getint("MAX_CONTEXT")
        if "RESPONSE_TRUNCATE" in section:
            self.LONEWOLF_RESPONSE_TRUNCATE = section.getint("RESPONSE_TRUNCATE")
        if "MAX_CYCLES" in section:
            self.LONEWOLF_MAX_CYCLES = section.getint("MAX_CYCLES")
        if "NO_PROGRESS_LIMIT" in section:
            self.LONEWOLF_NO_PROGRESS_LIMIT = section.getint("NO_PROGRESS_LIMIT")
        if "RECENT_WINDOW" in section:
            self.LONEWOLF_RECENT_WINDOW = section.getint("RECENT_WINDOW")
    def _load_anthropic_config(self, config):
        """Load ANTHROPIC section config for direct Claude API via OAuth."""
        if "ANTHROPIC" not in config:
            return
        section = config["ANTHROPIC"]
        if "ENABLED" in section:
            self.ANTHROPIC_OAUTH_ENABLED = section.getboolean("ENABLED")
        if "TOKEN_FILE" in section:
            self.ANTHROPIC_TOKEN_FILE = section["TOKEN_FILE"].strip()
    def _load_validation_config(self, config):
        """Load VALIDATION section config for Vision-Based XSS Validation."""
        if "VALIDATION" not in config:
            return
        section = config["VALIDATION"]
        if "VISION_MODEL" in section:
            # Mirror _load_llm_models_config: when a provider preset is active it has
            # already selected a vision model that provider serves, so a conf value
            # left over from another provider must not overwrite it (it would be a
            # hard 404 on every vision call). Users can still override via env vars.
            if not self._provider_config:
                self.VALIDATION_VISION_MODEL = section["VISION_MODEL"]
            else:
                logger.debug(
                    f"Skipping [VALIDATION] VISION_MODEL override — provider preset "
                    f"'{self.PROVIDER}' is active (using {self.VALIDATION_VISION_MODEL})"
                )
        if "VISION_ENABLED" in section:
            self.VALIDATION_VISION_ENABLED = section.getboolean("VISION_ENABLED")
        if "VISION_ONLY_FOR_XSS" in section:
            self.VALIDATION_VISION_ONLY_FOR_XSS = section.getboolean("VISION_ONLY_FOR_XSS")
        if "MAX_VISION_CALLS_PER_URL" in section:
            self.VALIDATION_MAX_VISION_CALLS_PER_URL = section.getint("MAX_VISION_CALLS_PER_URL")
    def _load_qlearning_config(self, config):
        """Load QLEARNING section config for WAF bypass system."""
        if "QLEARNING" not in config:
            return
        section = config["QLEARNING"]
        if "INITIAL_EPSILON" in section:
            self.WAF_QLEARNING_INITIAL_EPSILON = section.getfloat("INITIAL_EPSILON")
        if "MIN_EPSILON" in section:
            self.WAF_QLEARNING_MIN_EPSILON = section.getfloat("MIN_EPSILON")
        if "DECAY_RATE" in section:
            self.WAF_QLEARNING_DECAY_RATE = section.getfloat("DECAY_RATE")
        if "UCB_CONSTANT" in section:
            self.WAF_QLEARNING_UCB_CONSTANT = section.getfloat("UCB_CONSTANT")
        if "MAX_BACKUPS" in section:
            self.WAF_QLEARNING_MAX_BACKUPS = section.getint("MAX_BACKUPS")
    def _load_manipulator_config(self, config):
        """Load MANIPULATOR section config for HTTP Exploitation Tool."""
        if "MANIPULATOR" not in config:
            return
        section = config["MANIPULATOR"]
        if "GLOBAL_RATE_LIMIT" in section:
            self.MANIPULATOR_GLOBAL_RATE_LIMIT = section.getfloat("GLOBAL_RATE_LIMIT")
        if "USE_GLOBAL_RATE_LIMITER" in section:
            self.MANIPULATOR_USE_GLOBAL_RATE_LIMITER = section.getboolean("USE_GLOBAL_RATE_LIMITER")
        if "ENABLE_LLM_EXPANSION" in section:
            self.MANIPULATOR_ENABLE_LLM_EXPANSION = section.getboolean("ENABLE_LLM_EXPANSION")
        if "ENABLE_AGENTIC_FALLBACK" in section:
            self.MANIPULATOR_ENABLE_AGENTIC_FALLBACK = section.getboolean("ENABLE_AGENTIC_FALLBACK")
        if "BREAKOUT_PRIORITY_LEVEL" in section:
            self.MANIPULATOR_BREAKOUT_PRIORITY_LEVEL = section.getint("BREAKOUT_PRIORITY_LEVEL")
        if "MAX_LLM_PAYLOADS" in section:
            self.MANIPULATOR_MAX_LLM_PAYLOADS = section.getint("MAX_LLM_PAYLOADS")
    def _load_asset_discovery_config(self, config):
        """Load ASSET_DISCOVERY section config."""
        if "ASSET_DISCOVERY" not in config:
            return
        section = config["ASSET_DISCOVERY"]
        if "ENABLE_ASSET_DISCOVERY" in section:
            self.ENABLE_ASSET_DISCOVERY = section.getboolean("ENABLE_ASSET_DISCOVERY")
        if "ENABLE_DNS_ENUMERATION" in section:
            self.ENABLE_DNS_ENUMERATION = section.getboolean("ENABLE_DNS_ENUMERATION")
        if "ENABLE_CERTIFICATE_TRANSPARENCY" in section:
            self.ENABLE_CERTIFICATE_TRANSPARENCY = section.getboolean("ENABLE_CERTIFICATE_TRANSPARENCY")
        if "ENABLE_WAYBACK_DISCOVERY" in section:
            self.ENABLE_WAYBACK_DISCOVERY = section.getboolean("ENABLE_WAYBACK_DISCOVERY")
        if "ENABLE_CLOUD_STORAGE_ENUM" in section:
            self.ENABLE_CLOUD_STORAGE_ENUM = section.getboolean("ENABLE_CLOUD_STORAGE_ENUM")
        if "ENABLE_COMMON_PATHS" in section:
            self.ENABLE_COMMON_PATHS = section.getboolean("ENABLE_COMMON_PATHS")
        if "MAX_SUBDOMAINS" in section:
            self.MAX_SUBDOMAINS = section.getint("MAX_SUBDOMAINS")
    def _load_paths_config(self, config):
        """Load PATHS section config for LOG_DIR and REPORT_DIR.

        This ensures paths defined in bugtraceaicli.conf are properly loaded.
        Without this, LOG_DIR and REPORT_DIR from [PATHS] section are ignored.
        """
        if "PATHS" not in config:
            return
        section = config["PATHS"]
        if "LOG_DIR" in section:
            self.LOG_DIR_PATH = section["LOG_DIR"].strip()
        if "REPORT_DIR" in section:
            self.REPORT_DIR_PATH = section["REPORT_DIR"].strip()
    def _load_analysis_and_misc_config(self, config):
        """Load ANALYSIS, BROWSER, ADVANCED, REPORT, OPTIMIZATION sections."""
        if "ANALYSIS" in config:
            section = config["ANALYSIS"]
            if "ENABLE_ANALYSIS" in section:
                self.ANALYSIS_ENABLE = section.getboolean("ENABLE_ANALYSIS")
            if "APPROACH_PENTESTER" in section:
                self.ANALYSIS_APPROACH_PENTESTER = section.getboolean("APPROACH_PENTESTER")
            if "APPROACH_BUG_BOUNTY" in section:
                self.ANALYSIS_APPROACH_BUG_BOUNTY = section.getboolean("APPROACH_BUG_BOUNTY")
            if "APPROACH_CODE_AUDITOR" in section:
                self.ANALYSIS_APPROACH_CODE_AUDITOR = section.getboolean("APPROACH_CODE_AUDITOR")
            if "APPROACH_RED_TEAM" in section:
                self.ANALYSIS_APPROACH_RED_TEAM = section.getboolean("APPROACH_RED_TEAM")
            if "APPROACH_RESEARCHER" in section:
                self.ANALYSIS_APPROACH_RESEARCHER = section.getboolean("APPROACH_RESEARCHER")
            if "APPROACH_MODE" in section:
                self.APPROACH_MODE = section["APPROACH_MODE"].strip().upper()
            if "PENTESTER_MODEL" in section:
                self.ANALYSIS_PENTESTER_MODEL = section["PENTESTER_MODEL"]
            if "BUG_BOUNTY_MODEL" in section:
                self.ANALYSIS_BUG_BOUNTY_MODEL = section["BUG_BOUNTY_MODEL"]
            if "AUDITOR_MODEL" in section:
                self.ANALYSIS_AUDITOR_MODEL = section["AUDITOR_MODEL"]
            if "RED_TEAM_MODEL" in section:
                self.ANALYSIS_RED_TEAM_MODEL = section["RED_TEAM_MODEL"]
            if "RESEARCHER_MODEL" in section:
                self.ANALYSIS_RESEARCHER_MODEL = section["RESEARCHER_MODEL"]
            if "CONFIDENCE_THRESHOLD" in section:
                self.ANALYSIS_CONFIDENCE_THRESHOLD = section.getfloat("CONFIDENCE_THRESHOLD")
            if "SKIP_THRESHOLD" in section:
                self.ANALYSIS_SKIP_THRESHOLD = section.getfloat("SKIP_THRESHOLD")
            if "CONSENSUS_VOTES" in section:
                self.ANALYSIS_CONSENSUS_VOTES = section.getint("CONSENSUS_VOTES")
            if "DAST_ANALYSIS_TIMEOUT" in section:
                self.DAST_ANALYSIS_TIMEOUT = section.getfloat("DAST_ANALYSIS_TIMEOUT")

        if "BROWSER" in config:
            section = config["BROWSER"]
            if "HEADLESS" in section:
                self.HEADLESS_BROWSER = section.getboolean("HEADLESS")
            if "USER_AGENT" in section:
                self.USER_AGENT = section["USER_AGENT"]
            if "VIEWPORT_WIDTH" in section:
                self.VIEWPORT_WIDTH = section.getint("VIEWPORT_WIDTH")
            if "VIEWPORT_HEIGHT" in section:
                self.VIEWPORT_HEIGHT = section.getint("VIEWPORT_HEIGHT")
            if "TIMEOUT_MS" in section:
                self.TIMEOUT_MS = section.getint("TIMEOUT_MS")
            if "DOM_CLICK_MAX_LINKS" in section:
                self.DOM_CLICK_MAX_LINKS = section.getint("DOM_CLICK_MAX_LINKS")
            if "DOM_CLICK_MAX_TEXT_LINKS" in section:
                self.DOM_CLICK_MAX_TEXT_LINKS = section.getint("DOM_CLICK_MAX_TEXT_LINKS")
            if "DOM_CLICK_WAIT_SEC" in section:
                self.DOM_CLICK_WAIT_SEC = section.getfloat("DOM_CLICK_WAIT_SEC")
            if "DOM_CLICK_INITIAL_WAIT_SEC" in section:
                self.DOM_CLICK_INITIAL_WAIT_SEC = section.getfloat("DOM_CLICK_INITIAL_WAIT_SEC")

        if "ADVANCED" in config:
            if "TRACING_ENABLED" in config["ADVANCED"]:
                self.TRACING_ENABLED = config["ADVANCED"].getboolean("TRACING_ENABLED")
            if "INTERACTSH_SERVER" in config["ADVANCED"]:
                self.INTERACTSH_SERVER = config["ADVANCED"]["INTERACTSH_SERVER"]
        
        if "BROWSER_ADVANCED" in config:
            section = config["BROWSER_ADVANCED"]
            if "NAVIGATION_TIMEOUT_MS" in section:
                self.NAVIGATION_TIMEOUT_MS = section.getint("NAVIGATION_TIMEOUT_MS")
            if "NETWORKIDLE_TIMEOUT_MS" in section:
                self.NETWORKIDLE_TIMEOUT_MS = section.getint("NETWORKIDLE_TIMEOUT_MS")
            if "PAYLOAD_EXECUTION_WAIT_MS" in section:
                self.PAYLOAD_EXECUTION_WAIT_MS = section.getint("PAYLOAD_EXECUTION_WAIT_MS")
            if "SCREENSHOT_TIMEOUT_MS" in section:
                self.SCREENSHOT_TIMEOUT_MS = section.getint("SCREENSHOT_TIMEOUT_MS")
            if "SCREENSHOT_MAX_RETRIES" in section:
                self.SCREENSHOT_MAX_RETRIES = section.getint("SCREENSHOT_MAX_RETRIES")
            if "WAIT_STRATEGY" in section:
                self.WAIT_STRATEGY = section["WAIT_STRATEGY"].strip().lower()
            if "STAGGERED_WAIT_INITIAL" in section:
                self.STAGGERED_WAIT_INITIAL = section.getint("STAGGERED_WAIT_INITIAL")
            if "STAGGERED_WAIT_EXTRA" in section:
                self.STAGGERED_WAIT_EXTRA = section.getint("STAGGERED_WAIT_EXTRA")
            if "SCREENSHOT_FULL_PAGE" in section:
                self.SCREENSHOT_FULL_PAGE = section.getboolean("SCREENSHOT_FULL_PAGE")
            if "SCREENSHOT_ON_ERROR" in section:
                self.SCREENSHOT_ON_ERROR = section.getboolean("SCREENSHOT_ON_ERROR")

        if "REPORT" in config:
            if "ONLY_VALIDATED" in config["REPORT"]:
                self.REPORT_ONLY_VALIDATED = config["REPORT"].getboolean("ONLY_VALIDATED")
            if "EVIDENCE_MAX_FIELDS" in config["REPORT"]:
                self.REPORT_EVIDENCE_MAX_FIELDS = config["REPORT"].getint("EVIDENCE_MAX_FIELDS")
            if "EVIDENCE_VALUE_CHARS" in config["REPORT"]:
                self.REPORT_EVIDENCE_VALUE_CHARS = config["REPORT"].getint("EVIDENCE_VALUE_CHARS")

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
        # Load CORE first (DEBUG, SAFE_MODE)
        self._load_core_config(config)
        # Load paths early - other sections may depend on LOG_DIR/REPORT_DIR
        self._load_paths_config(config)
        self._load_provider_section(config)  # Read [PROVIDER] → sets self.PROVIDER
        self._load_provider_preset()          # Load JSON → sets model defaults
        self._load_crawler_config(config)
        self._load_scan_config(config)
        self._load_parallelization_config(config)
        self._load_url_prioritization_config(config)
        self._load_thinking_config(config)
        self._load_llm_models_config(config)  # User overrides from [LLM_MODELS]
        self._load_modellab_config(config)    # Model-eval scoring calibration [MODELLAB]
        self._load_conductor_and_scanning_config(config)
        self._load_analysis_and_misc_config(config)
        self._load_authority_config(config)
        self._load_lonewolf_config(config)
        self._load_anthropic_config(config)
        self._load_validation_config(config)
        self._load_qlearning_config(config)
        self._load_manipulator_config(config)
        self._load_asset_discovery_config(config)
    def load_env_specific(self):
        """Load environment-specific .env file if exists."""
        if test_mode_enabled():
            logger.debug("Skipping environment-specific .env load (BUGTRACE_TEST_MODE)")
            return
        env_file = f".env.{self.ENV}"
        env_path = self.BASE_DIR / env_file

        if env_path.exists():
            load_dotenv(env_path, override=True)
            logger.info(f"Loaded environment config: {env_file}")
        elif self.ENV != "production":
            logger.debug(f"No environment-specific config found: {env_file}")
