"""Settings ops extracted from config.Settings for LOC policy."""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from pathlib import Path

from bugtrace.utils.logger import get_logger

if TYPE_CHECKING:
    from bugtrace.core.config import Settings

logger = get_logger("core.config")


class SettingsOpsMixin:
    """Validation, masking, docs, and config history for Settings."""

    def validate_config(self) -> List[str]:
        """
        Validate entire configuration.
        Returns list of errors (empty if valid).
        Raises ValueError if critical errors found.
        """
        errors = []
        warnings = []

        # Check required API key for active provider
        provider_cfg = getattr(self, '_provider_config', {})
        provider_key_env = provider_cfg.get("api_key_env", "OPENROUTER_API_KEY")
        provider_key = getattr(self, provider_key_env, None) or os.environ.get(provider_key_env)
        if not provider_key:
            errors.append(f"{provider_key_env} is required for provider '{self.PROVIDER}'")

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
    def mask_secrets(self) -> Dict[str, Any]:
        """Return config dict with masked secrets for safe logging."""
        masked = self.model_dump()
        secret_fields = ['OPENROUTER_API_KEY', 'GLM_API_KEY', 'ANTHROPIC_API_KEY']
        for key in secret_fields:
            if masked.get(key):
                val = masked[key]
                if len(val) > 12:
                    masked[key] = val[:8] + '...' + val[-4:]
                else:
                    masked[key] = '***'
        return masked
    def log_config(self):
        """Log configuration with masked secrets (only in DEBUG mode)."""
        if not self.DEBUG:
            return
        logger.debug("Configuration loaded:")
        for key, value in self.mask_secrets().items():
            if not key.startswith('_') and key != 'model_config':
                logger.debug(f"  {key}: {value}")
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
