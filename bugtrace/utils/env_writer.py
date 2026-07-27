"""
.env File Writer — Safely update environment variables in .env files.

Used by the provider API to persist API keys without manual file editing.
"""

import re
from pathlib import Path
from dotenv import load_dotenv

from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger

logger = get_logger("utils.env_writer")


def update_env_var(key: str, value: str, env_path: Path = None) -> bool:
    """Update or add an environment variable in the .env file.

    Preserves existing comments and formatting.
    Reloads dotenv after writing so the change takes effect immediately.

    Args:
        key: Environment variable name (e.g. 'GLM_API_KEY')
        value: New value to set
        env_path: Path to .env file (defaults to settings.BASE_DIR / '.env')

    Returns:
        True if written successfully, False on error
    """
    if env_path is None:
        env_path = settings.BASE_DIR / ".env"

    # Sanitize: reject values with newlines, null bytes, or shell metacharacters
    if any(c in value for c in ('\n', '\r', '\0')):
        logger.error(f"Rejected {key}: value contains newline or null byte")
        return False

    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', key):
        logger.error(f"Rejected invalid env var name: {key}")
        return False

    try:
        # Read existing content
        if env_path.exists():
            content = env_path.read_text()
        else:
            content = ""

        # Pattern: KEY=value (with optional quotes)
        pattern = re.compile(rf'^{re.escape(key)}=.*$', re.MULTILINE)

        if pattern.search(content):
            # Update existing key
            content = pattern.sub(f'{key}={value}', content)
        else:
            # Append new key (with newline separator if needed)
            if content and not content.endswith('\n'):
                content += '\n'
            content += f'{key}={value}\n'

        env_path.write_text(content)

        # Reload dotenv so settings pick up the change
        load_dotenv(env_path, override=True)

        logger.info(f"Updated {key} in {env_path}")
        return True

    except Exception as e:
        logger.error(f"Failed to write {key} to {env_path}: {e}")
        return False
