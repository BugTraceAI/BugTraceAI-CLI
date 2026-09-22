"""
Auth Config Loader - Load authentication configuration from YAML files.

Supports TOTP-based 2FA authentication with customizable login flows.

Author: BugtraceAI Team
"""

import re
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import yaml

from bugtrace.utils.logger import get_logger
from bugtrace.utils.totp import validate_totp_secret

logger = get_logger("utils.auth_config")


# Schema for auth config validation
AUTH_CONFIG_SCHEMA = {
    "required_fields": ["login_url", "credentials"],
    "credentials_fields": ["username", "password"],  # At least one identifier + password
    "optional_fields": ["login_flow", "success_condition", "login_type", "scope_path"],
    "login_types": ["form", "sso", "api", "basic"],
    "success_condition_types": ["url_contains", "url_equals_exactly", "element_present", "text_contains"],
}


def load_auth_config(config_path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Load authentication configuration from a YAML file.

    Args:
        config_path: Path to the YAML config file

    Returns:
        Tuple of (config_dict, error_message)
        - On success: (config, None)
        - On error: (None, error_message)

    Example YAML structure:
    ```yaml
    authentication:
      login_type: form
      login_url: "https://example.com/login"
      credentials:
        username: "testuser"
        password: "testpassword"
        totp_secret: "JBSWY3DPEHPK3PXP"  # Optional Base32 TOTP secret

      login_flow:  # Optional custom flow
        - "Type $username into the email field"
        - "Type $password into the password field"
        - "Click the 'Sign In' button"
        - "Enter $totp in the verification code field"
        - "Click 'Verify'"

      success_condition:  # Optional
        type: url_contains
        value: "/dashboard"
    ```
    """
    path = Path(config_path)

    if not path.exists():
        return None, f"Config file not found: {config_path}"

    if not path.suffix.lower() in (".yaml", ".yml"):
        return None, f"Config file must be YAML (.yaml or .yml): {config_path}"

    try:
        with open(path, "r", encoding="utf-8") as f:
            # Use safe loader to prevent code execution
            raw_config = yaml.safe_load(f)

        if not raw_config:
            return None, "Config file is empty"

        # Extract authentication section
        auth_config = raw_config.get("authentication", raw_config)

        # Validate and sanitize
        validated, error = validate_auth_config(auth_config)
        if error:
            return None, error

        logger.info(f"Loaded auth config from {config_path}")
        return validated, None

    except yaml.YAMLError as e:
        return None, f"Invalid YAML syntax: {e}"
    except Exception as e:
        return None, f"Failed to load config: {e}"


def validate_auth_config(config: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Validate and sanitize authentication configuration.

    Args:
        config: Raw config dictionary

    Returns:
        Tuple of (sanitized_config, error_message)
    """
    if not isinstance(config, dict):
        return None, "Config must be a dictionary"

    # Check required fields
    if "login_url" not in config:
        return None, "Missing required field: login_url"

    if "credentials" not in config:
        return None, "Missing required field: credentials"

    credentials = config.get("credentials", {})
    if not isinstance(credentials, dict):
        return None, "credentials must be a dictionary"

    # Check for at least username/email and password
    has_identifier = any(k in credentials for k in ("username", "email", "user"))
    has_password = "password" in credentials

    if not has_identifier:
        return None, "credentials must contain username or email"

    if not has_password:
        return None, "credentials must contain password"

    # Validate login_url
    login_url = config.get("login_url", "")
    if not login_url:
        return None, "login_url cannot be empty"

    # Basic URL validation (allow relative URLs starting with /)
    if not login_url.startswith("/") and not re.match(r'^https?://', login_url):
        return None, f"Invalid login_url: must be absolute URL or start with /"

    # Validate TOTP secret if provided
    totp_secret = credentials.get("totp_secret", "")
    if totp_secret:
        is_valid, error = validate_totp_secret(totp_secret)
        if not is_valid:
            return None, f"Invalid totp_secret: {error}"

    # Validate login_flow if provided
    login_flow = config.get("login_flow", [])
    if login_flow:
        if not isinstance(login_flow, list):
            return None, "login_flow must be a list of strings"
        for i, step in enumerate(login_flow):
            if not isinstance(step, str):
                return None, f"login_flow step {i+1} must be a string"
            # Check for potential injection
            if _contains_dangerous_pattern(step):
                return None, f"login_flow step {i+1} contains potentially dangerous pattern"

    # Validate success_condition if provided
    success_condition = config.get("success_condition", {})
    if success_condition:
        if not isinstance(success_condition, dict):
            return None, "success_condition must be a dictionary"
        cond_type = success_condition.get("type", "")
        if cond_type and cond_type not in AUTH_CONFIG_SCHEMA["success_condition_types"]:
            return None, f"Invalid success_condition type: {cond_type}"

    # Validate login_type if provided
    login_type = config.get("login_type", "form")
    if login_type not in AUTH_CONFIG_SCHEMA["login_types"]:
        return None, f"Invalid login_type: {login_type}"

    # Build sanitized config
    sanitized = {
        "login_url": login_url.strip(),
        "login_type": login_type,
        "credentials": {
            "username": credentials.get("username", credentials.get("email", "")).strip(),
            "password": credentials.get("password", ""),
        },
    }

    # Add optional TOTP secret
    if totp_secret:
        sanitized["credentials"]["totp_secret"] = totp_secret.strip().upper()

    # Add optional login_flow
    if login_flow:
        sanitized["login_flow"] = [step.strip() for step in login_flow]

    # Add optional success_condition
    if success_condition:
        sanitized["success_condition"] = {
            "type": success_condition.get("type", "url_contains"),
            "value": success_condition.get("value", ""),
        }

    # Add optional scope_path (restricts crawling to URLs under this path)
    scope_path = config.get("scope_path", "")
    if scope_path:
        # Validate scope_path format
        if not scope_path.startswith("/"):
            scope_path = "/" + scope_path
        sanitized["scope_path"] = scope_path.strip()
        logger.info(f"Crawling scope restricted to: {scope_path}")

    return sanitized, None


def _contains_dangerous_pattern(text: str) -> bool:
    """Check for potentially dangerous patterns in login flow steps."""
    dangerous_patterns = [
        r'\$\{.*\}',           # Shell-style variable expansion
        r'`.*`',               # Backtick command execution
        r'\$\(.*\)',           # Command substitution
        r';\s*(rm|del|drop)',  # Command chaining with destructive ops
        r'\.\./',              # Path traversal
        r'<script',            # Script injection
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def convert_to_scan_auth(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert auth config to format expected by ScanOptions.auth.

    Args:
        config: Validated auth config from load_auth_config()

    Returns:
        Dictionary suitable for ScanOptions.auth field
    """
    result = {
        "login_url": config.get("login_url", ""),
        "credentials": config.get("credentials", {}),
        "login_flow": config.get("login_flow", []),
        "success_condition": config.get("success_condition", {}),
    }

    # Include scope_path if set (restrict crawling to this path)
    if config.get("scope_path"):
        result["scope_path"] = config["scope_path"]

    return result


def create_example_config(output_path: str = "auth-config.yaml") -> str:
    """
    Create an example auth config YAML file.

    Args:
        output_path: Path where to write the example

    Returns:
        Path to created file
    """
    example = """# BugTraceAI Authentication Configuration
# Use this file to configure authenticated scanning with TOTP support.

authentication:
  # Login type: form (default), sso, api, or basic
  login_type: form

  # URL of the login page (can be relative to target URL)
  login_url: "/login"

  # Login credentials
  credentials:
    # Username or email (use $username or $email in login_flow)
    username: "your-username"

    # Password (use $password in login_flow)
    password: "your-password"

    # Optional: TOTP secret for 2FA (Base32 encoded)
    # Get this from your authenticator app setup or account settings
    # totp_secret: "JBSWY3DPEHPK3PXP"

  # Optional: Custom login flow (if auto-detect doesn't work)
  # Each step is executed in order. Available variables: $username, $email, $password, $totp
  # login_flow:
  #   - "Type $username into the email field"
  #   - "Type $password into the password field"
  #   - "Click the 'Sign In' button"
  #   - "Enter $totp in the verification code field"
  #   - "Click 'Verify'"

  # Optional: How to verify login succeeded
  # success_condition:
  #   type: url_contains  # url_contains, url_equals_exactly, element_present, text_contains
  #   value: "/dashboard"
"""

    path = Path(output_path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(example)

    logger.info(f"Created example auth config at {output_path}")
    return str(path.absolute())
