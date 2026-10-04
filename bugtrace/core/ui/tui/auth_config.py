"""Target authentication snapshots shared by the workspace and its setup dialog."""
from copy import deepcopy
from pathlib import Path


AUTH_HEADERS = {"authorization", "cookie"}


def auth_mode(options):
    headers = options.get("custom_headers") or {}
    authorization = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
    token = authorization[7:] if authorization.lower().startswith("bearer ") else ""
    login = options.get("auth_data")
    if any(k.lower() == "cookie" for k in headers) or (authorization and not token) or (login and authorization):
        return "current"
    return "yaml" if login else "bearer" if token else "none"


def auth_label(options):
    mode = auth_mode(options)
    if mode == "current":
        return "Auth · Configured"
    if mode == "yaml":
        totp = (options.get("auth_data", {}).get("credentials") or {}).get("totp_secret")
        return "Auth · Login + 2FA" if totp else "Auth · Login"
    return "Auth · Bearer" if mode == "bearer" else "Auth · None"


def build_auth_options(options, mode, *, token="", login=None):
    """Replace target auth only; preserve other explicitly supplied HTTP headers."""
    result = {key: deepcopy(options.get(key)) for key in ("auth_data", "custom_headers")}
    if mode == "current":
        return result
    headers = {k: v for k, v in (result["custom_headers"] or {}).items() if k.lower() not in AUTH_HEADERS}
    result["auth_data"] = None
    if mode == "bearer":
        token = token.strip()
        if token.lower() == "bearer":
            token = ""
        elif token.lower().startswith("bearer "):
            token = token[7:].strip()
        if not token or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError("Enter a token without spaces or line breaks.")
        headers["Authorization"] = f"Bearer {token}"
    elif mode == "yaml":
        if not login:
            raise ValueError("Choose an authentication YAML file.")
        result["auth_data"] = deepcopy(login)
    elif mode != "none":
        raise ValueError("Choose an authentication method.")
    result["custom_headers"] = headers or None
    return result


def load_login_yaml(filename):
    """Use the WEB/CLI schema; never show YAML contents or secrets in errors."""
    import yaml
    from bugtrace.utils.auth_config import validate_auth_config, convert_to_scan_auth

    path = Path(filename).expanduser()
    if path.suffix.lower() not in {".yaml", ".yml"}:
        raise ValueError("Choose a .yaml or .yml authentication file.")
    try:
        if not path.is_file():
            raise OSError("Not a regular file")
        with path.open("rb") as source:
            content = source.read(128 * 1024 + 1)
    except OSError:
        raise ValueError("Cannot read this file. Check its path and permissions.") from None
    if len(content) > 128 * 1024:
        raise ValueError("Authentication YAML must be smaller than 128 KiB.")
    try:
        raw = yaml.safe_load(content.decode("utf-8"))
    except (yaml.YAMLError, UnicodeError):
        raise ValueError("Invalid YAML syntax. Check indentation and quoting.") from None
    if not isinstance(raw, dict):
        raise ValueError("YAML must contain an authentication configuration.")
    try:
        validated, error = validate_auth_config(raw.get("authentication", raw))
    except (TypeError, AttributeError, ValueError):
        raise ValueError("Invalid field types. Check the authentication YAML template.") from None
    if error:
        # Some schema errors include the rejected field value. Show only the reason.
        reason = error if error.startswith("Missing required field:") else error.split(":", 1)[0]
        raise ValueError(reason + ".")
    return convert_to_scan_auth(validated), str(path)
