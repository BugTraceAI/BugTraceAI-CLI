"""
JWT Analysis - Pure Functions

Pure functions for JWT parsing, claim analysis, header analysis,
algorithm detection, and app name extraction.

All functions are PURE: no side effects, no self, data as parameters.
"""

import json
import base64
import re
import datetime
from typing import Dict, List, Optional, Any, Tuple

from bugtrace.agents.jwt.types import (
    SUCCESS_KEYWORDS,
    FAIL_KEYWORDS,
    PRIVILEGE_KEYWORDS,
    HTML_NOISE_WORDS,
    RECON_NOISE_WORDS,
)


# =========================================================================
# JWT Token Parsing (PURE)
# =========================================================================

def is_jwt(token: str) -> bool:
    """Heuristic to check if a string looks like a JWT."""  # PURE
    parts = token.split('.')
    return len(parts) == 3 and all(len(p) > 4 for p in parts[:2])


def base64url_decode(data: str) -> str:
    """Base64Url decode helper."""  # PURE
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data).decode('utf-8')


def decode_token(token: str) -> Optional[Dict]:
    """Decode JWT parts without verification.

    Returns:
        Dict with 'header', 'payload', 'signature', 'raw' keys, or None on failure.
    """  # PURE
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))
        signature = parts[2]

        return {
            "header": header,
            "payload": payload,
            "signature": signature,
            "raw": token,
        }
    except Exception:
        return None


def get_algorithm(decoded: Dict) -> str:
    """Extract algorithm from decoded JWT header.

    Args:
        decoded: Result of decode_token()

    Returns:
        Algorithm string (e.g., 'HS256', 'RS256', 'none')
    """  # PURE
    return decoded.get('header', {}).get('alg', 'unknown')


def get_claims(decoded: Dict) -> List[str]:
    """Extract claim names from decoded JWT payload.

    Args:
        decoded: Result of decode_token()

    Returns:
        List of claim key names
    """  # PURE
    return list(decoded.get('payload', {}).keys())


# =========================================================================
# Token Verification Analysis (PURE)
# =========================================================================

def analyze_token_response(
    base_status: int,
    status: int,
    base_text: str,
    text: str,
) -> bool:
    """Analyze HTTP response to determine if token validation was bypassed.

    Args:
        base_status: Baseline request status code
        status: Forged token request status code
        base_text: Baseline response body
        text: Forged token response body

    Returns:
        True if bypass detected
    """  # PURE
    text_lower = text.lower()
    base_text_lower = base_text.lower()

    # Check status code change
    if base_status in [401, 403] and status == 200:
        return True

    # Check content-based indicators
    if status == 200:
        # Success markers appeared
        for sk in SUCCESS_KEYWORDS:
            if sk in text_lower and sk not in base_text_lower:
                return True

        # Fail markers disappeared
        for fk in FAIL_KEYWORDS:
            if fk in base_text_lower and fk not in text_lower:
                return True

    return False


def body_shows_privilege_difference(base_text: str, auth_text: str) -> bool:
    """Compare response bodies to detect privilege differences when both return 200.

    Checks:
    1. JSON key differences (auth response has extra keys)
    2. Array length differences (auth response returns more data)
    3. Privilege keywords present in auth response but not baseline
    4. Bodies are not identical (token actually changes something)

    Args:
        base_text: Baseline response body
        auth_text: Authenticated response body

    Returns:
        True if privilege difference detected
    """  # PURE
    # Identical responses -> token has no effect
    if base_text.strip() == auth_text.strip():
        return False

    # Both empty -> no difference
    if not base_text.strip() and not auth_text.strip():
        return False

    # Check for privilege keywords in auth response but not in baseline
    auth_lower = auth_text.lower()
    base_lower = base_text.lower()

    new_privilege_keywords = sum(
        1 for kw in PRIVILEGE_KEYWORDS
        if kw in auth_lower and kw not in base_lower
    )
    if new_privilege_keywords >= 2:
        return True

    # Try JSON comparison
    try:
        base_json = json.loads(base_text)
        auth_json = json.loads(auth_text)
    except (json.JSONDecodeError, TypeError):
        # Not JSON -- check raw length difference (auth response significantly larger)
        if len(auth_text) > len(base_text) * 1.5 and len(auth_text) - len(base_text) > 100:
            return True
        return False

    # Compare JSON objects
    if isinstance(base_json, dict) and isinstance(auth_json, dict):
        # New keys in auth response
        new_keys = set(auth_json.keys()) - set(base_json.keys())
        if new_keys:
            return True

        # Check for value changes in privilege-related fields
        for key in auth_json:
            if key in base_json and auth_json[key] != base_json[key]:
                if any(kw in key.lower() for kw in PRIVILEGE_KEYWORDS):
                    return True

    # Compare JSON arrays (auth returns more items)
    if isinstance(base_json, list) and isinstance(auth_json, list):
        if len(auth_json) > len(base_json) and len(auth_json) - len(base_json) >= 2:
            return True

    return False


# =========================================================================
# App Name Extraction (PURE)
# =========================================================================

def extract_names_from_html(text: str) -> List[str]:
    """Extract potential app/service names from HTML content.

    Args:
        text: HTML content string

    Returns:
        List of extracted name strings (lowercase)
    """  # PURE
    names = []

    # CamelCase words (e.g., "BugStore" -> "bugstore")
    for match in re.findall(r'\b([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b', text):
        w = match.lower()
        if len(w) >= 4 and w not in HTML_NOISE_WORDS:
            names.append(w)

    # Quoted strings
    for match in re.findall(r'"([^"]{3,30})"', text):
        for word in match.split():
            w = word.lower().strip()
            if len(w) >= 4 and w.isalpha() and w not in HTML_NOISE_WORDS:
                names.append(w)

    # HTML <title>
    title_match = re.search(r'<title[^>]*>([^<]+)</title>', text, re.IGNORECASE)
    if title_match:
        for word in re.split(r'[\s\-_|]+', title_match.group(1)):
            w = word.lower().strip()
            if len(w) >= 3 and w.isalpha() and w not in HTML_NOISE_WORDS:
                names.append(w)

    return names


def extract_names_from_recon_cache(report_dir, extract_html_fn=None) -> List[str]:
    """Extract app names from cached recon data on disk (no HTTP needed).

    Args:
        report_dir: Path to report directory
        extract_html_fn: Function to extract names from HTML (default: extract_names_from_html)

    Returns:
        List of extracted name strings
    """  # PURE (reads files but produces no side effects)
    from pathlib import Path
    import glob as glob_mod

    if extract_html_fn is None:
        extract_html_fn = extract_names_from_html

    names = []
    report_dir = Path(report_dir)

    # 1. Read DASTySAST HTML captures (most likely to have app name)
    dastysast_dir = report_dir / "dastysast"
    if dastysast_dir.exists():
        for json_file in sorted(dastysast_dir.glob("*.json"))[:5]:
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                html = data.get("html_content", "") or data.get("page_source", "")
                if html:
                    names.extend(extract_html_fn(html))
                title = data.get("page_title", "") or data.get("title", "")
                if title:
                    for word in re.split(r'[\s\-_|]+', title):
                        w = word.lower().strip()
                        if len(w) >= 3 and w.isalpha() and w not in RECON_NOISE_WORDS:
                            names.append(w)
            except Exception:
                pass

    # 2. Read tech_profile.json for framework/server names
    for tp_path in [report_dir / "recon" / "tech_profile.json", report_dir / "tech_profile.json"]:
        if tp_path.exists():
            try:
                tp = json.loads(tp_path.read_text(encoding="utf-8"))
                tp_url = tp.get("url", "")
                if tp_url:
                    from urllib.parse import urlparse
                    parsed = urlparse(tp_url)
                    for part in (parsed.hostname or "").replace("-", ".").replace("_", ".").split("."):
                        if len(part) >= 4 and part.isalpha() and part not in RECON_NOISE_WORDS:
                            names.append(part.lower())
            except Exception:
                pass

    # 3. Read screenshots directory for HTML files with titles
    captures_dir = report_dir / "captures"
    if captures_dir.exists():
        for html_file in glob_mod.glob(str(captures_dir / "*.html"))[:3]:
            try:
                with open(html_file, 'r', errors='ignore') as f:
                    content = f.read(5000)
                names.extend(extract_html_fn(content))
            except Exception:
                pass

    # 4. Read analysis/ directory for page titles in DAST reports
    analysis_dir = report_dir / "analysis"
    if analysis_dir.exists():
        for json_file in sorted(analysis_dir.glob("*.json"))[:3]:
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                for key in ("page_title", "title", "app_name", "target_name"):
                    val = data.get(key, "")
                    if val:
                        for word in re.split(r'[\s\-_|]+', str(val)):
                            w = word.lower().strip()
                            if len(w) >= 3 and w.isalpha() and w not in RECON_NOISE_WORDS:
                                names.append(w)
            except Exception:
                pass

    return names


def extract_target_names(url: str, report_dir=None) -> List[str]:
    """Extract potential app/service names from URL + recon data for secret generation.

    Args:
        url: Target URL
        report_dir: Optional report directory Path

    Returns:
        List of unique name strings
    """  # PURE
    from urllib.parse import urlparse

    names = set()
    parsed = urlparse(url)

    # From hostname: "bugstore.example.com" -> "bugstore"
    hostname = parsed.hostname or ""
    parts = hostname.replace("-", ".").replace("_", ".").split(".")
    generic_parts = {"www", "api", "app", "dev", "staging", "test",
                     "localhost", "com", "org", "net", "io", "co",
                     "uk", "us", "eu", "127", "0"}
    for part in parts:
        part = part.lower().strip()
        if part and part not in generic_parts and not part.isdigit():
            names.add(part)

    # From path: look for service name patterns
    path_parts = [p for p in parsed.path.split("/") if p and p not in ("api", "v1", "v2", "v3")]
    if path_parts:
        names.add(path_parts[0].lower())

    # From recon data
    if report_dir:
        try:
            from pathlib import Path
            captures_dir = Path(report_dir) / "captures"
            if captures_dir.exists():
                import glob as glob_mod
                for html_file in glob_mod.glob(str(captures_dir / "*.html"))[:3]:
                    with open(html_file, 'r', errors='ignore') as f:
                        content = f.read(5000)
                    title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1).strip()
                        for word in re.split(r'[\s\-_|]+', title):
                            word = word.lower().strip()
                            if len(word) >= 3 and word not in generic_parts and word.isalpha():
                                names.add(word)
        except Exception:
            pass

        try:
            from pathlib import Path
            urls_file = Path(report_dir) / "recon" / "urls.txt"
            if urls_file and urls_file.exists():
                for line in urls_file.read_text().splitlines()[:50]:
                    lp = urlparse(line.strip())
                    rhost = lp.hostname or ""
                    for rp in rhost.replace("-", ".").replace("_", ".").split("."):
                        rp = rp.lower().strip()
                        if rp and rp not in generic_parts and not rp.isdigit():
                            names.add(rp)
        except Exception:
            pass

    return list(names)


def get_root_url(url: str) -> Optional[str]:
    """Get root URL if current URL has a path.

    Args:
        url: Full URL

    Returns:
        Root URL string or None if already at root
    """  # PURE
    from urllib.parse import urlparse

    p = urlparse(url)
    if p.path != "/" and p.path != "":
        return f"{p.scheme}://{p.netloc}/"
    return None


__all__ = [
    "is_jwt",
    "base64url_decode",
    "decode_token",
    "get_algorithm",
    "get_claims",
    "analyze_token_response",
    "body_shows_privilege_difference",
    "extract_names_from_html",
    "extract_names_from_recon_cache",
    "extract_target_names",
    "get_root_url",
]
