"""
JWT Agent Module

This module provides JWT (JSON Web Token) vulnerability detection and
exploitation capabilities.

The JWTAgent class is the main entry point for JWT scanning.

Modules:
    - types: JWTFinding dataclass, vulnerability constants
    - analysis: PURE: JWT parsing, claim analysis, algorithm detection
    - attacks: PURE: payload generation for alg:none, key confusion, weak secrets
    - validation: PURE: token validation, finding validation logic
    - discovery: I/O: JWT token discovery in URLs, cookies, localStorage
    - exploitation: I/O: attack execution, token forging, secret cracking
    - dedup: PURE: JWT fingerprint dedup
    - agent: Thin orchestrator class

Usage:
    from bugtrace.agents.jwt import JWTAgent, run_jwt_analysis

    agent = JWTAgent()
    result = await agent.check_url("http://example.com")

For backward compatibility, JWTAgent can also be imported from:
    from bugtrace.agents.jwt_agent import JWTAgent
"""

# Re-export agent class and convenience function
from bugtrace.agents.jwt.agent import JWTAgent, run_jwt_analysis

# Re-export types
from bugtrace.agents.jwt.types import (
    JWTFinding,
    ALG_NONE_VARIANTS,
    SUCCESS_KEYWORDS,
    FAIL_KEYWORDS,
    PRIVILEGE_KEYWORDS,
    AUTH_PATTERNS,
    ADMIN_PATHS,
    ADMIN_NAMES,
)

# Re-export pure analysis functions
from bugtrace.agents.jwt.analysis import (
    is_jwt,
    base64url_decode,
    decode_token,
    get_algorithm,
    get_claims,
    analyze_token_response,
    body_shows_privilege_difference,
    extract_names_from_html,
    extract_names_from_recon_cache,
    extract_target_names,
    get_root_url,
)

# Re-export pure attack functions
from bugtrace.agents.jwt.attacks import (
    none_alg_decode_header,
    generate_none_alg_tokens,
    prepare_brute_force,
    test_secret,
    load_jwt_wordlist,
    generate_name_based_secrets,
    sign_forged_payload,
    forge_admin_token_variations,
    build_kid_injection_token,
    forge_key_confusion_token,
    inject_token_into_url_param,
)

# Re-export pure validation functions
from bugtrace.agents.jwt.validation import (
    validate_jwt_finding,
    get_validation_status,
)

# Re-export pure dedup functions
from bugtrace.agents.jwt.dedup import (
    generate_jwt_fingerprint,
    fallback_fingerprint_dedup,
)

# Re-export I/O discovery functions
from bugtrace.agents.jwt.discovery import (
    discover_tokens,
    extract_app_name_from_root,
)

# Re-export I/O exploitation functions
from bugtrace.agents.jwt.exploitation import (
    verify_token_works,
    check_none_algorithm,
    attack_brute_force,
    attack_kid_injection,
    attack_key_confusion,
)

__all__ = [
    # Main class
    "JWTAgent",
    "run_jwt_analysis",
    # Types
    "JWTFinding",
    "ALG_NONE_VARIANTS",
    "SUCCESS_KEYWORDS",
    "FAIL_KEYWORDS",
    "PRIVILEGE_KEYWORDS",
    # Analysis (PURE)
    "is_jwt",
    "base64url_decode",
    "decode_token",
    "get_algorithm",
    "get_claims",
    "analyze_token_response",
    "body_shows_privilege_difference",
    "extract_names_from_html",
    "extract_target_names",
    # Attacks (PURE)
    "generate_none_alg_tokens",
    "prepare_brute_force",
    "test_secret",
    "load_jwt_wordlist",
    "generate_name_based_secrets",
    "forge_admin_token_variations",
    "build_kid_injection_token",
    "forge_key_confusion_token",
    # Validation (PURE)
    "validate_jwt_finding",
    "get_validation_status",
    # Dedup (PURE)
    "generate_jwt_fingerprint",
    "fallback_fingerprint_dedup",
    # Discovery (I/O)
    "discover_tokens",
    "extract_app_name_from_root",
    # Exploitation (I/O)
    "verify_token_works",
    "check_none_algorithm",
    "attack_brute_force",
    "attack_kid_injection",
    "attack_key_confusion",
]
