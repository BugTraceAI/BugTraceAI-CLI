"""
WAF Bypass Intelligence Module (TASK-79: Documentation).

This module provides intelligent WAF detection and bypass capabilities using
reinforcement learning (Q-Learning) to adaptively select the most effective
encoding strategies for each target.

Components
----------
WAFFingerprinter
    Identifies specific WAF products (Cloudflare, ModSecurity, AWS WAF, etc.)
    through header analysis, cookie patterns, and behavioral fingerprinting.

    Key features:
    - Detects 10+ WAF types with confidence scoring (TASK-70)
    - Multi-WAF detection for stacked configurations (TASK-73)
    - Result caching with TTL for performance (TASK-69)
    - False positive reduction (TASK-77)
    - Configurable SSL verification (TASK-66)

StrategyRouter
    Uses Q-Learning (Multi-Armed Bandit with UCB) to select optimal bypass
    strategies based on historical success rates against each WAF type.

    Key features:
    - UCB1 exploration/exploitation balance (TASK-68)
    - Input validation against data poisoning (TASK-67)
    - Automatic backup and restore (TASK-71)
    - Detailed success metrics (TASK-72)
    - ASCII visualization of Q-table (TASK-78)
    - Configurable hyperparameters (TASK-75)

EncodingTechniques
    18+ encoding and obfuscation methods organized by WAF effectiveness.

    Key features:
    - URL, Unicode, HTML entity encodings
    - Comment injection, null bytes, whitespace obfuscation
    - Strategy combinations for complex bypasses (TASK-74)
    - Expanded payload library (TASK-76)

Quick Start
-----------
    from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques

    # Detect WAF on target
    waf_name, confidence = await waf_fingerprinter.detect("https://target.com")

    # Get best strategies for this WAF
    waf, strategies = await strategy_router.get_strategies_for_target("https://target.com")

    # Encode payload with optimal strategy
    variants = encoding_techniques.encode_payload("<script>alert(1)</script>", waf=waf_name)

    # Record results to improve future selections
    strategy_router.record_result(waf_name, "unicode_encode", success=True)

    # View learning progress
    strategy_router.print_q_table()

Configuration
-------------
SSL/TLS settings in config.py:
    VERIFY_SSL_CERTIFICATES: bool = True
    ALLOW_SELF_SIGNED_CERTS: bool = False

Q-Learning settings in config.py:
    WAF_QLEARNING_INITIAL_EPSILON: float = 0.3
    WAF_QLEARNING_MIN_EPSILON: float = 0.05
    WAF_QLEARNING_DECAY_RATE: float = 0.995
    WAF_QLEARNING_UCB_CONSTANT: float = 2.0
    WAF_QLEARNING_MAX_BACKUPS: int = 5

Security Notes
--------------
- SSL verification is enabled by default (TASK-66)
- Q-Learning inputs are validated to prevent poisoning attacks (TASK-67)
- Q-table backups are created automatically before each save (TASK-71)
"""

from .fingerprinter import WAFFingerprinter, waf_fingerprinter
from .strategy_router import StrategyRouter, strategy_router, VALID_WAF_TYPES, VALID_STRATEGIES
from .encodings import EncodingTechniques, encoding_techniques

__all__ = [
    'WAFFingerprinter',
    'waf_fingerprinter',
    'StrategyRouter',
    'strategy_router',
    'EncodingTechniques',
    'encoding_techniques',
    'VALID_WAF_TYPES',
    'VALID_STRATEGIES'
]
