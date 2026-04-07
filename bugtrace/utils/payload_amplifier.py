"""
PayloadAmplifier - Payload multiplication using breakout prefixes.

This module is responsible for "amplifying" seed payloads by combining them
with breakout prefixes from breakouts.json. This is Phase 3 of the XSS Hybrid Engine.

Author: BugtraceAI Team
Version: 1.0.0
Date: 2026-02-03
"""

import json
from pathlib import Path
from typing import List, Set, Optional
from dataclasses import dataclass

from bugtrace.utils.logger import get_logger

logger = get_logger("utils.payload_amplifier")


@dataclass
class BreakoutConfig:
    """Configuration for a single breakout prefix."""
    prefix: str
    description: str
    category: str
    priority: int
    enabled: bool = True
    success_count: int = 0


class PayloadAmplifier:
    """
    Amplifies seed payloads by combining them with breakout prefixes.

    Given 100 seed payloads and 40 breakout prefixes, this produces ~4000
    unique payloads ready for mass fuzzing.

    Usage:
        amplifier = PayloadAmplifier()
        mass_payloads = amplifier.amplify(seed_payloads, category="xss")
    """

    DEFAULT_BREAKOUTS_PATH = Path(__file__).parent.parent / "payloads" / "breakouts.json"

    def __init__(self, breakouts_path: Optional[Path] = None):
        """
        Initialize the amplifier.

        Args:
            breakouts_path: Path to breakouts.json. Defaults to bugtrace/payloads/breakouts.json
        """
        self.breakouts_path = breakouts_path or self.DEFAULT_BREAKOUTS_PATH
        self._cache: Optional[List[BreakoutConfig]] = None
        self._prefixes_by_category: dict = {}

    def _load_breakouts(self) -> List[BreakoutConfig]:
        """Load breakouts from JSON file with caching."""
        if self._cache is not None:
            return self._cache

        try:
            with open(self.breakouts_path, 'r') as f:
                data = json.load(f)

            self._cache = []
            for b in data.get('breakouts', []):
                config = BreakoutConfig(
                    prefix=b.get('prefix', ''),
                    description=b.get('description', ''),
                    category=b.get('category', 'general'),
                    priority=b.get('priority', 3),
                    enabled=b.get('enabled', True),
                    success_count=b.get('success_count', 0)
                )
                if config.enabled:
                    self._cache.append(config)

            # Sort by priority (lower = higher priority) and success_count
            self._cache.sort(key=lambda x: (x.priority, -x.success_count))

            logger.info(f"Loaded {len(self._cache)} enabled breakouts from {self.breakouts_path}")
            return self._cache

        except FileNotFoundError:
            logger.warning(f"Breakouts file not found: {self.breakouts_path}. Using empty list.")
            self._cache = []
            return self._cache
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in breakouts file: {e}")
            self._cache = []
            return self._cache

    def get_prefixes(
        self,
        category: Optional[str] = None,
        max_priority: int = 3
    ) -> List[str]:
        """
        Get breakout prefixes filtered by category and priority.

        Args:
            category: Filter by category (e.g., "xss", "sqli"). None = all.
            max_priority: Maximum priority level to include (1=highest, 3=lowest)

        Returns:
            List of prefix strings sorted by priority
        """
        breakouts = self._load_breakouts()

        filtered = []
        for b in breakouts:
            # Priority filter
            if b.priority > max_priority:
                continue

            # Category filter (categories are comma-separated)
            if category:
                categories = [c.strip().lower() for c in b.category.split(',')]
                if category.lower() not in categories and 'general' not in categories:
                    continue

            filtered.append(b.prefix)

        return filtered

    def amplify(
        self,
        seed_payloads: List[str],
        category: Optional[str] = "xss",
        max_priority: int = 3,
        deduplicate: bool = True
    ) -> List[str]:
        """
        Amplify seed payloads by combining with breakout prefixes.

        This is the main method for Phase 3 (Amplification) of the XSS Hybrid Engine.

        Args:
            seed_payloads: List of seed payloads from LLM (typically ~100)
            category: Filter breakouts by category (default: "xss")
            max_priority: Maximum breakout priority to use
            deduplicate: Remove duplicate payloads (default: True)

        Returns:
            Amplified list of payloads (typically seed_count * prefix_count)

        Example:
            >>> amplifier = PayloadAmplifier()
            >>> seeds = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
            >>> amplified = amplifier.amplify(seeds)
            >>> len(amplified)  # seeds * prefixes + seeds
            82  # (2 seeds * 40 prefixes) + 2 pure seeds
        """
        prefixes = self.get_prefixes(category=category, max_priority=max_priority)

        if deduplicate:
            amplified: Set[str] = set()
        else:
            amplified_list: List[str] = []

        for seed in seed_payloads:
            seed = seed.strip()
            if not seed:
                continue

            # 1. Add seed payload as-is (pure injection)
            if deduplicate:
                amplified.add(seed)
            else:
                amplified_list.append(seed)

            # 2. Combine with each breakout prefix
            for prefix in prefixes:
                combined = f"{prefix}{seed}"
                if deduplicate:
                    amplified.add(combined)
                else:
                    amplified_list.append(combined)

        result = list(amplified) if deduplicate else amplified_list

        logger.info(
            f"Amplified {len(seed_payloads)} seeds × {len(prefixes)} prefixes "
            f"= {len(result)} payloads (dedup={deduplicate})"
        )

        return result

    def amplify_with_suffixes(
        self,
        seed_payloads: List[str],
        suffixes: Optional[List[str]] = None,
        category: Optional[str] = "xss"
    ) -> List[str]:
        """
        Amplify with both prefixes AND suffixes (full wrapping).

        Useful for context-aware injection where both breakout and closing
        are needed.

        Args:
            seed_payloads: List of seed payloads
            suffixes: List of suffix strings to append (optional)
            category: Filter breakouts by category

        Returns:
            Amplified payloads with prefix + seed + suffix combinations
        """
        if suffixes is None:
            # Default suffixes for common context closures
            suffixes = ["", "//", "-->", "'>", "\">", "</script>"]

        prefixes = self.get_prefixes(category=category)
        amplified: Set[str] = set()

        for seed in seed_payloads:
            seed = seed.strip()
            if not seed:
                continue

            # Pure seed
            amplified.add(seed)

            # Prefix-only
            for prefix in prefixes:
                amplified.add(f"{prefix}{seed}")

            # Prefix + Suffix wrapping
            for prefix in prefixes:
                for suffix in suffixes:
                    wrapped = f"{prefix}{seed}{suffix}"
                    amplified.add(wrapped)

        logger.info(
            f"Amplified with wrapping: {len(seed_payloads)} seeds × "
            f"{len(prefixes)} prefixes × {len(suffixes)} suffixes "
            f"= {len(amplified)} unique payloads"
        )

        return list(amplified)

    def get_stats(self) -> dict:
        """Get statistics about loaded breakouts."""
        breakouts = self._load_breakouts()

        categories = {}
        for b in breakouts:
            for cat in b.category.split(','):
                cat = cat.strip().lower()
                categories[cat] = categories.get(cat, 0) + 1

        priorities = {1: 0, 2: 0, 3: 0}
        for b in breakouts:
            if b.priority in priorities:
                priorities[b.priority] += 1

        return {
            "total_breakouts": len(breakouts),
            "by_category": categories,
            "by_priority": priorities,
            "source_file": str(self.breakouts_path)
        }
