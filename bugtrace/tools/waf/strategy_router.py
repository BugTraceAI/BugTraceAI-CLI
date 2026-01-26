"""
Strategy Router with Q-Learning (Multi-Armed Bandit).

Learns which encoding strategies work best against each WAF over time.
"""

import json
import asyncio
import math
import re
import os
import glob as glob_module
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from .fingerprinter import waf_fingerprinter
from .encodings import encoding_techniques, EncodingTechniques

logger = get_logger("waf.strategy_router")


# =============================================================================
# TASK-67: Input Validation for Q-Learning Data Poisoning Prevention
# =============================================================================

# Whitelist of valid WAF types (extensible)
VALID_WAF_TYPES: Set[str] = {
    "cloudflare", "modsecurity", "aws_waf", "akamai",
    "imperva", "f5_bigip", "sucuri", "fortiweb",
    "nginx_naxsi", "barracuda", "unknown", "generic"
}

# Whitelist of valid encoding strategies (includes TASK-76 additions)
VALID_STRATEGIES: Set[str] = {
    "url_encode", "double_url_encode", "unicode_encode",
    "html_entity_encode", "html_entity_hex", "case_mixing",
    "null_byte_injection", "comment_injection", "whitespace_obfuscation",
    "base64_encode", "overlong_utf8", "backslash_escape", "base64_xss_wrap",
    # TASK-76: New evasion techniques
    "concat_string", "hex_encode", "scientific_notation",
    "buffer_overflow", "newline_injection"
}


def validate_name(name: str, allowed_set: Set[str], name_type: str = "name", max_length: int = 50) -> str:
    """
    Validate that a name is safe and in the allowed set.

    Args:
        name: The name to validate
        allowed_set: Set of allowed values
        name_type: Type of name for error messages ("waf" or "strategy")
        max_length: Maximum allowed length

    Returns:
        Validated name or "unknown" if invalid

    Raises:
        ValueError: If name is not a string or too long
    """
    if not isinstance(name, str):
        raise ValueError(f"{name_type} must be string, got {type(name).__name__}")

    if len(name) > max_length:
        raise ValueError(f"{name_type} too long: {len(name)} > {max_length}")

    # Only allow alphanumeric and underscore (prevent injection attacks)
    if not re.match(r'^[a-z0-9_]+$', name.lower()):
        logger.warning(f"Invalid {name_type} format rejected: {name[:20]}")
        return "unknown"

    # Normalize to lowercase
    name_lower = name.lower()

    if name_lower not in allowed_set:
        logger.warning(f"Unknown {name_type}: {name_lower}, defaulting to 'unknown'")
        return "unknown"

    return name_lower


@dataclass
class StrategyStats:
    """Statistics for a single strategy against a specific WAF."""
    attempts: int = 0
    successes: int = 0
    last_used: str = ""

    @property
    def success_rate(self) -> float:
        if self.attempts == 0:
            return 0.5  # Optimistic prior for unexplored strategies
        return self.successes / self.attempts

    def ucb_score(self, total_attempts: int = 1) -> float:
        """
        Upper Confidence Bound score for exploration vs exploitation (TASK-68).
        Higher score = should try this strategy more.

        Args:
            total_attempts: Total attempts across all strategies for proper UCB1

        Returns:
            UCB score combining exploitation (success rate) and exploration bonus
        """
        if self.attempts == 0:
            return float('inf')  # Encourage exploration of untried strategies

        # UCB1 formula: Q(s) + c * sqrt(ln(N) / n(s))
        # Where: Q(s) = success rate, c = exploration constant, N = total attempts, n(s) = strategy attempts
        c = settings.WAF_QLEARNING_UCB_CONSTANT
        exploration_bonus = c * math.sqrt(math.log(total_attempts + 1) / self.attempts)
        return self.success_rate + exploration_bonus


@dataclass
class WAFLearningData:
    """Learning data for a specific WAF."""
    waf_name: str
    strategies: Dict[str, StrategyStats] = field(default_factory=dict)

    def get_ranked_strategies(self) -> List[Tuple[str, float]]:
        """
        Return strategies ranked by UCB score (best first).
        Uses proper UCB1 formula with total attempts (TASK-68).
        """
        # Calculate total attempts for proper UCB1
        total_attempts = sum(stats.attempts for stats in self.strategies.values())
        total_attempts = max(total_attempts, 1)  # Avoid division by zero

        rankings = []
        for strategy_name, stats in self.strategies.items():
            rankings.append((strategy_name, stats.ucb_score(total_attempts)))

        # Add unexplored strategies with infinite score
        all_strategies = encoding_techniques.get_technique_names()
        for strat in all_strategies:
            if strat not in self.strategies:
                rankings.append((strat, float('inf')))

        # Sort by score descending
        rankings.sort(key=lambda x: x[1], reverse=True)
        return rankings

    def get_total_attempts(self) -> int:
        """Get total attempts across all strategies."""
        return sum(stats.attempts for stats in self.strategies.values())

    def get_total_successes(self) -> int:
        """Get total successes across all strategies."""
        return sum(stats.successes for stats in self.strategies.values())


class StrategyRouter:
    """
    Intelligent strategy selection using Multi-Armed Bandit (UCB1).

    Learns which encoding techniques work best against each WAF type
    and prioritizes them accordingly.

    Usage:
        router = StrategyRouter()

        # Get best strategies for a target
        waf, strategies = await router.get_strategies_for_target("https://example.com")

        # After testing, record what worked
        router.record_result("cloudflare", "unicode_encode", success=True)
    """

    def __init__(self, data_dir: Path = None):
        if data_dir is None:
            data_dir = Path("bugtrace/data")

        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.learning_file = self.data_dir / "waf_strategy_learning.json"

        self.learning_data: Dict[str, WAFLearningData] = self._load_learning_data()

        # Initial knowledge (seeded from security research)
        self._seed_initial_knowledge()

    def _load_learning_data(self) -> Dict[str, WAFLearningData]:
        """Load learning data from disk with validation (TASK-67)."""
        if not self.learning_file.exists():
            return {}

        try:
            with open(self.learning_file, 'r') as f:
                raw_data = json.load(f)

            result = {}
            rejected_wafs = 0
            rejected_strategies = 0

            for waf_name, waf_data in raw_data.items():
                # TASK-67: Validate WAF name on load
                if not re.match(r'^[a-z0-9_]+$', waf_name.lower()):
                    rejected_wafs += 1
                    continue
                if waf_name.lower() not in VALID_WAF_TYPES:
                    rejected_wafs += 1
                    continue

                waf_name_clean = waf_name.lower()
                strategies = {}

                for strat_name, strat_data in waf_data.get("strategies", {}).items():
                    # TASK-67: Validate strategy name on load
                    if not re.match(r'^[a-z0-9_]+$', strat_name.lower()):
                        rejected_strategies += 1
                        continue
                    if strat_name.lower() not in VALID_STRATEGIES:
                        rejected_strategies += 1
                        continue

                    # Validate numeric values
                    attempts = strat_data.get("attempts", 0)
                    successes = strat_data.get("successes", 0)
                    if not isinstance(attempts, (int, float)) or not isinstance(successes, (int, float)):
                        rejected_strategies += 1
                        continue

                    strategies[strat_name.lower()] = StrategyStats(
                        attempts=int(attempts),
                        successes=int(successes),
                        last_used=str(strat_data.get("last_used", ""))[:50]  # Limit length
                    )

                if strategies:  # Only add WAF if it has valid strategies
                    result[waf_name_clean] = WAFLearningData(waf_name=waf_name_clean, strategies=strategies)

            if rejected_wafs or rejected_strategies:
                logger.warning(f"Rejected {rejected_wafs} invalid WAFs and {rejected_strategies} invalid strategies during load")

            logger.info(f"Loaded learning data for {len(result)} WAFs")
            return result

        except json.JSONDecodeError as e:
            logger.warning(f"Q-table JSON corrupted: {e}, starting fresh")
            return {}
        except Exception as e:
            logger.warning(f"Failed to load learning data: {e}")
            return {}

    def _save_learning_data(self):
        """Save learning data to disk with automatic backup (TASK-71)."""
        try:
            # TASK-71: Create backup before saving
            if self.learning_file.exists():
                backup_path = f"{self.learning_file}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(self.learning_file, backup_path)
                self._cleanup_old_backups()

            data_to_save = {}
            for waf_name, waf_data in self.learning_data.items():
                strategies_dict = {}
                for strat_name, stats in waf_data.strategies.items():
                    strategies_dict[strat_name] = asdict(stats)
                data_to_save[waf_name] = {
                    "waf_name": waf_name,
                    "strategies": strategies_dict
                }

            # Write atomically (write to temp, then rename)
            temp_file = self.learning_file.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(data_to_save, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            # Atomic rename
            temp_file.rename(self.learning_file)
            logger.debug("Learning data saved successfully")

        except Exception as e:
            logger.error(f"Failed to save learning data: {e}")

    def _cleanup_old_backups(self, keep: int = None):
        """Remove old backup files, keeping only the most recent ones (TASK-71)."""
        if keep is None:
            keep = settings.WAF_QLEARNING_MAX_BACKUPS

        try:
            backup_pattern = f"{self.learning_file}.backup.*"
            backups = sorted(glob_module.glob(backup_pattern))
            for old_backup in backups[:-keep]:
                os.remove(old_backup)
                logger.debug(f"Removed old backup: {old_backup}")
        except Exception as e:
            logger.debug(f"Backup cleanup failed: {e}")

    def restore_from_backup(self, backup_index: int = 0) -> bool:
        """
        Restore Q-table from a backup file (TASK-71).

        Args:
            backup_index: 0 = most recent, 1 = second most recent, etc.

        Returns:
            True if restore successful, False otherwise
        """
        try:
            backup_pattern = f"{self.learning_file}.backup.*"
            backups = sorted(glob_module.glob(backup_pattern), reverse=True)

            if not backups:
                logger.warning("No backups available")
                return False

            if backup_index >= len(backups):
                logger.warning(f"Backup index {backup_index} not available (only {len(backups)} backups)")
                return False

            backup_file = backups[backup_index]
            shutil.copy2(backup_file, self.learning_file)
            self.learning_data = self._load_learning_data()
            logger.info(f"Restored from backup: {backup_file}")
            return True

        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False

    def _seed_initial_knowledge(self):
        """
        Seed the learning system with known-good strategy combinations.
        This gives the system a head start instead of random exploration.
        """
        # Initial seeds based on security research
        initial_seeds = {
            "cloudflare": [
                ("unicode_encode", 5, 3),      # 60% success
                ("html_entity_hex", 5, 2),     # 40% success
                ("case_mixing", 5, 2),         # 40% success
                ("double_url_encode", 5, 1),   # 20% success
            ],
            "modsecurity": [
                ("comment_injection", 5, 4),   # 80% success
                ("null_byte_injection", 5, 3), # 60% success
                ("double_url_encode", 5, 3),   # 60% success
            ],
            "aws_waf": [
                ("double_url_encode", 5, 3),   # 60% success
                ("comment_injection", 5, 2),   # 40% success
                ("whitespace_obfuscation", 5, 2),
            ],
            "akamai": [
                ("unicode_encode", 5, 3),
                ("whitespace_obfuscation", 5, 3),
                ("html_entity_encode", 5, 2),
            ],
            "imperva": [
                ("backslash_escape", 5, 3),
                ("unicode_encode", 5, 2),
                ("overlong_utf8", 5, 2),
            ],
        }

        for waf_name, seeds in initial_seeds.items():
            if waf_name not in self.learning_data:
                self.learning_data[waf_name] = WAFLearningData(waf_name=waf_name)

            for strategy, attempts, successes in seeds:
                if strategy not in self.learning_data[waf_name].strategies:
                    self.learning_data[waf_name].strategies[strategy] = StrategyStats(
                        attempts=attempts,
                        successes=successes,
                        last_used=""
                    )

    async def get_strategies_for_target(
        self,
        url: str,
        max_strategies: int = 5
    ) -> Tuple[str, List[str]]:
        """
        Get the best encoding strategies for a target URL.

        Args:
            url: Target URL to test
            max_strategies: Maximum number of strategies to return

        Returns:
            Tuple of (detected_waf_name, list_of_strategy_names)
        """
        # Step 1: Detect WAF
        waf_name, confidence = await waf_fingerprinter.detect(url)

        logger.info(f"Target WAF: {waf_name} (confidence: {confidence:.0%})")

        # Step 2: Get ranked strategies for this WAF
        if waf_name not in self.learning_data:
            self.learning_data[waf_name] = WAFLearningData(waf_name=waf_name)

        waf_data = self.learning_data[waf_name]
        ranked = waf_data.get_ranked_strategies()

        # Step 3: Return top N strategies
        top_strategies = [name for name, score in ranked[:max_strategies]]

        logger.info(f"Selected strategies for {waf_name}: {top_strategies}")

        return waf_name, top_strategies

    def record_result(self, waf_name: str, strategy_name: str, success: bool):
        """
        Record the result of using a strategy against a WAF.
        This is how the system learns.

        Args:
            waf_name: The WAF that was targeted
            strategy_name: The encoding strategy that was used
            success: Whether the bypass was successful

        Note: Inputs are validated to prevent data poisoning attacks (TASK-67)
        """
        # TASK-67: Validate inputs to prevent data poisoning
        try:
            waf_name = validate_name(waf_name, VALID_WAF_TYPES, "waf")
            strategy_name = validate_name(strategy_name, VALID_STRATEGIES, "strategy")
        except ValueError as e:
            logger.error(f"Invalid input rejected: {e}")
            return  # Don't record invalid data

        if waf_name not in self.learning_data:
            self.learning_data[waf_name] = WAFLearningData(waf_name=waf_name)

        waf_data = self.learning_data[waf_name]

        if strategy_name not in waf_data.strategies:
            waf_data.strategies[strategy_name] = StrategyStats()

        stats = waf_data.strategies[strategy_name]
        stats.attempts += 1
        if success:
            stats.successes += 1
        stats.last_used = datetime.now().isoformat()

        logger.debug(
            f"Recorded: {waf_name}/{strategy_name} = {'SUCCESS' if success else 'FAIL'} "
            f"(rate: {stats.success_rate:.0%})"
        )

        # Save periodically (every 10 updates)
        total_updates = sum(
            sum(s.attempts for s in w.strategies.values())
            for w in self.learning_data.values()
        )
        if total_updates % 10 == 0:
            self._save_learning_data()

    def get_stats_summary(self) -> Dict[str, Dict[str, float]]:
        """
        Get a summary of learning statistics.

        Returns:
            Dict mapping WAF names to their strategy success rates
        """
        summary = {}
        for waf_name, waf_data in self.learning_data.items():
            summary[waf_name] = {
                strat: stats.success_rate
                for strat, stats in waf_data.strategies.items()
                if stats.attempts > 0
            }
        return summary

    def get_detailed_metrics(self) -> Dict:
        """
        Get comprehensive bypass metrics (TASK-72).

        Returns:
            Dict with overall stats, per-WAF stats, and per-strategy stats
        """
        total_attempts = 0
        total_successes = 0
        by_waf = {}
        by_strategy = {}

        for waf_name, waf_data in self.learning_data.items():
            waf_attempts = waf_data.get_total_attempts()
            waf_successes = waf_data.get_total_successes()
            total_attempts += waf_attempts
            total_successes += waf_successes

            by_waf[waf_name] = {
                "attempts": waf_attempts,
                "successes": waf_successes,
                "success_rate": waf_successes / waf_attempts if waf_attempts > 0 else 0.0,
                "strategies_tried": len(waf_data.strategies)
            }

            for strat_name, stats in waf_data.strategies.items():
                if strat_name not in by_strategy:
                    by_strategy[strat_name] = {"attempts": 0, "successes": 0}
                by_strategy[strat_name]["attempts"] += stats.attempts
                by_strategy[strat_name]["successes"] += stats.successes

        # Calculate success rates for strategies
        for strat_name, stats in by_strategy.items():
            stats["success_rate"] = stats["successes"] / stats["attempts"] if stats["attempts"] > 0 else 0.0

        return {
            "overall": {
                "total_attempts": total_attempts,
                "total_successes": total_successes,
                "overall_success_rate": total_successes / total_attempts if total_attempts > 0 else 0.0,
                "wafs_encountered": len(self.learning_data),
                "strategies_used": len(by_strategy)
            },
            "by_waf": by_waf,
            "by_strategy": by_strategy,
            "best_strategies": sorted(
                [(s, d["success_rate"]) for s, d in by_strategy.items() if d["attempts"] >= 5],
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }

    def get_best_strategy_for_waf(self, waf_name: str) -> Optional[Tuple[str, float]]:
        """
        Get the single best strategy for a specific WAF (TASK-72).

        Args:
            waf_name: The WAF type

        Returns:
            Tuple of (strategy_name, success_rate) or None
        """
        if waf_name not in self.learning_data:
            return None

        waf_data = self.learning_data[waf_name]
        best = None
        best_rate = -1.0

        for strat_name, stats in waf_data.strategies.items():
            if stats.attempts >= 3 and stats.success_rate > best_rate:
                best = strat_name
                best_rate = stats.success_rate

        return (best, best_rate) if best else None

    def force_save(self):
        """Force save learning data to disk."""
        self._save_learning_data()
        logger.info("Learning data saved")

    def visualize_q_table(self, waf_filter: Optional[str] = None) -> str:
        """
        Generate ASCII visualization of Q-table state (TASK-78).

        Args:
            waf_filter: Optional WAF name to filter by

        Returns:
            Formatted string visualization
        """
        lines = []
        lines.append("=" * 70)
        lines.append("Q-LEARNING WAF STRATEGY TABLE")
        lines.append("=" * 70)

        wafs_to_show = [waf_filter] if waf_filter else list(self.learning_data.keys())

        for waf_name in wafs_to_show:
            if waf_name not in self.learning_data:
                continue

            waf_data = self.learning_data[waf_name]
            total_attempts = waf_data.get_total_attempts()
            total_successes = waf_data.get_total_successes()
            overall_rate = total_successes / total_attempts if total_attempts > 0 else 0

            lines.append(f"\n[{waf_name.upper()}] Total: {total_attempts} attempts, {overall_rate:.1%} success")
            lines.append("-" * 50)

            # Sort strategies by success rate
            sorted_strategies = sorted(
                waf_data.strategies.items(),
                key=lambda x: x[1].success_rate,
                reverse=True
            )

            for strat_name, stats in sorted_strategies:
                # Create visual bar
                bar_length = int(stats.success_rate * 20)
                bar = "█" * bar_length + "░" * (20 - bar_length)

                ucb = stats.ucb_score(total_attempts)
                lines.append(
                    f"  {strat_name:<25} [{bar}] "
                    f"{stats.success_rate:>5.1%} ({stats.successes}/{stats.attempts}) UCB:{ucb:.2f}"
                )

        lines.append("\n" + "=" * 70)

        # Add summary
        metrics = self.get_detailed_metrics()
        lines.append(f"Overall: {metrics['overall']['total_attempts']} attempts, "
                    f"{metrics['overall']['overall_success_rate']:.1%} success rate")

        if metrics['best_strategies']:
            best = metrics['best_strategies'][0]
            lines.append(f"Best strategy overall: {best[0]} ({best[1]:.1%})")

        return "\n".join(lines)

    def print_q_table(self, waf_filter: Optional[str] = None):
        """Print Q-table visualization to console (TASK-78)."""
        print(self.visualize_q_table(waf_filter))

    def get_learning_progress(self) -> Dict:
        """
        Get learning progress summary for monitoring (TASK-78).

        Returns:
            Dict with learning progress metrics
        """
        metrics = self.get_detailed_metrics()

        # Calculate exploration vs exploitation ratio
        total_unique_strategies = 0
        total_strategies_tried = 0

        for waf_name, waf_data in self.learning_data.items():
            total_unique_strategies += len(waf_data.strategies)
            for stats in waf_data.strategies.values():
                if stats.attempts > 0:
                    total_strategies_tried += 1

        # Estimate if we're exploring enough
        available_strategies = len(VALID_STRATEGIES)
        wafs_seen = len(self.learning_data)
        max_possible = available_strategies * wafs_seen if wafs_seen > 0 else 1
        exploration_coverage = total_unique_strategies / max_possible if max_possible > 0 else 0

        return {
            "wafs_learned": wafs_seen,
            "strategies_tried": total_strategies_tried,
            "total_attempts": metrics['overall']['total_attempts'],
            "overall_success_rate": metrics['overall']['overall_success_rate'],
            "exploration_coverage": exploration_coverage,
            "is_exploring": exploration_coverage < 0.5,  # Still exploring if < 50% coverage
            "best_strategies": metrics['best_strategies']
        }


# Singleton instance
strategy_router = StrategyRouter()
