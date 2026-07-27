"""
Breakout Manager - Manages payload breakout prefixes with auto-learning.

Features:
- Load breakouts from JSON files
- Auto-learn successful breakouts
- Track success statistics
- Fully editable configuration (no hardcoding)
"""

import json
import asyncio
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from bugtrace.utils.logger import get_logger

logger = get_logger("tools.manipulator.breakout_manager")


@dataclass
class Breakout:
    """Represents a single breakout prefix with metadata."""
    prefix: str
    description: str
    category: str = "general"
    priority: int = 3  # 1=critical, 2=high, 3=normal, 4=advanced
    success_count: int = 0
    last_success: Optional[str] = None
    enabled: bool = True

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'Breakout':
        return cls(**data)


class BreakoutManager:
    """
    Manages breakout prefixes - ZERO hardcoding, everything from files.
    """

    def __init__(self, breakouts_file: Path = None, learned_file: Path = None):
        self.base_dir = Path(__file__).parent.parent.parent / "payloads"

        # Files
        self.breakouts_file = breakouts_file or (self.base_dir / "breakouts.json")
        self.learned_file = learned_file or (self.base_dir / "learned_breakouts.json")

        # State
        self.breakouts: List[Breakout] = []
        self._breakout_map: Dict[str, Breakout] = {}
        self._lock = asyncio.Lock()

        # Initialize
        self._ensure_learned_file_exists()
        self.load_breakouts()

    def _ensure_learned_file_exists(self):
        """Create empty learned file if not exists."""
        if not self.learned_file.exists():
            self.learned_file.parent.mkdir(parents=True, exist_ok=True)
            empty_learned = {
                "version": "1.0",
                "description": "Auto-learned breakouts from successful attacks",
                "last_updated": datetime.now().isoformat(),
                "breakouts": []
            }
            self.learned_file.write_text(json.dumps(empty_learned, indent=2))
            logger.info(f"Created empty learned breakouts file: {self.learned_file}")

    def load_breakouts(self):
        """Load breakouts from files - NO HARDCODING."""
        self.breakouts.clear()
        self._breakout_map.clear()

        # Load base breakouts from file
        if not self.breakouts_file.exists():
            logger.error(f"Breakouts file not found: {self.breakouts_file}")
            logger.error("Please ensure bugtrace/payloads/breakouts.json exists")
            return

        try:
            data = json.loads(self.breakouts_file.read_text())
            for item in data.get("breakouts", []):
                breakout = Breakout.from_dict(item)
                if breakout.enabled:
                    self.breakouts.append(breakout)
                    self._breakout_map[breakout.prefix] = breakout
            logger.info(f"✓ Loaded {len(self.breakouts)} base breakouts from {self.breakouts_file.name}")
        except Exception as e:
            logger.error(f"Failed to load breakouts from {self.breakouts_file}: {e}")
            return

        # Load learned breakouts
        try:
            data = json.loads(self.learned_file.read_text())
            learned_count = 0
            for item in data.get("breakouts", []):
                breakout = Breakout.from_dict(item)
                if breakout.enabled and breakout.prefix not in self._breakout_map:
                    self.breakouts.append(breakout)
                    self._breakout_map[breakout.prefix] = breakout
                    learned_count += 1
            if learned_count > 0:
                logger.info(f"✓ Loaded {learned_count} learned breakouts")
            logger.info(f"📊 Total active breakouts: {len(self.breakouts)}")
        except Exception as e:
            logger.error(f"Failed to load learned breakouts: {e}")

    def get_breakout_prefixes(self, category: str = None, max_priority: int = 3) -> List[str]:
        """
        Get breakout prefixes filtered by category and priority.

        Args:
            category: Filter by vulnerability type (xss, sqli, ssti, etc.)
            max_priority: Only include breakouts with priority <= max_priority
                         1 = Critical only (~8 breakouts)
                         2 = Critical + High (~19 breakouts)
                         3 = All common (~40 breakouts) [DEFAULT]
                         4 = Everything including advanced

        Returns:
            List of breakout prefix strings
        """
        filtered = self.breakouts

        # Filter by priority
        filtered = [b for b in filtered if b.priority <= max_priority]

        # Filter by category if specified
        if category:
            filtered = [b for b in filtered if category.lower() in b.category.lower()]

        return [b.prefix for b in filtered]

    async def record_success(self, payload: str, vuln_type: str = "general"):
        """
        Record successful payload and auto-learn new breakout if detected.

        Args:
            payload: The successful payload
            vuln_type: Type of vulnerability (xss, sqli, etc.)
        """
        async with self._lock:
            detected_breakout = self._detect_breakout(payload)

            if detected_breakout:
                if detected_breakout in self._breakout_map:
                    # Known breakout - increment success count
                    breakout = self._breakout_map[detected_breakout]
                    breakout.success_count += 1
                    breakout.last_success = datetime.now().isoformat()
                    logger.info(f"✓ Breakout '{detected_breakout}' success #{breakout.success_count}")
                else:
                    # NEW breakout discovered! 🎉
                    logger.info(f"🎯 NEW BREAKOUT DISCOVERED: '{detected_breakout}' (type: {vuln_type})")
                    new_breakout = Breakout(
                        prefix=detected_breakout,
                        description=f"Auto-learned from {vuln_type} success",
                        success_count=1,
                        last_success=datetime.now().isoformat(),
                        category=vuln_type,
                        priority=3,
                        enabled=True
                    )
                    self.breakouts.append(new_breakout)
                    self._breakout_map[detected_breakout] = new_breakout

                    # Save to learned file
                    await self._save_learned_breakout(new_breakout)

                # Update main file stats
                await self._save_stats()

    def _detect_breakout(self, payload: str) -> Optional[str]:
        """
        Detect breakout prefix from successful payload.
        Returns the longest matching known prefix, or extracts a new one.
        """
        # First check known breakouts (longest match)
        matching = [
            prefix for prefix in self._breakout_map.keys()
            if prefix and payload.startswith(prefix)
        ]
        if matching:
            return max(matching, key=len)

        # Try to extract new breakout pattern
        import re
        patterns = [
            r'^["\']',           # Quotes
            r'^["\']>',          # Quote + close
            r'^</\w+>',          # Tag close
            r'^%[0-9a-fA-F]{2}', # URL encoded
            r'^[<>(){}\[\]]',    # Brackets
        ]

        for pattern in patterns:
            match = re.match(pattern, payload)
            if match:
                potential = match.group(0)
                if 1 <= len(potential) <= 10:
                    return potential

        return None

    async def _save_learned_breakout(self, breakout: Breakout):
        """Save newly learned breakout to learned file."""
        try:
            data = json.loads(self.learned_file.read_text())
            data["breakouts"].append(breakout.to_dict())
            data["last_updated"] = datetime.now().isoformat()
            self.learned_file.write_text(json.dumps(data, indent=2))
            logger.info(f"💾 Saved learned breakout to {self.learned_file.name}")
        except Exception as e:
            logger.error(f"Failed to save learned breakout: {e}")

    async def _save_stats(self):
        """Update success statistics in main file."""
        try:
            data = json.loads(self.breakouts_file.read_text())
            for item in data["breakouts"]:
                prefix = item["prefix"]
                if prefix in self._breakout_map:
                    breakout = self._breakout_map[prefix]
                    item["success_count"] = breakout.success_count
                    item["last_success"] = breakout.last_success
            data["last_updated"] = datetime.now().isoformat()
            self.breakouts_file.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Failed to save stats: {e}")

    def get_top_breakouts(self, limit: int = 10) -> List[Breakout]:
        """Get most successful breakouts sorted by success count."""
        return sorted(
            self.breakouts,
            key=lambda b: b.success_count,
            reverse=True
        )[:limit]

    def reload(self):
        """Reload breakouts from files (for manual edits)."""
        logger.info("🔄 Reloading breakouts from files...")
        self.load_breakouts()


# Singleton instance
breakout_manager = BreakoutManager()
