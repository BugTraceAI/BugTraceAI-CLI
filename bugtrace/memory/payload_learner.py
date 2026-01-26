
import json
import os
from pathlib import Path
from typing import List, Dict, Set
import filelock
from bugtrace.utils.logger import get_logger

logger = get_logger("memory.payload_learner")

class PayloadLearner:
    """
    Manages the learning and prioritization of attack payloads (Hybrid System).
    
    1. Loads Curated User Lists (Static High Quality)
    2. Learns from Successful Exploits (Dynamic Memory)
    3. Prioritizes Proven Payloads based on Context
    """
    
    def __init__(self, data_bfs: Path = Path("bugtrace/data")):
        self.data_dir = data_bfs
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.proven_file = self.data_dir / "xss_proven_payloads.json"
        self.curated_file = self.data_dir / "xss_curated_list.txt"
        
        self.proven_payloads: List[Dict] = self._load_proven()
        self.curated_payloads: List[str] = self._load_curated()
        
    def _load_proven(self) -> List[Dict]:
        """Load proven payloads from JSON memory."""
        if not self.proven_file.exists():
            return []
        try:
            with open(self.proven_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load proven payloads: {e}")
            return []

    def _load_curated(self) -> List[str]:
        """Load static curated list from text file."""
        if not self.curated_file.exists():
            return []
        try:
            payloads = []
            with open(self.curated_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
            logger.info(f"Loaded {len(payloads)} curated payloads.")
            return payloads
        except Exception as e:
            logger.error(f"Failed to load curated payloads: {e}")
            return []

    def save_success(self, payload: str, context: str = "unknown", url: str = ""):
        """
        Register a successful exploitation (Reinforcement Learning).
        Boosts the score if exists, adds if new.
        """
        found = False
        for entry in self.proven_payloads:
            if entry['payload'] == payload:
                entry['score'] += 1
                entry['last_success'] = _now()
                if context not in entry['contexts']:
                    entry['contexts'].append(context)
                found = True
                break
        
        if not found:
            self.proven_payloads.append({
                "payload": payload,
                "score": 1,
                "contexts": [context],
                "first_seen": _now(),
                "last_success": _now()
            })
            
        self._save_to_disk()
        logger.info(f"Memory: Learned successful payload (Score: {self._get_score(payload)})")

    def _save_to_disk(self):
        """Save proven payloads with file locking for thread safety (Bug #5)."""
        lock_file = self.proven_file.with_suffix('.lock')
        lock = filelock.FileLock(str(lock_file), timeout=10)

        try:
            with lock:
                with open(self.proven_file, 'w') as f:
                    json.dump(self.proven_payloads, f, indent=2)
        except filelock.Timeout:
            logger.warning("Could not acquire lock for payload file, skipping save")
        except Exception as e:
            logger.error(f"Failed to save proven payloads: {e}")

    def _get_score(self, payload: str) -> int:
        for p in self.proven_payloads:
            if p['payload'] == payload:
                return p['score']
        return 0

    def get_prioritized_payloads(self, default_list: List[str] = []) -> List[str]:
        """
        Returns a smart list of payloads in execution order:
        1. Curated User Payloads (Highest Priority - Manual overrides)
        2. Proven Payloads (Dynamic Memory - Highest Score first)
        3. Default Agent Payloads (if not already included)
        """
        final_list = []
        seen = set()

        # 1. Curated (User/Operator priority)
        for p in self.curated_payloads:
            if p not in seen:
                final_list.append(p)
                seen.add(p)

        # 2. Proven (Dynamic memory from successes)
        sorted_proven = sorted(self.proven_payloads, key=lambda x: x['score'], reverse=True)
        for item in sorted_proven:
            p = item['payload']
            if p not in seen:
                final_list.append(p)
                seen.add(p)
                
        # 3. Defaults
        for p in default_list:
            if p not in seen:
                final_list.append(p)
                seen.add(p)
                
        return final_list

def _now():
    from datetime import datetime
    return datetime.now().isoformat()
