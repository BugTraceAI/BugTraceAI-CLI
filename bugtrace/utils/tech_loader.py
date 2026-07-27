"""
Tech Profile Loader - Utility for loading technology detection results.

Provides a singleton accessor for tech_profile.json so specialist agents
can access infrastructure/framework information for precise exploit generation.

Author: BugtraceAI Team
Date: 2026-02-02
Version: 1.0.0
"""

import json
from pathlib import Path
from typing import Dict, Optional
from bugtrace.utils.logger import get_logger

logger = get_logger("tech_loader")


def load_tech_profile(scan_dir: Path) -> Dict:
    """
    Load tech_profile.json from scan directory.
    
    Args:
        scan_dir: Path to scan report directory
        
    Returns:
        Tech profile dictionary with infrastructure, frameworks, etc.
        Empty dict if file not found.
    """
    tech_profile_path = scan_dir / "tech_profile.json"

    # NucleiAgent writes to recon/ subdirectory, specialists load from scan root
    if not tech_profile_path.exists():
        tech_profile_path = scan_dir / "recon" / "tech_profile.json"

    if not tech_profile_path.exists():
        logger.debug(f"Tech profile not found at {scan_dir}")
        return {
            "infrastructure": [],
            "frameworks": [],
            "servers": [],
            "languages": [],
            "cms": [],
            "waf": [],
            "cdn": [],
            "tech_tags": []
        }
    
    try:
        with open(tech_profile_path, "r") as f:
            tech_profile = json.load(f)
            
        logger.info(f"Tech profile loaded: {len(tech_profile.get('frameworks', []))} frameworks, "
                   f"{len(tech_profile.get('infrastructure', []))} infrastructure")
        
        return tech_profile
        
    except Exception as e:
        logger.error(f"Failed to load tech_profile.json: {e}")
        return {
            "infrastructure": [],
            "frameworks": [],
            "servers": [],
            "languages": [],
            "cms": [],
            "waf": [],
            "cdn": [],
            "tech_tags": []
        }


def format_tech_context(tech_profile: Dict) -> str:
    """
    Format tech profile for LLM context.
    
    Args:
        tech_profile: Tech profile dictionary
        
    Returns:
        Formatted string for inclusion in prompts
    """
    parts = []
    
    if tech_profile.get("infrastructure"):
        parts.append(f"Infrastructure: {', '.join(tech_profile['infrastructure'])}")
    
    if tech_profile.get("frameworks"):
        parts.append(f"Frameworks: {', '.join(tech_profile['frameworks'])}")
    
    if tech_profile.get("servers"):
        parts.append(f"Servers: {', '.join(tech_profile['servers'])}")
    
    if tech_profile.get("languages"):
        parts.append(f"Languages: {', '.join(tech_profile['languages'])}")
    
    if tech_profile.get("waf"):
        parts.append(f"⚠️ WAF: {', '.join(tech_profile['waf'])}")
    
    if tech_profile.get("cdn"):
        parts.append(f"CDN: {', '.join(tech_profile['cdn'])}")
    
    if not parts:
        return "Technology Stack: Basic web application (no specific technologies detected)"
    
    return "Technology Stack:\n" + "\n".join(f"  - {p}" for p in parts)
