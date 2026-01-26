"""
Skill Loader for DASTySAST Agent.
Loads specialized knowledge based on detected vulnerability types.
"""

import os
import logging
from pathlib import Path
from typing import List, Optional
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.skills")

SKILLS_DIR = Path(__file__).parent / "vulnerabilities"

# Map vulnerability types to skill files
SKILL_MAP = {
    "ssrf": "ssrf.md",
    "server-side request": "ssrf.md",
    "sqli": "sqli.md",
    "sql injection": "sqli.md",
    "sql": "sqli.md",
    "xxe": "xxe.md",
    "xml external": "xxe.md",
    "xss": "xss.md",
    "cross-site scripting": "xss.md",
    "rce": "rce.md",
    "remote code": "rce.md",
    "command injection": "rce.md",
    "lfi": "lfi.md",
    "path traversal": "lfi.md",
    "local file": "lfi.md",
    "idor": "idor.md",
    "insecure direct": "idor.md",
    "jwt": "jwt.md",
    "token": "jwt.md",
}


def get_skill_content(vuln_type: str) -> Optional[str]:
    """
    Load skill content for a specific vulnerability type.
    
    Args:
        vuln_type: The vulnerability type (e.g., "SSRF", "SQL Injection")
    
    Returns:
        The skill markdown content, or None if not found.
    """
    vuln_lower = vuln_type.lower()
    
    for keyword, filename in SKILL_MAP.items():
        if keyword in vuln_lower:
            skill_path = SKILLS_DIR / filename
            if skill_path.exists():
                logger.info(f"Loaded skill content for {vuln_type} from {filename}")
                return skill_path.read_text()
    
    return None


def get_skills_for_findings(findings: List[dict], max_skills: int = 3) -> str:
    """
    Load relevant skills for a list of findings.
    Deduplicates and limits to max_skills to avoid token overload.
    
    Args:
        findings: List of vulnerability findings with 'type' field
        max_skills: Maximum number of skills to include
    
    Returns:
        Combined skill content as a string.
    """
    loaded_skills = set()
    skill_contents = []
    
    for finding in findings:
        vuln_type = finding.get("type", "")
        vuln_lower = vuln_type.lower()
        
        # Find matching skill
        for keyword, filename in SKILL_MAP.items():
            if keyword in vuln_lower and filename not in loaded_skills:
                content = get_skill_content(vuln_type)
                if content:
                    loaded_skills.add(filename)
                    skill_contents.append(content)
                    
                    if len(skill_contents) >= max_skills:
                        break
        
        if len(skill_contents) >= max_skills:
            break
    
    if skill_contents:
        return "\n\n---\n\n".join(skill_contents)
    
    return ""


import re

def _extract_section(content: str, tag_name: str) -> str:
    """
    Core extraction logic for skill sections.
    Supports both:
    1. <!-- tag --> ... <!-- /tag --> (MD033 compliant)
    2. <tag> ... </tag> (Legacy/XML-like)
    """
    if not content:
        return ""
        
    # Pattern 1: Markdown comments (preferred for linting)
    comment_pattern = rf"<!--\s*{tag_name}\s*-->(.*?)<!--\s*/{tag_name}\s*-->"
    match = re.search(comment_pattern, content, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
        
    # Pattern 2: XML-like tags
    xml_pattern = rf"<{tag_name}>(.*?)</{tag_name}>"
    match = re.search(xml_pattern, content, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
        
    return ""


def get_scoring_guide(vuln_type: str) -> str:
    """Extract scoring guide section."""
    content = get_skill_content(vuln_type)
    return _extract_section(content, "scoring_guide")


def get_false_positives(vuln_type: str) -> str:
    """Extract false positives section."""
    content = get_skill_content(vuln_type)
    return _extract_section(content, "false_positives")
