"""
BugtraceAI Skills Package

Modular skill classes for URLMasterAgent exploitation and reconnaissance.
Each skill encapsulates a specific vulnerability testing capability.
"""

from .base import BaseSkill
from .recon import ReconSkill, AnalyzeSkill
from .injection import XSSSkill, SQLiSkill, LFISkill, XXESkill, CSTISkill
from .infrastructure import HeaderInjectionSkill, PrototypePollutionSkill
from .external_tools import SQLMapSkill, NucleiSkill, GoSpiderSkill, MutationSkill
from .advanced import SSRFSkill, IDORSkill, OpenRedirectSkill, OOBXSSSkill, CSRFSkill
from .utility import BrowserSkill, ReportSkill

# Registry of all available skills for URLMasterAgent
SKILL_REGISTRY = {
    # Reconnaissance
    "recon": ReconSkill,
    "analyze": AnalyzeSkill,
    
    # Injection vulnerabilities
    "xss": XSSSkill,
    "sqli": SQLiSkill,
    "lfi": LFISkill,
    "xxe": XXESkill,
    "csti": CSTISkill,
    
    # Infrastructure
    "header_injection": HeaderInjectionSkill,
    "prototype_pollution": PrototypePollutionSkill,
    
    # External tools
    "sqlmap": SQLMapSkill,
    "nuclei": NucleiSkill,
    "gospider": GoSpiderSkill,
    "mutation": MutationSkill,
    
    # Advanced (v1.6)
    "ssrf": SSRFSkill,
    "idor": IDORSkill,
    "open_redirect": OpenRedirectSkill,
    "oob_xss": OOBXSSSkill,
    "csrf": CSRFSkill,
    
    # Utility
    "browser": BrowserSkill,
    "report": ReportSkill,
}

__all__ = [
    "BaseSkill",
    "SKILL_REGISTRY",
    # Recon
    "ReconSkill",
    "AnalyzeSkill",
    # Injection
    "XSSSkill",
    "SQLiSkill", 
    "LFISkill",
    "XXESkill",
    "CSTISkill",
    # Infrastructure
    "HeaderInjectionSkill",
    "PrototypePollutionSkill",
    # External
    "SQLMapSkill",
    "NucleiSkill",
    "GoSpiderSkill",
    "MutationSkill",
    # Advanced
    "SSRFSkill",
    "IDORSkill",
    "OpenRedirectSkill",
    "OOBXSSSkill",
    "CSRFSkill",
    # Utility
    "BrowserSkill",
    "ReportSkill",
]
