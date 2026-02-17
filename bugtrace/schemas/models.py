import logging
from pydantic import BaseModel, Field
from typing import List, Optional, Any
from enum import Enum

_vuln_logger = logging.getLogger("bugtrace.schemas.models")

class VulnType(str, Enum):
    XSS = "XSS"
    SQLI = "SQLI"
    RCE = "RCE"
    XXE = "XXE"
    CSTI = "CSTI"
    PROTO_POLLUTION = "PROTOTYPE_POLLUTION"
    OPEN_REDIRECT = "OPEN_REDIRECT"
    HEADER_INJECTION = "HEADER_INJECTION"
    SENSITIVE_DATA = "SENSITIVE_DATA_EXPOSURE"
    IDOR = "IDOR"
    LFI = "LFI"
    SSRF = "SSRF"
    MISCONFIG = "SECURITY_MISCONFIGURATION"
    JWT = "JWT"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    API_SECURITY = "API_SECURITY"
    FILE_UPLOAD = "FILE_UPLOAD"

def normalize_vuln_type(type_str: str) -> VulnType:
    """
    Normalize common vulnerability type strings to VulnType enum.
    Handles case variations and common aliases.
    """
    type_upper = type_str.upper().strip()
    type_map = _build_vuln_type_mappings()

    # Direct lookup
    if type_upper in type_map:
        return type_map[type_upper]

    # Fuzzy match
    fuzzy_match = _try_fuzzy_match(type_upper, type_map)
    if fuzzy_match:
        return fuzzy_match

    # Enum value match
    return _try_enum_match(type_str)

def _build_vuln_type_mappings() -> dict:
    """Build mapping of vulnerability type strings to VulnType enum."""
    return {
        "XSS": VulnType.XSS,
        "CROSS-SITE SCRIPTING": VulnType.XSS,
        "CROSS-SITE SCRIPTING (XSS)": VulnType.XSS,
        "SQLI": VulnType.SQLI,
        "SQL INJECTION": VulnType.SQLI,
        "SQL": VulnType.SQLI,
        "SQLINJECTION": VulnType.SQLI,
        "RCE": VulnType.RCE,
        "REMOTE CODE EXECUTION": VulnType.RCE,
        "XXE": VulnType.XXE,
        "XML EXTERNAL ENTITY": VulnType.XXE,
        "CSTI": VulnType.CSTI,
        "CLIENT-SIDE TEMPLATE INJECTION": VulnType.CSTI,
        "SSTI": VulnType.CSTI,
        "SERVER-SIDE TEMPLATE INJECTION": VulnType.CSTI,
        "PROTOTYPE_POLLUTION": VulnType.PROTO_POLLUTION,
        "PROTOTYPE POLLUTION": VulnType.PROTO_POLLUTION,
        "OPEN_REDIRECT": VulnType.OPEN_REDIRECT,
        "OPEN REDIRECT": VulnType.OPEN_REDIRECT,
        "HEADER_INJECTION": VulnType.HEADER_INJECTION,
        "HEADER INJECTION": VulnType.HEADER_INJECTION,
        "SENSITIVE_DATA_EXPOSURE": VulnType.SENSITIVE_DATA,
        "SENSITIVE DATA EXPOSURE": VulnType.SENSITIVE_DATA,
        "DATA EXPOSURE": VulnType.SENSITIVE_DATA,
        "IDOR": VulnType.IDOR,
        "INSECURE DIRECT OBJECT REFERENCE": VulnType.IDOR,
        "LFI": VulnType.LFI,
        "LOCAL FILE INCLUSION": VulnType.LFI,
        "SSRF": VulnType.SSRF,
        "SERVER-SIDE REQUEST FORGERY": VulnType.SSRF,
        "SECURITY_MISCONFIGURATION": VulnType.MISCONFIG,
        "SECURITY MISCONFIGURATION": VulnType.MISCONFIG,
        "MISCONFIG": VulnType.MISCONFIG,
        "JWT": VulnType.JWT,
        "JSON WEB TOKEN": VulnType.JWT,
        "JWT ATTACK": VulnType.JWT,
        "JWT VULNERABILITY": VulnType.JWT,
        "WEAK JWT": VulnType.JWT,
        "MASS_ASSIGNMENT": VulnType.MASS_ASSIGNMENT,
        "MASS ASSIGNMENT": VulnType.MASS_ASSIGNMENT,
        "OVERPOSTING": VulnType.MASS_ASSIGNMENT,
        "API_SECURITY": VulnType.API_SECURITY,
        "API SECURITY": VulnType.API_SECURITY,
        "GRAPHQL": VulnType.API_SECURITY,
        "GRAPHQL INJECTION": VulnType.API_SECURITY,
        "GRAPHQL INTROSPECTION": VulnType.API_SECURITY,
        "FILE_UPLOAD": VulnType.FILE_UPLOAD,
        "FILE UPLOAD": VulnType.FILE_UPLOAD,
        "UNRESTRICTED FILE UPLOAD": VulnType.FILE_UPLOAD,
        "UNRESTRICTED UPLOAD": VulnType.FILE_UPLOAD,
    }

def _try_fuzzy_match(type_upper: str, type_map: dict) -> Optional[VulnType]:
    """Attempt fuzzy match for vulnerability type variants."""
    for key, val in type_map.items():
        if key in type_upper and len(key) > 2:
            return val
    return None

def _try_enum_match(type_str: str) -> VulnType:
    """Try to match as enum value, default to MISCONFIG if invalid."""
    try:
        return VulnType(type_str)
    except ValueError:
        _vuln_logger.warning(
            f"Unknown vulnerability type '{type_str}' — falling back to SECURITY_MISCONFIGURATION. "
            f"Consider adding it to VulnType enum and _build_vuln_type_mappings()."
        )
        return VulnType.MISCONFIG

class ReflectionContext(str, Enum):
    NONE = "NONE"
    HTML_TAG = "HTML_TAG"
    ATTRIBUTE = "ATTRIBUTE"
    JS_BLOCK = "JS_BLOCK"

class Vulnerability(BaseModel):
    type: VulnType
    severity: str
    payload_used: str
    reflection_context: Optional[ReflectionContext] = None
    confidence_score: float = 0.0
    details: str
    visual_validated: bool = False
    attack_url: Optional[str] = None
    vuln_parameter: Optional[str] = None

class Target(BaseModel):
    url: str
    
class AgentState(BaseModel):
    current_target: Optional[Target] = None
    findings: List[Vulnerability] = []
    
class GoSpiderConfig(BaseModel):
    enabled: bool = True
    depth: int = 2
    max_urls: int = 50
    concurrent: int = 10
    image: str = "jaeles-project/gospider"

class NucleiConfig(BaseModel):
    enabled: bool = True
    severity: str = "critical,high,medium"
    templates: str = "cves,vulnerabilities"
    image: str = "projectdiscovery/nuclei:latest"
    rate_limit: int = 150

class SQLMapConfig(BaseModel):
    enabled: bool = True
    level: int = 1
    risk: int = 1
    batch: bool = True
    image: str = "sqlmapproject/sqlmap"

class DatabaseConfig(BaseModel):
    url: str = "sqlite:///bugtrace.db"
    vector_path: str = "./data/lancedb"

class ReconConfig(BaseModel):
    gospider: GoSpiderConfig = Field(default_factory=GoSpiderConfig)

class ExploitConfig(BaseModel):
    nuclei: NucleiConfig = Field(default_factory=NucleiConfig)
    sqlmap: SQLMapConfig = Field(default_factory=SQLMapConfig)

class SkepticalConfig(BaseModel):
    enabled: bool = True

class GlobalConfig(BaseModel):
    api_key: Optional[str] = None
    openrouter_api_key: Optional[str] = None # OpenRouter Visibility
    enable_rich_ui: bool = True
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)
    exploit: ExploitConfig = Field(default_factory=ExploitConfig)
    skeptical: SkepticalConfig = Field(default_factory=SkepticalConfig)
