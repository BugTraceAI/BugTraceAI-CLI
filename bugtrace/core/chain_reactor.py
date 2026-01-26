from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from bugtrace.schemas.models import VulnType
from bugtrace.schemas.db_models import FindingTable
from bugtrace.utils.logger import get_logger

logger = get_logger("core.chain_reactor")

@dataclass
class AttackChain:
    name: str
    description: str
    priority: int  # 1 (Highest) to 10 (Lowest)
    steps: List[str]
    required_findings: List[str]

class ChainReactor:
    """
    Logic engine for correlating independent findings into Attack Chains.
    "Connecting the dots" between vulnerabilities using type-safe logic.
    """
    
    def __init__(self):
        pass

    def analyze_chains(self, findings: List[FindingTable], context_flags: List[str] = []) -> List[AttackChain]:
        """
        Analyzes a list of findings and context flags to identify potential attack chains.
        
        Args:
            findings: List of DB FindingTable objects
            context_flags: List of string flags (e.g., "login_detected", "admin_panel")
        """
        chains = []
        
        # Mapping findings for quick lookup (Using Enum Values correctly)
        # findings.type should be VulnType Enum or string that matches it
        finding_types = set()
        for f in findings:
            if hasattr(f.type, 'value'):
                finding_types.add(f.type.value)
            else:
                finding_types.add(str(f.type))
                
        # Safe concatenation of details
        finding_details = " ".join([str(f.details or "") for f in findings]).lower()
        
        # --- Rule 1: Account Takeover Chain ---
        # Trigger: Reflected XSS + Login Page Detected
        if VulnType.XSS.value in finding_types and "login_page_indicator" in context_flags:
            chains.append(AttackChain(
                name="Account Takeover via XSS",
                description="Use the XSS vulnerability on the Login Page to steal session cookies.",
                priority=1,
                steps=[
                    "Craft XSS payload to document.cookie",
                    "Send malicious link to victim (simulated)",
                    "Capture session ID"
                ],
                required_findings=["Reflected XSS", "Login Form"]
            ))

        # --- Rule 2: Admin Compromise Chain ---
        # Trigger: SQL Injection + Admin Panel
        if VulnType.SQLI.value in finding_types and "admin_panel_indicator" in context_flags:
            chains.append(AttackChain(
                name="Admin Panel Bypass via SQLi",
                description="Use SQL Injection to bypass authentication on the Admin Panel.",
                priority=1,
                steps=[
                    "Locate Admin Login",
                    "Inject ' OR '1'='1'-- into username field",
                    "Access Admin Dashboard"
                ],
                required_findings=["SQL Injection", "Admin Panel"]
            ))
            
        # --- Rule 3: Database Dump Chain ---
        # Trigger: SQL Injection (Union)
        if VulnType.SQLI.value in finding_types and "union" in finding_details:
             chains.append(AttackChain(
                name="Full Database Exfiltration",
                description="Union-based SQL Injection allows dumping the entire database.",
                priority=2,
                steps=[
                    "Identify column count (ORDER BY)",
                    "Extract table names (information_schema)",
                    "Dump user/pass columns"
                ],
                required_findings=["Union-based SQLi"]
            ))

        # --- Rule 4: Credential Stuffing Risk ---
        # Trigger: Leaked API Key or Private Key
        if VulnType.SENSITIVE_DATA.value in finding_types or any("leaked" in f for f in context_flags):
             chains.append(AttackChain(
                name="Credential Abuse / Stuffing",
                description="Use leaked keys/tokens to access protected APIs or services.",
                priority=3,
                steps=[
                    "Validate leaked key permissions",
                    "Access internal API endpoints",
                    "Pivot to other services"
                ],
                required_findings=["Leaked Credentials"]
            ))

        if chains:
            logger.info(f"ChainReactor: Identified {len(chains)} potential attack chains.")
            
        return chains

# Singleton
chain_reactor = ChainReactor()
