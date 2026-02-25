"""
Chain Discovery Core

PURE functions for chain templates, vulnerability conversion,
severity inference, graph operations, and Mermaid diagram generation.

Extracted from chain_discovery_agent.py for modularity.
"""

import json
from typing import List, Dict, Set, Optional, Any, Tuple
from datetime import datetime


# =============================================================================
# CHAIN TEMPLATES
# =============================================================================

# Vulnerability type mapping from specialist names to internal format
VULN_TYPE_MAP = {
    "xss": "XSS",
    "sqli": "SQLi",
    "csti": "CSTI",
    "lfi": "LFI",
    "idor": "IDOR",
    "rce": "RCE",
    "ssrf": "SSRF",
    "xxe": "XXE",
    "jwt": "JWT",
    "openredirect": "Open Redirect",
    "prototype_pollution": "Prototype Pollution",
}

# Severity inference by vulnerability type
CRITICAL_TYPES = {"RCE", "SQLi", "SSRF", "XXE"}
HIGH_TYPES = {"XSS", "CSTI", "LFI", "JWT", "IDOR", "Prototype Pollution"}
MEDIUM_TYPES = {"Open Redirect"}


def get_critical_chain_templates() -> List[Dict]:  # PURE
    """Get critical severity chain templates.

    Returns:
        List of critical chain template dicts
    """
    return [
        {
            "name": "SQLi to RCE",
            "steps": ["SQLi", "Auth Bypass", "Admin Access", "File Upload", "RCE"],
            "severity": "CRITICAL",
            "impact": "Full system compromise",
            "likelihood": 0.7,
        },
        {
            "name": "SSRF to Cloud Takeover",
            "steps": ["SSRF", "Cloud Metadata", "IAM Credentials", "S3 Access"],
            "severity": "CRITICAL",
            "impact": "Cloud resource compromise",
            "likelihood": 0.6,
        },
        {
            "name": "IDOR to Mass Data Breach",
            "steps": ["IDOR", "User Enumeration", "Admin ID Discovery", "Full DB Access"],
            "severity": "CRITICAL",
            "impact": "Complete data breach",
            "likelihood": 0.5,
        },
        {
            "name": "JWT None Algorithm to Privilege Escalation",
            "steps": ["JWT Analysis", "None Algorithm", "Token Forgery", "Admin Access"],
            "severity": "CRITICAL",
            "impact": "Authentication bypass",
            "likelihood": 0.6,
        },
        {
            "name": "Path Traversal to Source Code Leak",
            "steps": ["Path Traversal", "Config File Read", "Credential Extraction", "Database Access"],
            "severity": "CRITICAL",
            "impact": "Source code + credentials",
            "likelihood": 0.5,
        },
    ]


def get_high_severity_chain_templates() -> List[Dict]:  # PURE
    """Get high severity chain templates.

    Returns:
        List of high severity chain template dicts
    """
    return [
        {
            "name": "XSS to Account Takeover",
            "steps": ["XSS", "Cookie Theft", "Session Hijack", "Account Takeover"],
            "severity": "HIGH",
            "impact": "User account compromise",
            "likelihood": 0.8,
        },
        {
            "name": "GraphQL Introspection to Data Leak",
            "steps": ["GraphQL Discovery", "Introspection", "Sensitive Query", "Data Exfiltration"],
            "severity": "HIGH",
            "impact": "Sensitive data exposure",
            "likelihood": 0.7,
        },
        {
            "name": "CSRF to Admin Action",
            "steps": ["CSRF", "Admin Cookie Theft", "Forged Request", "Privilege Escalation"],
            "severity": "HIGH",
            "impact": "Unauthorized admin actions",
            "likelihood": 0.4,
        },
    ]


def load_chain_templates() -> List[Dict]:  # PURE
    """Load all known exploitation chain patterns.

    These are high-value chains commonly seen in bug bounties.

    Returns:
        Combined list of all chain templates
    """
    templates = []
    templates.extend(get_critical_chain_templates())
    templates.extend(get_high_severity_chain_templates())
    return templates


# =============================================================================
# VULNERABILITY CONVERSION (PURE)
# =============================================================================

def infer_severity(vuln_type: str) -> str:  # PURE
    """Infer severity from vulnerability type.

    Args:
        vuln_type: Vulnerability type string

    Returns:
        Severity string (CRITICAL, HIGH, MEDIUM, LOW)
    """
    if vuln_type in CRITICAL_TYPES:
        return "CRITICAL"
    elif vuln_type in HIGH_TYPES:
        return "HIGH"
    elif vuln_type in MEDIUM_TYPES:
        return "MEDIUM"
    return "LOW"


def convert_specialist_finding(
    specialist: str,
    finding: Dict,
    status: str,
) -> Optional[Dict]:  # PURE
    """
    Convert specialist finding to internal vulnerability format.

    Args:
        specialist: Specialist agent name (xss, sqli, csti, etc.)
        finding: Finding data from specialist
        status: Validation status

    Returns:
        Vulnerability dict compatible with chain analysis, or None
    """
    vuln_type = VULN_TYPE_MAP.get(specialist.lower(), finding.get("type", "Unknown"))

    return {
        "type": vuln_type,
        "url": finding.get("url"),
        "parameter": finding.get("parameter"),
        "payload": finding.get("payload"),
        "severity": finding.get("severity", infer_severity(vuln_type)),
        "status": status,
        "source": f"specialist:{specialist}",
        "exploitable": status == "VALIDATED_CONFIRMED",
        "specialist_data": finding,  # Keep original data for chain analysis
    }


# =============================================================================
# GRAPH OPERATIONS (PURE)
# =============================================================================

def make_vuln_node_id(vuln: Dict, node_count: int) -> str:  # PURE
    """Generate unique node ID for exploitation graph.

    Args:
        vuln: Vulnerability dict
        node_count: Current number of nodes in graph

    Returns:
        Unique node ID string
    """
    return f"{vuln.get('type')}_{vuln.get('url', 'unknown')}_{node_count}"


def build_node_attributes(vuln: Dict) -> Dict:  # PURE
    """Build graph node attributes from vulnerability dict.

    Args:
        vuln: Vulnerability dict

    Returns:
        Node attribute dict for NetworkX
    """
    return {
        "type": vuln.get("type"),
        "severity": vuln.get("severity", "MEDIUM"),
        "url": vuln.get("url"),
        "payload": vuln.get("payload"),
        "verified": vuln.get("verified", False),
        "timestamp": datetime.now().isoformat(),
    }


def build_chain_from_template(
    template: Dict,
    graph_nodes: List[Tuple[str, Dict]],
) -> Optional[List[Dict]]:  # PURE
    """
    Build concrete exploitation chain from template.

    Maps template steps to actual discovered vulnerabilities in the graph.

    Args:
        template: Chain template dict
        graph_nodes: List of (node_id, data) tuples from graph

    Returns:
        List of chain steps or None if empty
    """
    chain = []

    for step_name in template["steps"]:
        # Find matching vulnerability
        matching_vulns = [
            (node_id, data)
            for node_id, data in graph_nodes
            if data["type"] == step_name
        ]

        if matching_vulns:
            node_id, vuln_data = matching_vulns[0]
            chain.append({
                "step": step_name,
                "vulnerability_id": node_id,
                "url": vuln_data.get("url"),
                "payload": vuln_data.get("payload"),
                "exploited": False,
            })
        else:
            # Step not yet discovered
            chain.append({
                "step": step_name,
                "status": "pending_discovery",
                "exploited": False,
            })

    return chain if chain else None


def find_matching_templates(
    templates: List[Dict],
    discovered_types: Set[str],
) -> List[Dict]:  # PURE
    """Find chain templates that match discovered vulnerability types.

    Args:
        templates: Available chain templates
        discovered_types: Set of discovered vulnerability type strings

    Returns:
        List of matching templates
    """
    matching = []
    for template in templates:
        template_steps = set(template["steps"][:2])
        if template_steps.issubset(discovered_types):
            matching.append(template)
    return matching


# =============================================================================
# STEP EXECUTION HELPERS (PURE)
# =============================================================================

def step_execute_and_validate(step_name: str, guidance: Dict) -> Dict:  # PURE
    """Execute step action and validate success (simulated).

    Args:
        step_name: Name of exploitation step
        guidance: LLM guidance dict

    Returns:
        Result dict with success/failure
    """
    # Simulate success based on vulnerability type
    simulated_success = step_name in ["SQLi", "XSS", "IDOR", "SSRF", "JWT Analysis"]

    if simulated_success:
        return {
            "success": True,
            "step": step_name,
            "action": guidance.get("action"),
            "result": "Exploitation successful (simulated)",
        }
    else:
        return {
            "success": False,
            "step": step_name,
            "error": "Exploitation failed - protection detected",
        }


def step_build_error(step_name: str, error: Exception) -> Dict:  # PURE
    """Build error result for failed step.

    Args:
        step_name: Name of exploitation step
        error: Exception that occurred

    Returns:
        Error result dict
    """
    return {
        "success": False,
        "step": step_name,
        "error": str(error),
    }


# =============================================================================
# REPORT BUILDING (PURE)
# =============================================================================

def build_chain_report(
    template: Dict,
    chain: List[Dict],
    exploit_log: List[Dict],
    poc_script: str = "# PoC generation failed",
) -> Dict:  # PURE
    """Build chain exploitation report.

    Args:
        template: Chain template used
        chain: Chain steps
        exploit_log: Exploitation log entries
        poc_script: Generated PoC script

    Returns:
        Report dict
    """
    return {
        "chain_name": template["name"],
        "severity": template["severity"],
        "impact": template["impact"],
        "steps_completed": len(exploit_log),
        "total_steps": len(chain),
        "exploitation_path": exploit_log,
        "timestamp": datetime.now().isoformat(),
        "proof_of_concept": poc_script,
    }


def build_exploit_prompt(template: Dict, step_name: str, url: str, payload: str) -> str:  # PURE
    """Build LLM prompt for exploitation step guidance.

    Args:
        template: Chain template
        step_name: Current step name
        url: Target URL
        payload: Available payload

    Returns:
        Prompt string for LLM
    """
    return f"""
You are an expert penetration tester. You've discovered a vulnerability chain.

Chain Template: {template['name']}
Current Step: {step_name}
URL: {url}
Available Payload: {payload}

What is the NEXT exploitation action to progress this chain?

Provide:
1. Specific command/request to execute
2. Expected outcome
3. How to verify success

Format as JSON:
{{
    "action": "description",
    "method": "GET/POST/etc",
    "url": "target_url",
    "payload": "exploitation_payload",
    "success_indicators": ["indicator1", "indicator2"],
    "next_step_prerequisites": "what we need for next step"
}}
"""


def build_poc_prompt(template: Dict, chain: List[Dict], exploit_log: List[Dict]) -> str:  # PURE
    """Build LLM prompt for PoC script generation.

    Args:
        template: Chain template
        chain: Chain steps
        exploit_log: Exploitation log

    Returns:
        Prompt string for LLM
    """
    return f"""
Generate a Python proof-of-concept script that reproduces this exploitation chain:

Chain: {template['name']}
Steps: {json.dumps(chain, indent=2)}
Exploitation Log: {json.dumps(exploit_log, indent=2)}

Requirements:
- Use requests library
- Include comments explaining each step
- Handle errors gracefully
- Print clear output showing progression
- Include success/failure indicators

Output ONLY the Python code, no explanations.
"""


# =============================================================================
# MERMAID VISUALIZATION (PURE)
# =============================================================================

SEVERITY_COLORS = {
    "CRITICAL": "fill:#ff0000",
    "HIGH": "#ff6600",
    "MEDIUM": "#ffaa00",
    "LOW": "#00aa00",
}


def visualize_graph(
    graph_nodes: List[Tuple[str, Dict]],
    discovered_chains: List[List[Dict]],
) -> str:  # PURE
    """
    Generate Mermaid diagram of exploitation graph.

    Useful for reports and presentations.

    Args:
        graph_nodes: List of (node_id, data) tuples
        discovered_chains: List of chain step lists

    Returns:
        Mermaid diagram string
    """
    mermaid = ["graph TD"]

    for node_id, data in graph_nodes:
        vuln_type = data.get("type", "Unknown")
        severity = data.get("severity", "MEDIUM")
        color = SEVERITY_COLORS.get(severity, "#cccccc")

        mermaid.append(f'    {node_id}["{vuln_type}<br/>{severity}"]')
        mermaid.append(f'    style {node_id} {color}')

    # Add edges (chains)
    for chain in discovered_chains:
        for i in range(len(chain) - 1):
            step1 = chain[i].get("vulnerability_id")
            step2 = chain[i + 1].get("vulnerability_id")
            if step1 and step2:
                mermaid.append(f'    {step1} --> {step2}')

    return "\n".join(mermaid)
