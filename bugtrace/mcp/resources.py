"""MCP Resources for BugTraceAI AI assistant integration.

This module registers MCP resources that provide structured reference data:
- scan_results/{scan_id}: Combined scan status and findings
- vulnerability_types: List of all detectable vulnerability categories
- configuration_schema: JSON schema of ScanOptions and runtime config fields

Resources are read-only and provide context for AI assistants to understand
BugTraceAI's capabilities and current scan state.

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

from typing import Any, Dict

from bugtrace.mcp.server import mcp_server
from bugtrace.api.deps import get_scan_service
from bugtrace.schemas.models import VulnType
from bugtrace.services.scan_context import ScanOptions
from bugtrace.core.config import settings


# Vulnerability type knowledge base
VULN_TYPE_DESCRIPTIONS = {
    "XSS": {
        "name": "Cross-Site Scripting",
        "description": "Injection of malicious scripts into web pages viewed by other users"
    },
    "SQLI": {
        "name": "SQL Injection",
        "description": "Insertion of SQL code into application queries to manipulate database"
    },
    "RCE": {
        "name": "Remote Code Execution",
        "description": "Ability to execute arbitrary code on the target server"
    },
    "XXE": {
        "name": "XML External Entity",
        "description": "Processing of external XML entities leading to data disclosure or SSRF"
    },
    "CSTI": {
        "name": "Client-Side Template Injection",
        "description": "Injection into client-side template engines"
    },
    "PROTOTYPE_POLLUTION": {
        "name": "Prototype Pollution",
        "description": "Manipulation of JavaScript object prototypes"
    },
    "OPEN_REDIRECT": {
        "name": "Open Redirect",
        "description": "Unvalidated redirect to attacker-controlled URLs"
    },
    "HEADER_INJECTION": {
        "name": "Header Injection",
        "description": "Injection of HTTP headers via user input"
    },
    "SENSITIVE_DATA_EXPOSURE": {
        "name": "Sensitive Data Exposure",
        "description": "Unprotected exposure of sensitive information"
    },
    "IDOR": {
        "name": "Insecure Direct Object Reference",
        "description": "Direct access to objects via user-supplied references without authorization"
    },
    "LFI": {
        "name": "Local File Inclusion",
        "description": "Inclusion of local server files through manipulated file paths"
    },
    "SSRF": {
        "name": "Server-Side Request Forgery",
        "description": "Server-side requests to attacker-specified URLs"
    },
    "SECURITY_MISCONFIGURATION": {
        "name": "Security Misconfiguration",
        "description": "Insecure default configurations or missing security hardening"
    }
}


@mcp_server.resource("scan-results://{scan_id}")
async def get_scan_results(scan_id: str) -> Dict[str, Any]:
    """
    Get combined scan status and findings for a specific scan.

    Args:
        scan_id: Scan identifier

    Returns:
        Dictionary with scan status and findings, or error if scan not found
    """
    try:
        # Convert scan_id to int
        scan_id_int = int(scan_id)

        # Get scan service
        scan_service = get_scan_service()

        # Fetch status and findings
        status = await scan_service.get_scan_status(scan_id_int)
        findings = await scan_service.get_findings(scan_id_int, per_page=100)

        return {
            "status": status,
            "findings": findings
        }
    except ValueError as e:
        return {
            "error": "Scan not found",
            "scan_id": scan_id,
            "details": str(e)
        }
    except Exception as e:
        return {
            "error": "Failed to retrieve scan results",
            "scan_id": scan_id,
            "details": str(e)
        }


@mcp_server.resource("bugtrace://vulnerability_types")
async def get_vulnerability_types() -> Dict[str, Any]:
    """
    Get list of all detectable vulnerability types.

    Returns:
        Dictionary with vulnerability_types array containing id, name, and description
    """
    vulnerability_types = []

    for vuln_type in VulnType:
        vuln_value = vuln_type.value
        vuln_info = VULN_TYPE_DESCRIPTIONS.get(vuln_value, {
            "name": vuln_value.replace("_", " ").title(),
            "description": f"Vulnerability type: {vuln_value}"
        })

        vulnerability_types.append({
            "id": vuln_value,
            "name": vuln_info["name"],
            "description": vuln_info["description"]
        })

    return {
        "vulnerability_types": vulnerability_types
    }


@mcp_server.resource("bugtrace://configuration_schema")
async def get_configuration_schema() -> Dict[str, Any]:
    """
    Get JSON schema of ScanOptions and runtime configuration fields.

    Returns:
        Dictionary with scan_options_schema and runtime_config_fields
    """
    # Get ScanOptions JSON schema
    scan_options_schema = ScanOptions.model_json_schema()

    # Define runtime config fields that can be modified via API
    runtime_config_fields = {
        "MAX_DEPTH": {
            "type": "integer",
            "description": "Maximum crawl depth for URL discovery",
            "current_value": settings.MAX_DEPTH
        },
        "MAX_URLS": {
            "type": "integer",
            "description": "Maximum number of URLs to scan",
            "current_value": settings.MAX_URLS
        },
        "MAX_CONCURRENT_URL_AGENTS": {
            "type": "integer",
            "description": "Maximum number of concurrent URL scanning agents",
            "current_value": settings.MAX_CONCURRENT_URL_AGENTS
        },
        "SAFE_MODE": {
            "type": "boolean",
            "description": "Enable safe mode to limit aggressive scanning techniques",
            "current_value": settings.SAFE_MODE
        },
        "DEFAULT_MODEL": {
            "type": "string",
            "description": "Default LLM model for scanning operations",
            "current_value": settings.DEFAULT_MODEL
        }
    }

    return {
        "scan_options_schema": scan_options_schema,
        "runtime_config_fields": runtime_config_fields
    }
