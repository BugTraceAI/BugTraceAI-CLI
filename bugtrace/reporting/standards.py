"""
Centralized reporting standards and constants for BugTraceAI.

This module provides:
- Standardized CWE mappings for vulnerability types
- Remediation templates for common vulnerabilities
- Default severity levels for each vulnerability type
- Helper functions for consistent formatting and normalization
"""

from typing import Optional
from bugtrace.reporting.models import Severity


# CWE Mappings: Maps vulnerability types to Common Weakness Enumeration IDs
# Reference: https://cwe.mitre.org/
CWE_MAPPINGS = {
    "XSS": "CWE-79",  # Improper Neutralization of Input During Web Page Generation
    "SQLI": "CWE-89",  # Improper Neutralization of Special Elements used in an SQL Command
    "LFI": "CWE-22",  # Improper Limitation of a Pathname to a Restricted Directory
    "SSRF": "CWE-918",  # Server-Side Request Forgery
    "IDOR": "CWE-639",  # Authorization Bypass Through User-Controlled Key
    "JWT": "CWE-347",  # Improper Verification of Cryptographic Signature
    "XXE": "CWE-611",  # Improper Restriction of XML External Entity Reference
    "RCE": "CWE-94",  # Improper Control of Generation of Code
    "OPEN_REDIRECT": "CWE-601",  # URL Redirection to Untrusted Site
    "PROTOTYPE_POLLUTION": "CWE-1321",  # Improperly Controlled Modification of Object Prototype Attributes
    "CSTI": "CWE-1336",  # Improper Neutralization of Special Elements Used in a Template Engine
    "SSTI": "CWE-1336",  # Improper Neutralization of Special Elements Used in a Template Engine
    "HEADER_INJECTION": "CWE-113",  # Improper Neutralization of CRLF Sequences in HTTP Headers
    "FILE_UPLOAD": "CWE-434",  # Unrestricted Upload of File with Dangerous Type
    "MASS_ASSIGNMENT": "CWE-915",  # Improperly Controlled Modification of Dynamically-Determined Object Attributes
    "API_SECURITY": "CWE-863",  # Incorrect Authorization
    "MISSING_SECURITY_HEADER": "CWE-693",  # Protection Mechanism Failure
    "BROKEN_ACCESS_CONTROL": "CWE-284",  # Improper Access Control
    "INSECURE_COOKIE_CONFIGURATION": "CWE-614",  # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    "GRAPHQL_INTROSPECTION": "CWE-200",  # Exposure of Sensitive Information
    "API_DOCUMENTATION_EXPOSURE": "CWE-200",  # Exposure of Sensitive Information
    "INSECURE_DESERIALIZATION": "CWE-502",  # Deserialization of Untrusted Data
    "VULNERABLE_DEPENDENCY": "CWE-1035",  # Using Components with Known Vulnerabilities
    "MISSING_RATE_LIMITING": "CWE-770",  # Allocation of Resources Without Limits
    "INFORMATION_DISCLOSURE": "CWE-200",  # Exposure of Sensitive Information
    "CORS_MISCONFIGURATION": "CWE-942",  # Permissive Cross-domain Policy with Untrusted Domains
    "WEAK_CRYPTOGRAPHY": "CWE-326",  # Inadequate Encryption Strength
    "CSRF": "CWE-352",  # Cross-Site Request Forgery
}


def _normalize_vuln_type_key(vuln_type: str) -> str:
    """Normalize vulnerability type string for dictionary lookups.

    Converts 'Broken Access Control', 'broken access control',
    'BROKEN_ACCESS_CONTROL' all to 'BROKEN_ACCESS_CONTROL'.
    """
    return vuln_type.upper().strip().replace(" ", "_")


# Remediation Templates: Standard remediation guidance for each vulnerability type
REMEDIATION_TEMPLATES = {
    "XSS": """
To remediate Cross-Site Scripting (XSS) vulnerabilities:
1. Implement proper output encoding/escaping for all user-controlled data
2. Use Content Security Policy (CSP) headers to restrict script execution
3. Validate and sanitize all input data on the server side
4. Use security-focused template engines that auto-escape by default
5. Consider using HTTP-only cookies to prevent JavaScript access to session tokens
""",
    "SQLI": """
To remediate SQL Injection (SQLi) vulnerabilities:
1. Use parameterized queries (prepared statements) exclusively
2. Never concatenate user input directly into SQL queries
3. Implement strict input validation and whitelist allowed characters
4. Use ORM frameworks with built-in SQL injection protection
5. Apply principle of least privilege to database accounts
6. Disable detailed error messages in production to prevent information disclosure
""",
    "LFI": """
To remediate Local File Inclusion (LFI) vulnerabilities:
1. Avoid using user input to construct file paths
2. Implement strict whitelist validation for allowed file paths/names
3. Use absolute paths and verify files are within allowed directories
4. Disable PHP allow_url_include and allow_url_fopen if not required
5. Implement proper access controls and file permission checks
6. Consider using a file access API instead of direct file operations
""",
    "SSRF": """
To remediate Server-Side Request Forgery (SSRF) vulnerabilities:
1. Validate and sanitize all URLs before making server-side requests
2. Implement whitelist-based validation for allowed domains/IP ranges
3. Disable redirects or validate redirect destinations
4. Block requests to internal/private IP ranges (RFC 1918, loopback, etc.)
5. Use network segmentation to isolate sensitive internal services
6. Implement URL parsing and validation to prevent bypass techniques
""",
    "IDOR": """
To remediate Insecure Direct Object Reference (IDOR) vulnerabilities:
1. Implement proper authorization checks for every object access
2. Use indirect references (UUIDs, mappings) instead of sequential IDs
3. Verify the current user has permission to access the requested resource
4. Implement role-based or attribute-based access control (RBAC/ABAC)
5. Log all access attempts for audit purposes
6. Never rely on client-side access controls alone
""",
    "JWT": """
To remediate JWT (JSON Web Token) vulnerabilities:
1. Always verify JWT signatures using strong algorithms (RS256, ES256)
2. Reject tokens with 'none' or weak algorithms (HS256 with public keys)
3. Validate all JWT claims (iss, aud, exp, nbf)
4. Use short expiration times and implement token rotation
5. Store JWT secrets securely (environment variables, key management systems)
6. Implement token revocation mechanisms for compromised tokens
7. Never trust client-provided algorithm headers (alg parameter)
""",
    "XXE": """
To remediate XML External Entity (XXE) vulnerabilities:
1. Disable external entity processing in all XML parsers
2. Disable DTD processing if not required
3. Use less complex data formats (JSON) when possible
4. Keep XML parser libraries updated to latest secure versions
5. Implement input validation to reject suspicious XML content
6. Use parser-specific configurations to disable dangerous features
""",
    "RCE": """
To remediate Remote Code Execution (RCE) vulnerabilities:
1. Never pass user input directly to code execution functions (eval, exec, system)
2. Implement strict input validation with whitelist approach
3. Use safe alternatives to dangerous functions when possible
4. Apply principle of least privilege to application processes
5. Use sandboxing and containerization to limit impact
6. Disable or remove unnecessary dangerous functions
7. Implement comprehensive logging and monitoring for suspicious activity
""",
    "OPEN_REDIRECT": """
To remediate Open Redirect vulnerabilities:
1. Validate all redirect URLs against a whitelist of trusted domains
2. Avoid using user input directly in redirect functions
3. Use relative URLs for internal redirects when possible
4. Implement URL parsing to verify protocol, domain, and path
5. Reject redirects to external domains unless explicitly required
6. Log all redirect attempts for security monitoring
7. Consider using indirect references (e.g., redirect IDs) mapped to safe URLs
""",
    "PROTOTYPE_POLLUTION": """
To remediate Prototype Pollution vulnerabilities:
1. Validate and sanitize all object keys before using them in assignments
2. Use Map instead of plain objects for user-controlled data
3. Freeze Object.prototype to prevent modifications
4. Use Object.create(null) for objects that should not inherit from Object.prototype
5. Implement strict input validation to reject keys like __proto__, constructor, prototype
6. Use modern JavaScript features and avoid unsafe object merging patterns
7. Keep all dependencies updated as prototype pollution often comes from libraries
""",
    "CSTI": """
To remediate Client-Side Template Injection (CSTI) / Server-Side Template Injection (SSTI) vulnerabilities:
1. Never pass user input directly into template expressions
2. Use sandboxed template engines or disable dangerous features (e.g., code execution)
3. Implement strict input validation and output encoding for template contexts
4. For AngularJS: use Content Security Policy (CSP) and avoid ng-bind-html with untrusted data
5. For server-side engines (Jinja2, Twig, Velocity): disable eval/exec capabilities in production
6. Consider using logic-less templates (Mustache, Handlebars) when full template power is not needed
7. Upgrade to frameworks that auto-escape template expressions by default
""",
    "SSTI": """
To remediate Server-Side Template Injection (SSTI) vulnerabilities:
1. Never pass user input directly into template expressions
2. Use sandboxed template engines or disable dangerous features (e.g., code execution)
3. For Jinja2: use SandboxedEnvironment and disable dangerous globals
4. For Velocity/Freemarker: restrict class access and disable reflection
5. For Twig: use the sandbox extension with strict whitelist policies
6. Implement strict input validation before template rendering
7. Apply principle of least privilege to template engine configurations
""",
    "HEADER_INJECTION": """
To remediate HTTP Header Injection (CRLF Injection) vulnerabilities:
1. Validate and sanitize all user input used in HTTP headers
2. Reject or encode CR (\\r) and LF (\\n) characters in header values
3. Use framework-provided methods for setting HTTP headers (they typically sanitize input)
4. Implement Content Security Policy (CSP) to mitigate impact of injected headers
5. Never use raw user input in Set-Cookie, Location, or other sensitive headers
""",
    "FILE_UPLOAD": """
To remediate Unrestricted File Upload vulnerabilities:
1. Validate file types using both MIME type and file extension whitelists
2. Verify file content (magic bytes) matches the declared type
3. Store uploaded files outside the web root directory
4. Generate random filenames to prevent path traversal
5. Implement file size limits and rate limiting
6. Scan uploaded files for malware using antivirus engines
7. Disable script execution in upload directories (e.g., .htaccess, web.config)
""",
    "MASS_ASSIGNMENT": """
To remediate Mass Assignment vulnerabilities:
1. Use explicit allowlists of permitted fields for each endpoint
2. Never bind request body directly to database models or ORM objects
3. Use Data Transfer Objects (DTOs) or serializers with declared fields
4. Reject or strip undeclared fields from request payloads
5. Implement role-based field access (e.g., only admins can set 'role' field)
6. Log unexpected fields in requests for security monitoring
""",
    "API_SECURITY": """
To remediate API Security vulnerabilities:
1. Disable GraphQL introspection in production environments
2. Implement proper authentication and authorization on all API endpoints
3. Apply rate limiting and query depth limits on GraphQL endpoints
4. Use field-level authorization to restrict access to sensitive data
5. Validate and sanitize all API input parameters
6. Implement proper pagination to prevent data enumeration
7. Disable verbose error messages that leak internal structure
""",
    "MISSING_SECURITY_HEADER": """
To remediate missing security headers:
1. Enable HSTS (Strict-Transport-Security) with includeSubDomains and preload
2. Set X-Content-Type-Options: nosniff to prevent MIME sniffing
3. Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking
4. Implement Content-Security-Policy (CSP) to restrict resource loading
5. Set Secure and HttpOnly flags on all session cookies
6. Set SameSite=Strict or Lax on cookies to prevent CSRF
""",
    "BROKEN_ACCESS_CONTROL": """
To remediate Broken Access Control vulnerabilities:
1. Implement proper authentication and authorization checks on all endpoints
2. Deny access by default; require explicit grants for each resource
3. Remove or protect administrative endpoints from public access
4. Use role-based access control (RBAC) consistently across the application
5. Log and monitor all access attempts to sensitive endpoints
6. Regularly audit exposed endpoints and remove unnecessary ones
""",
    "INSECURE_COOKIE_CONFIGURATION": """
To remediate Insecure Cookie Configuration:
1. Set the Secure flag on all cookies to ensure transmission only over HTTPS
2. Set the HttpOnly flag to prevent JavaScript access to session cookies
3. Set SameSite=Strict or SameSite=Lax to mitigate CSRF attacks
4. Set appropriate cookie expiration and path restrictions
5. Avoid storing sensitive data directly in cookies
""",
    "GRAPHQL_INTROSPECTION": """
To remediate GraphQL Introspection exposure:
1. Disable introspection queries in production environments
2. Implement proper authentication and authorization on GraphQL endpoints
3. Apply query depth limiting and complexity analysis
4. Use field-level authorization to restrict access to sensitive data
5. Implement rate limiting on GraphQL endpoints
""",
    "API_DOCUMENTATION_EXPOSURE": """
To remediate API Documentation Exposure:
1. Disable Swagger/OpenAPI/ReDoc endpoints in production environments
2. Require authentication to access API documentation endpoints
3. Use environment-based configuration to toggle documentation visibility
4. Review exposed endpoints for sensitive operations or data
""",
    "INSECURE_DESERIALIZATION": """
To remediate Insecure Deserialization vulnerabilities:
1. Avoid deserializing untrusted data whenever possible
2. Use safe serialization formats (JSON) instead of native object serialization
3. Implement integrity checks (signatures, HMACs) on serialized data
4. Restrict deserialization to expected types using allowlists
5. Monitor and log deserialization failures for security events
""",
    "VULNERABLE_DEPENDENCY": """
To remediate Vulnerable Dependency issues:
1. Update the affected library to a patched version
2. Implement a Software Composition Analysis (SCA) tool in CI/CD
3. Monitor CVE databases for vulnerabilities in your dependencies
4. Use package lock files to prevent accidental version drift
5. Consider alternatives for libraries with poor security track records
""",
    "MISSING_RATE_LIMITING": """
To remediate Missing Rate Limiting:
1. Implement rate limiting on authentication and sensitive endpoints
2. Use progressive delays or account lockout after failed attempts
3. Apply per-IP and per-user rate limits independently
4. Return proper HTTP 429 responses with Retry-After headers
5. Log and alert on rate limit violations for abuse detection
""",
    "CORS_MISCONFIGURATION": """
To remediate CORS Misconfiguration:
1. Restrict Access-Control-Allow-Origin to specific trusted domains
2. Never use wildcard (*) with credentials mode
3. Validate the Origin header against a strict whitelist
4. Avoid reflecting the Origin header back in Access-Control-Allow-Origin
5. Restrict allowed methods and headers to what is actually needed
""",
    "CSRF": """
To remediate Cross-Site Request Forgery (CSRF) vulnerabilities:
1. Use anti-CSRF tokens (synchronizer token pattern) on all state-changing requests
2. Set SameSite=Strict or SameSite=Lax on session cookies
3. Verify the Origin and Referer headers on sensitive endpoints
4. Use framework-provided CSRF protection mechanisms
5. Require re-authentication for sensitive operations
""",
}


# Default Severity: Maps vulnerability types to their typical severity levels
# Note: Actual severity may vary based on context and exploitability
DEFAULT_SEVERITY = {
    "XSS": Severity.HIGH,
    "SQLI": Severity.CRITICAL,
    "LFI": Severity.HIGH,
    "SSRF": Severity.HIGH,
    "IDOR": Severity.HIGH,
    "JWT": Severity.CRITICAL,
    "XXE": Severity.HIGH,
    "RCE": Severity.CRITICAL,
    "OPEN_REDIRECT": Severity.MEDIUM,
    "PROTOTYPE_POLLUTION": Severity.HIGH,
    "CSTI": Severity.HIGH,
    "SSTI": Severity.CRITICAL,
    "HEADER_INJECTION": Severity.MEDIUM,
    "FILE_UPLOAD": Severity.HIGH,
    "MASS_ASSIGNMENT": Severity.HIGH,
    "API_SECURITY": Severity.HIGH,
    "MISSING_SECURITY_HEADER": Severity.LOW,
    "BROKEN_ACCESS_CONTROL": Severity.HIGH,
    "INSECURE_COOKIE_CONFIGURATION": Severity.LOW,
    "GRAPHQL_INTROSPECTION": Severity.MEDIUM,
    "API_DOCUMENTATION_EXPOSURE": Severity.LOW,
    "INSECURE_DESERIALIZATION": Severity.CRITICAL,
    "VULNERABLE_DEPENDENCY": Severity.MEDIUM,
    "MISSING_RATE_LIMITING": Severity.MEDIUM,
    "INFORMATION_DISCLOSURE": Severity.LOW,
    "CORS_MISCONFIGURATION": Severity.MEDIUM,
    "WEAK_CRYPTOGRAPHY": Severity.MEDIUM,
    "CSRF": Severity.MEDIUM,
}


# Reference CVEs: Maps (vuln_type, context) to known CVE references.
# These are well-known CVEs for specific technologies/engines that serve as
# references in professional pentest reports. The framework uses these as
# fallback when the LLM doesn't return a CVE.
# Key format: "VULN_TYPE" for generic, "VULN_TYPE:context" for engine-specific
REFERENCE_CVES = {
    # SSTI/CSTI by template engine
    "CSTI:velocity": "CVE-2020-13936",    # Apache Velocity arbitrary code execution
    "CSTI:freemarker": "CVE-2022-24816",  # Apache Freemarker template injection
    "CSTI:jinja2": "CVE-2019-10906",      # Jinja2 sandbox escape
    "CSTI:twig": "CVE-2022-39261",        # Twig path traversal / code execution
    "CSTI:angular": "CVE-2022-25869",     # AngularJS XSS via sandbox escape
    "CSTI:angularjs": "CVE-2022-25869",
    "CSTI:pebble": "CVE-2022-37767",      # Pebble template injection
    "SSTI:velocity": "CVE-2020-13936",
    "SSTI:freemarker": "CVE-2022-24816",
    "SSTI:jinja2": "CVE-2019-10906",
    "SSTI:twig": "CVE-2022-39261",
    "SSTI:pebble": "CVE-2022-37767",
    # XXE by parser
    "XXE": "CVE-2021-29505",              # Generic XML External Entity reference
    # JWT
    "JWT:none_algorithm": "CVE-2022-23529",  # JWT none algorithm bypass
    # Log4j-style (if detected via Nuclei)
    "RCE:log4j": "CVE-2021-44228",        # Log4Shell
    "RCE:log4shell": "CVE-2021-44228",
}


def get_reference_cve(vuln_type: str, finding: dict = None) -> Optional[str]:
    """
    Look up a reference CVE based on vulnerability type and finding context.

    Checks engine-specific CVEs first, then falls back to generic type CVEs.

    Args:
        vuln_type: The vulnerability type (e.g., "CSTI", "SQLI")
        finding: Optional finding dict with context (template_engine, etc.)

    Returns:
        CVE ID string or None if no reference CVE exists
    """
    vuln_upper = vuln_type.upper()

    # Try engine-specific lookup first (CSTI:velocity, SSTI:jinja2, etc.)
    if finding:
        engine = (
            finding.get("template_engine", "") or
            finding.get("engine", "") or
            finding.get("technology", "") or
            ""
        ).lower().strip()
        if engine:
            key = f"{vuln_upper}:{engine}"
            if key in REFERENCE_CVES:
                return REFERENCE_CVES[key]

        # Check payload/description for engine hints
        payload = str(finding.get("payload", "")).lower()
        desc = str(finding.get("description", "")).lower()
        context_text = payload + " " + desc

        engine_hints = {
            "velocity": ["#set(", "$class", "velocity"],
            "freemarker": ["freemarker", "<#assign", "?new()"],
            "jinja2": ["__class__", "__mro__", "lipsum", "jinja"],
            "twig": ["twig", "{{dump(", "{{app."],
            "angular": ["constructor.constructor", "ng-app", "angular"],
            "pebble": ["pebble", '{"dumpAll"'],
            "log4j": ["${jndi:", "log4j", "log4shell"],
        }
        for eng, keywords in engine_hints.items():
            if any(kw in context_text for kw in keywords):
                key = f"{vuln_upper}:{eng}"
                if key in REFERENCE_CVES:
                    return REFERENCE_CVES[key]

    # Generic type lookup
    return REFERENCE_CVES.get(vuln_upper)


def get_cwe_for_vuln(vuln_type: str) -> Optional[str]:
    """
    Get the CWE ID for a given vulnerability type.

    Handles both 'Broken Access Control' (spaces) and 'BROKEN_ACCESS_CONTROL' (underscores).

    Args:
        vuln_type: The vulnerability type (e.g., "XSS", "SQLI", "Broken Access Control")

    Returns:
        CWE ID in format "CWE-XXX" or None if not found
    """
    return CWE_MAPPINGS.get(_normalize_vuln_type_key(vuln_type))


def get_remediation_for_vuln(vuln_type: str) -> str:
    """
    Get the remediation guidance for a given vulnerability type.

    Handles both 'Broken Access Control' (spaces) and 'BROKEN_ACCESS_CONTROL' (underscores).

    Args:
        vuln_type: The vulnerability type (e.g., "XSS", "SQLI", "Insecure Cookie Configuration")

    Returns:
        Remediation text, or generic guidance if type not found
    """
    remediation = REMEDIATION_TEMPLATES.get(_normalize_vuln_type_key(vuln_type))
    if remediation:
        return remediation.strip()
    return "Implement secure coding practices and follow OWASP guidelines for this vulnerability type."


def get_default_severity(vuln_type: str) -> Severity:
    """
    Get the default severity level for a given vulnerability type.

    Handles both 'Broken Access Control' (spaces) and 'BROKEN_ACCESS_CONTROL' (underscores).

    Args:
        vuln_type: The vulnerability type (e.g., "XSS", "SQLI", "Insecure Cookie Configuration")

    Returns:
        Severity enum value, defaults to HIGH if type not found
    """
    return DEFAULT_SEVERITY.get(_normalize_vuln_type_key(vuln_type), Severity.HIGH)


def format_cve(cve_id: str) -> str:
    """
    Format and validate a CVE identifier.

    Args:
        cve_id: CVE identifier (with or without "CVE-" prefix)

    Returns:
        Properly formatted CVE identifier (e.g., "CVE-2021-12345")

    Raises:
        ValueError: If CVE format is invalid

    Example:
        >>> format_cve("2021-12345")
        "CVE-2021-12345"
        >>> format_cve("CVE-2021-12345")
        "CVE-2021-12345"
    """
    cve_id = cve_id.strip().upper()

    # Remove CVE- prefix if present for validation
    if cve_id.startswith("CVE-"):
        cve_id = cve_id[4:]

    # Validate format: YYYY-NNNNN (year-number)
    parts = cve_id.split("-")
    if len(parts) != 2:
        raise ValueError(f"Invalid CVE format: {cve_id}. Expected format: CVE-YYYY-NNNNN")

    year, number = parts
    if not (year.isdigit() and len(year) == 4):
        raise ValueError(f"Invalid CVE year: {year}. Expected 4-digit year")
    if not number.isdigit():
        raise ValueError(f"Invalid CVE number: {number}. Expected numeric value")

    return f"CVE-{year}-{number}"


def normalize_severity(severity: str) -> Severity:
    """
    Convert a severity string to standardized Severity enum.
    Handles various casing and formats for backward compatibility.

    Args:
        severity: Severity string (any case)

    Returns:
        Severity enum value

    Raises:
        ValueError: If severity string is not recognized

    Example:
        >>> normalize_severity("critical")
        Severity.CRITICAL
        >>> normalize_severity("High")
        Severity.HIGH
    """
    severity_upper = (severity or "HIGH").upper().strip()

    # Handle common variations
    severity_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
        "INFORMATION": Severity.INFO,  # Allow "Information" as alias
    }

    if severity_upper not in severity_map:
        raise ValueError(f"Unknown severity level: {severity}. Valid values: CRITICAL, HIGH, MEDIUM, LOW, INFO")

    return severity_map[severity_upper]
