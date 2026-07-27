"""
Data types, constants, and enums for the reporting module.
"""

from typing import Dict, Set


# -- Patterns that indicate static analysis, not real exploits --
STATIC_ANALYSIS_PATTERNS = (
    "source-to-sink pattern detected",
    "detected via code analysis",
    "pattern detected via",
)

# -- XSS validation levels that lack browser-confirmed execution --
XSS_UNCONFIRMED_LEVELS: Set[str] = {"L0.5", "L1"}

# -- Vuln types that are informational in bug bounty -- skip LLM CVSS scoring
INFORMATIONAL_TYPES: Set[str] = {"MISSING_SECURITY_HEADER", "API DOCUMENTATION EXPOSURE"}

# -- Nuclei template patterns for grouping into consolidated findings --
HEADER_TEMPLATES: Set[str] = {
    "security-headers-hsts", "security-headers-xcto", "security-headers-xfo",
    "security-headers-csp", "security-headers-xxp", "security-headers-rp",
    "security-headers-pp", "http-missing-security-headers", "missing-sri",
}

API_DOCS_TEMPLATES: Set[str] = {"swagger-api", "redoc-api-docs", "openapi"}

# -- Severity weights for sorting --
SEVERITY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 10.0, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0,
}

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
}

# -- Known product display names for tech profile parsing --
DISPLAY_NAMES: Dict[str, str] = {
    "php": "PHP", "asp": "ASP.NET", "iis": "IIS", "aws": "AWS",
    "gcp": "GCP", "cdn": "CDN", "jquery": "jQuery", "angularjs": "AngularJS",
    "vuejs": "Vue.js", "nodejs": "Node.js", "reactjs": "React",
}

# -- Misconfig template prefixes (not technologies) --
MISCONFIG_PREFIXES = (
    "http-missing-", "missing-", "cookies-without-",
    "cookies-", "security-headers-", "cors-", "cluster-",
)

# -- Category mapping for tech profile --
CATEGORY_MAP: Dict[str, str] = {
    "frameworks": "Framework",
    "servers": "Web Server",
    "cms": "CMS",
    "cdn": "CDN",
    "languages": "Language / Runtime",
}

# -- Header readable name map for consolidated findings --
HEADER_READABLE_MAP: Dict[str, str] = {
    "HSTS": "Strict-Transport-Security (HSTS)",
    "XCTO": "X-Content-Type-Options",
    "XFO": "X-Frame-Options",
    "CSP": "Content-Security-Policy",
    "XXP": "X-XSS-Protection",
    "RP": "Referrer-Policy",
    "PP": "Permissions-Policy",
    "MISSING-SRI": "Subresource Integrity (SRI)",
    "MULTIPLE HEADERS": "HTTP Security Headers Bundle",
}

# -- Severity badges for markdown rendering --
SEVERITY_BADGES: Dict[str, str] = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🔵 LOW",
    "INFO": "⚪ INFO",
}

# -- Impact descriptions by vulnerability type --
IMPACT_DESCRIPTIONS: Dict[str, str] = {
    "XSS": "Cross-Site Scripting can lead to session hijacking, credential theft, defacement, and malware distribution.",
    "SQLI": "SQL Injection can lead to unauthorized data access, data manipulation, and complete database compromise.",
    "LFI": "Local File Inclusion can expose sensitive files and potentially lead to remote code execution.",
    "RCE": "Remote Code Execution allows attackers to run arbitrary commands on the server.",
    "SSRF": "Server-Side Request Forgery can expose internal services and sensitive data.",
    "IDOR": "Insecure Direct Object Reference can lead to unauthorized access to other users' data.",
    "CSTI": "Client-Side Template Injection can lead to XSS, data theft, and in some cases remote code execution.",
    "SSTI": "Server-Side Template Injection can lead to remote code execution and full server compromise.",
    "JWT": "JWT vulnerabilities can lead to authentication bypass and unauthorized access to protected resources.",
    "XXE": "XML External Entity injection can expose sensitive files, perform SSRF, and cause denial of service.",
    "OPEN_REDIRECT": "Open Redirect can be used for phishing attacks and credential theft via trusted domain abuse.",
    "PROTOTYPE_POLLUTION": "Prototype Pollution can lead to XSS, denial of service, and privilege escalation in JavaScript applications.",
    "HEADER_INJECTION": "HTTP Header Injection can lead to cache poisoning, session fixation, and XSS via response splitting.",
    "FILE_UPLOAD": "Unrestricted file upload can lead to remote code execution and server compromise.",
    "MASS_ASSIGNMENT": "Mass Assignment can allow privilege escalation by modifying restricted fields like roles or permissions.",
    "API_SECURITY": "API security issues can expose sensitive data, enable unauthorized operations, and lead to data breaches.",
    "BROKEN_ACCESS_CONTROL": "Broken Access Control allows unauthorized users to access administrative or restricted functionality.",
    "BROKEN ACCESS CONTROL": "Broken Access Control allows unauthorized users to access administrative or restricted functionality.",
    "INSECURE_COOKIE_CONFIGURATION": "Insecure cookie configuration can expose session tokens to theft via network sniffing or XSS attacks.",
    "INSECURE COOKIE CONFIGURATION": "Insecure cookie configuration can expose session tokens to theft via network sniffing or XSS attacks.",
    "GRAPHQL_INTROSPECTION": "GraphQL introspection exposure allows attackers to map the entire API schema and discover hidden queries and mutations.",
    "GRAPHQL INTROSPECTION": "GraphQL introspection exposure allows attackers to map the entire API schema and discover hidden queries and mutations.",
    "API_DOCUMENTATION_EXPOSURE": "Exposed API documentation reveals endpoint structure, parameters, and data models to potential attackers.",
    "API DOCUMENTATION EXPOSURE": "Exposed API documentation reveals endpoint structure, parameters, and data models to potential attackers.",
    "MISSING_SECURITY_HEADER": "Missing security headers reduce defense-in-depth, making other vulnerabilities easier to exploit.",
    "INSECURE_DESERIALIZATION": "Insecure deserialization can lead to remote code execution, authentication bypass, and data tampering.",
    "INSECURE DESERIALIZATION": "Insecure deserialization can lead to remote code execution, authentication bypass, and data tampering.",
}

# -- Type-specific LLM contexts for PoC enrichment --
TYPE_SPECIFIC_CONTEXTS: Dict[str, str] = {
    "SQLI": """**SQLi-Specific Context:**
- This is a SQL Injection vulnerability
- Consider: Data exfiltration, authentication bypass, privilege escalation
- Think about what tables might exist (users, orders, payments, admin)
- Mention specific SQLMap flags or techniques if relevant""",

    "XSS": """**XSS-Specific Context:**
- This is a Cross-Site Scripting vulnerability
- Consider: Session hijacking, credential theft, keylogging, defacement
- Think about the impact if this executes in an admin's browser
- Mention if it's reflected, stored, or DOM-based""",

    "XXE": """**XXE-Specific Context:**
- This is an XML External Entity vulnerability
- Consider: File disclosure (/etc/passwd, application configs), SSRF, DoS
- Think about what sensitive files might be accessible
- Mention the ability to exfiltrate data via out-of-band channels""",

    "SSRF": """**SSRF-Specific Context:**
- This is a Server-Side Request Forgery vulnerability
- Consider: Internal network access, cloud metadata (169.254.169.254), port scanning
- Think about internal services (databases, admin panels, APIs)
- Mention AWS/GCP/Azure metadata endpoints if cloud-hosted""",

    "CSTI": """**CSTI-Specific Context:**
- This is a Client-Side Template Injection vulnerability
- Consider: XSS via template expressions, data exfiltration
- Think about the frontend framework (Angular, Vue, React)
- Mention the ability to execute arbitrary JavaScript""",

    "IDOR": """**IDOR-Specific Context:**
- This is an Insecure Direct Object Reference vulnerability
- Consider: Access to other users' data, horizontal privilege escalation
- Think about what resources can be accessed (profiles, orders, files)
- Mention the predictability of object IDs""",
}
