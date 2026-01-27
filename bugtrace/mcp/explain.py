"""MCP Tools for vulnerability explanation and remediation.

This module provides two MCP tools that return pre-written security knowledge:
- explain_vulnerability: Business-friendly vulnerability explanations
- suggest_remediation: Context-aware fix recommendations with code examples

These tools DO NOT call external LLMs. They return structured templates based on
vulnerability type and severity. The AI assistant consuming these tools interprets
and presents the information to users.

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

from typing import Dict, Any, List

from bugtrace.mcp.server import mcp_server


# Vulnerability knowledge base for explanations
VULN_KNOWLEDGE = {
    "XSS": {
        "business_impact": "Attackers can inject malicious scripts that execute in users' browsers, potentially stealing credentials, session tokens, or performing actions on behalf of users.",
        "technical_explanation": "Cross-Site Scripting occurs when user input is reflected in web pages without proper sanitization or encoding. The browser executes the injected JavaScript code with the same privileges as the application.",
        "affected_area": "User data and session security"
    },
    "SQLI": {
        "business_impact": "Attackers can read, modify, or delete database contents, bypass authentication, and potentially gain complete control over the application's data layer.",
        "technical_explanation": "SQL Injection allows attackers to manipulate database queries by injecting SQL syntax through user input fields. Without parameterized queries, malicious SQL code is executed directly against the database.",
        "affected_area": "Database integrity and confidentiality"
    },
    "RCE": {
        "business_impact": "Attackers can execute arbitrary commands on the server, leading to complete system compromise, data theft, ransomware installation, or use of the server for further attacks.",
        "technical_explanation": "Remote Code Execution vulnerabilities allow attackers to run system commands or code on the server. This typically occurs through unsafe deserialization, command injection, or improper input validation in code execution contexts.",
        "affected_area": "Server infrastructure and all hosted data"
    },
    "XXE": {
        "business_impact": "Attackers can read local files, perform internal network scans, cause denial of service, or extract sensitive data through XML entity expansion.",
        "technical_explanation": "XML External Entity attacks exploit XML parsers that process external entity references. Attackers can define entities that reference local files or internal network resources.",
        "affected_area": "File system access and internal network"
    },
    "CSTI": {
        "business_impact": "Attackers can execute arbitrary JavaScript code in the context of the application, similar to XSS but through template injection points.",
        "technical_explanation": "Client-Side Template Injection occurs when user input is embedded into client-side templates (Angular, Vue, React) without proper sanitization. Template expressions are evaluated and executed.",
        "affected_area": "Client-side application logic"
    },
    "PROTOTYPE_POLLUTION": {
        "business_impact": "Attackers can modify JavaScript object prototypes, potentially bypassing security controls, causing denial of service, or enabling other attack vectors like XSS.",
        "technical_explanation": "Prototype Pollution exploits JavaScript's prototype inheritance by injecting properties into Object.prototype or other built-in prototypes, affecting all objects in the application.",
        "affected_area": "Application-wide JavaScript objects"
    },
    "OPEN_REDIRECT": {
        "business_impact": "Attackers can redirect users to malicious sites for phishing attacks, malware distribution, or credential harvesting while appearing to come from a trusted domain.",
        "technical_explanation": "Open Redirect vulnerabilities occur when applications redirect users to URLs specified in unvalidated user input. Attackers craft links that redirect to malicious sites.",
        "affected_area": "User trust and authentication flows"
    },
    "HEADER_INJECTION": {
        "business_impact": "Attackers can inject HTTP headers to perform response splitting, cache poisoning, session fixation, or XSS attacks through header manipulation.",
        "technical_explanation": "Header Injection occurs when user input is included in HTTP response headers without proper validation. Attackers can inject newline characters to add arbitrary headers or split responses.",
        "affected_area": "HTTP response integrity"
    },
    "SENSITIVE_DATA_EXPOSURE": {
        "business_impact": "Unauthorized disclosure of sensitive information like API keys, passwords, PII, or financial data, leading to regulatory violations, identity theft, or system compromise.",
        "technical_explanation": "Sensitive Data Exposure occurs when applications fail to protect confidential information through encryption, access controls, or proper error handling. Data may be exposed through URLs, logs, error messages, or unencrypted transmission.",
        "affected_area": "Confidential business and user data"
    },
    "IDOR": {
        "business_impact": "Attackers can access or modify other users' data by manipulating object identifiers, leading to privacy violations, data breaches, and unauthorized operations.",
        "technical_explanation": "Insecure Direct Object Reference vulnerabilities occur when applications use user-supplied input to access objects without proper authorization checks. Attackers can enumerate and access resources they shouldn't.",
        "affected_area": "User data access controls"
    },
    "LFI": {
        "business_impact": "Attackers can read sensitive local files including configuration files, source code, and system files, potentially exposing credentials, API keys, or enabling further attacks.",
        "technical_explanation": "Local File Inclusion exploits insufficient validation of file paths in include/require statements. Attackers use path traversal sequences (../) to access files outside the intended directory.",
        "affected_area": "File system and source code confidentiality"
    },
    "SSRF": {
        "business_impact": "Attackers can make the server perform requests to internal resources, scan internal networks, bypass firewalls, or access cloud metadata services to steal credentials.",
        "technical_explanation": "Server-Side Request Forgery allows attackers to make HTTP requests from the server to arbitrary URLs. This bypasses network restrictions and can access internal services not exposed to the internet.",
        "affected_area": "Internal network and cloud infrastructure"
    },
    "SECURITY_MISCONFIGURATION": {
        "business_impact": "Security weaknesses from improper configuration can expose the application to various attacks, including unauthorized access, information disclosure, or system compromise.",
        "technical_explanation": "Security Misconfiguration includes default credentials, verbose error messages, unnecessary services, missing security headers, or outdated software. Each misconfiguration presents specific attack surfaces.",
        "affected_area": "Application and infrastructure security posture"
    }
}


# Remediation knowledge base
REMEDIATION_KNOWLEDGE = {
    "XSS": {
        "remediation_steps": [
            "Implement output encoding for all user-controlled data displayed in HTML contexts",
            "Use Content Security Policy (CSP) headers to restrict script execution sources",
            "Validate and sanitize all user input on the server side",
            "Use framework-specific auto-escaping features (e.g., React JSX, Vue templates)",
            "Consider using HTTPOnly and Secure flags on cookies to limit XSS impact"
        ],
        "code_example": """// Bad: Direct HTML insertion
element.innerHTML = userInput;

// Good: Use textContent or proper encoding
element.textContent = userInput;

// Or use framework escaping
<div>{userInput}</div>  // React auto-escapes

// Add CSP header
Content-Security-Policy: default-src 'self'; script-src 'self'""",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "CWE-79: Improper Neutralization of Input During Web Page Generation"
        ]
    },
    "SQLI": {
        "remediation_steps": [
            "Use parameterized queries or prepared statements for all database operations",
            "Never concatenate user input directly into SQL queries",
            "Apply principle of least privilege to database accounts",
            "Implement input validation with strict allow-lists",
            "Use ORM frameworks that handle parameterization automatically"
        ],
        "code_example": """-- Bad: String concatenation
query = "SELECT * FROM users WHERE id = " + userId;

-- Good: Parameterized query
query = "SELECT * FROM users WHERE id = ?";
stmt = connection.prepareStatement(query);
stmt.setInt(1, userId);

# Python example with SQLAlchemy
session.query(User).filter(User.id == user_id)""",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
        ]
    },
    "RCE": {
        "remediation_steps": [
            "Never execute system commands with user-supplied input",
            "Use safe alternatives to eval(), exec(), or system() functions",
            "Implement strict input validation with allow-lists for any required command execution",
            "Run application processes with minimal privileges (sandboxing)",
            "Disable or restrict dangerous functions in language configuration (e.g., PHP disable_functions)"
        ],
        "code_example": """# Bad: Direct command execution
os.system("ping " + user_input)

# Good: Use safe libraries with validation
import ipaddress
try:
    ip = ipaddress.ip_address(user_input)
    # Use safe ping library instead of shell command
    result = ping_safely(str(ip))
except ValueError:
    return "Invalid IP address"

# Or use subprocess with shell=False
subprocess.run(['ping', '-c', '1', validated_ip], shell=False)""",
        "references": [
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cwe.mitre.org/data/definitions/78.html",
            "CWE-94: Improper Control of Generation of Code"
        ]
    },
    "XXE": {
        "remediation_steps": [
            "Disable external entity processing in all XML parsers",
            "Use less complex data formats like JSON when possible",
            "Keep XML processing libraries updated to latest secure versions",
            "Implement input validation to reject DOCTYPE declarations",
            "Use local static DTDs instead of allowing external DTD references"
        ],
        "code_example": """# Bad: Default parser with XXE vulnerability
parser = etree.XMLParser()
doc = etree.parse(xml_input, parser)

# Good: Disable external entities
parser = etree.XMLParser(resolve_entities=False, no_network=True)
doc = etree.parse(xml_input, parser)

// Java example
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);""",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            "CWE-611: Improper Restriction of XML External Entity Reference"
        ]
    },
    "CSTI": {
        "remediation_steps": [
            "Never interpolate user input directly into template expressions",
            "Use framework sandboxing features for template rendering",
            "Sanitize user input before passing to template engines",
            "Avoid server-side rendering of user-controlled templates",
            "Use static templates with data binding instead of dynamic template generation"
        ],
        "code_example": """// Bad: Direct template interpolation
template = '{{' + userInput + '}}';
compiled = templateEngine.compile(template);

// Good: Use data binding with static templates
template = '{{username}}';  // Static template
compiled = templateEngine.compile(template);
result = compiled({username: sanitized(userInput)});

// Angular: Use property binding
<div [innerHTML]="sanitizedContent"></div>""",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
            "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine"
        ]
    },
    "PROTOTYPE_POLLUTION": {
        "remediation_steps": [
            "Avoid using unsafe merge functions that allow __proto__ or constructor.prototype",
            "Use Object.create(null) for maps instead of {} to create prototype-less objects",
            "Validate object keys before merge operations",
            "Freeze prototypes using Object.freeze() for critical objects",
            "Use Map/Set instead of plain objects for user-controlled data"
        ],
        "code_example": """// Bad: Unsafe merge
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key];  // Allows __proto__
    }
}

// Good: Safe merge with validation
function safeMerge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;  // Skip dangerous keys
        }
        target[key] = source[key];
    }
}

// Better: Use Map instead
const userMap = new Map();
userMap.set(userKey, userValue);""",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/Prototype_Pollution",
            "https://portswigger.net/web-security/prototype-pollution",
            "CWE-1321: Improperly Controlled Modification of Object Prototype Attributes"
        ]
    },
    "OPEN_REDIRECT": {
        "remediation_steps": [
            "Validate redirect URLs against an allow-list of trusted domains",
            "Use relative URLs for redirects when possible",
            "Reject URLs with different protocols or domains",
            "Display a warning page before external redirects",
            "Never use user input directly in redirect functions"
        ],
        "code_example": """# Bad: Direct redirect
redirect_url = request.GET.get('next')
return redirect(redirect_url)

# Good: Validate against allow-list
ALLOWED_DOMAINS = ['example.com', 'app.example.com']

def safe_redirect(url):
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc not in ALLOWED_DOMAINS:
        return redirect('/default-page')
    return redirect(url)

# Better: Use relative URLs only
if url.startswith('/'):
    return redirect(url)
else:
    return redirect('/default-page')""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            "CWE-601: URL Redirection to Untrusted Site"
        ]
    },
    "HEADER_INJECTION": {
        "remediation_steps": [
            "Validate and sanitize all user input before including in HTTP headers",
            "Reject inputs containing newline characters (\\r\\n)",
            "Use framework functions that automatically escape header values",
            "Implement strict allow-lists for header values when possible",
            "Never directly concatenate user input into header strings"
        ],
        "code_example": """# Bad: Direct header injection
response.headers['X-Custom-Header'] = user_input

# Good: Validate and sanitize
def safe_header_value(value):
    # Remove newlines and carriage returns
    cleaned = value.replace('\\r', '').replace('\\n', '')
    # Validate against expected format
    if not re.match(r'^[a-zA-Z0-9-_]+$', cleaned):
        raise ValueError("Invalid header value")
    return cleaned

response.headers['X-Custom-Header'] = safe_header_value(user_input)""",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
            "CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers"
        ]
    },
    "SENSITIVE_DATA_EXPOSURE": {
        "remediation_steps": [
            "Encrypt sensitive data at rest and in transit (TLS/SSL)",
            "Remove sensitive data from URLs, logs, and error messages",
            "Implement proper access controls and authentication",
            "Use environment variables or secure vaults for credentials",
            "Mask or redact sensitive data in user interfaces and APIs"
        ],
        "code_example": """# Bad: Exposing sensitive data
logger.info(f"User logged in: {username} with password {password}")
api_key = "sk-1234567890abcdef"  # Hardcoded

# Good: Secure handling
logger.info(f"User logged in: {username}")
api_key = os.environ.get('API_KEY')  # From environment

# Mask sensitive data
def mask_sensitive(data):
    if len(data) > 8:
        return data[:4] + '****' + data[-4:]
    return '****'

response = {'api_key': mask_sensitive(api_key)}""",
        "references": [
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
            "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
        ]
    },
    "IDOR": {
        "remediation_steps": [
            "Implement authorization checks for every object access",
            "Use indirect references (random UUIDs) instead of sequential IDs",
            "Validate that the current user owns or has access to the requested resource",
            "Implement access control lists (ACLs) or role-based access control (RBAC)",
            "Never rely on client-side checks alone"
        ],
        "code_example": """# Bad: Direct object access without authorization
def get_user_document(doc_id):
    return Document.objects.get(id=doc_id)

# Good: Check ownership before access
def get_user_document(doc_id, current_user):
    doc = Document.objects.get(id=doc_id)
    if doc.owner_id != current_user.id:
        raise PermissionDenied("Access denied")
    return doc

# Better: Use framework authorization
@require_object_permission('document.view')
def get_user_document(doc_id, current_user):
    return Document.objects.get(id=doc_id)""",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            "CWE-639: Authorization Bypass Through User-Controlled Key"
        ]
    },
    "LFI": {
        "remediation_steps": [
            "Never use user input directly in file path operations",
            "Use allow-lists for permitted files or directories",
            "Validate file paths to prevent directory traversal (../ sequences)",
            "Use absolute paths and validate against a whitelist",
            "Implement chroot jails or containerization to limit file system access"
        ],
        "code_example": """# Bad: Direct file inclusion
file_path = request.GET.get('file')
content = open(file_path).read()

# Good: Validate against whitelist
ALLOWED_FILES = {
    'report': '/app/reports/report.txt',
    'summary': '/app/reports/summary.txt'
}

file_key = request.GET.get('file')
if file_key not in ALLOWED_FILES:
    raise ValueError("Invalid file")

file_path = ALLOWED_FILES[file_key]
content = open(file_path).read()

# Or validate path is within allowed directory
base_dir = '/app/data/'
requested_file = os.path.join(base_dir, user_input)
real_path = os.path.realpath(requested_file)
if not real_path.startswith(base_dir):
    raise ValueError("Path traversal detected")""",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
            "CWE-22: Improper Limitation of a Pathname to a Restricted Directory"
        ]
    },
    "SSRF": {
        "remediation_steps": [
            "Validate and sanitize all URLs from user input",
            "Use allow-lists for permitted domains and protocols",
            "Disable redirects or validate redirect destinations",
            "Block requests to private IP ranges and localhost",
            "Use network segmentation to limit internal resource access"
        ],
        "code_example": """# Bad: Direct URL request
url = request.POST.get('url')
response = requests.get(url)

# Good: Validate URL against whitelist
import ipaddress
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.example.com', 'public-api.org']
BLOCKED_IPS = ['127.0.0.1', '0.0.0.0', '169.254.169.254']  # localhost, metadata

def is_safe_url(url):
    parsed = urlparse(url)

    # Check protocol
    if parsed.scheme not in ['http', 'https']:
        return False

    # Check domain whitelist
    if parsed.netloc not in ALLOWED_DOMAINS:
        return False

    # Resolve and check IP
    try:
        ip = socket.gethostbyname(parsed.hostname)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            return False
    except:
        return False

    return True

if is_safe_url(url):
    response = requests.get(url, allow_redirects=False)""",
        "references": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "CWE-918: Server-Side Request Forgery (SSRF)"
        ]
    },
    "SECURITY_MISCONFIGURATION": {
        "remediation_steps": [
            "Disable default accounts and change default credentials",
            "Remove or disable unnecessary features, services, and ports",
            "Keep all software and dependencies updated to latest secure versions",
            "Implement security headers (CSP, HSTS, X-Frame-Options, etc.)",
            "Configure proper error handling to avoid information disclosure"
        ],
        "code_example": """# Bad: Verbose error messages in production
app.debug = True
app.config['PROPAGATE_EXCEPTIONS'] = True

# Good: Secure configuration
app.debug = False
app.config['PROPAGATE_EXCEPTIONS'] = False

# Add security headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# Generic error handler
@app.errorhandler(Exception)
def handle_error(error):
    logger.error(f"Error: {error}")  # Log details
    return {"error": "Internal server error"}, 500  # Generic message""",
        "references": [
            "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
            "https://cheatsheetseries.owasp.org/cheatsheets/Security_Headers_Cheat_Sheet.html",
            "CWE-16: Configuration"
        ]
    }
}


def get_risk_rating(severity: str) -> int:
    """Convert severity to numeric risk rating."""
    severity_upper = severity.upper()
    ratings = {
        "CRITICAL": 10,
        "HIGH": 8,
        "MEDIUM": 5,
        "LOW": 2,
        "INFO": 1,
        "INFORMATIONAL": 1
    }
    return ratings.get(severity_upper, 5)


def get_priority(severity: str) -> str:
    """Convert severity to remediation priority."""
    severity_upper = severity.upper()
    priorities = {
        "CRITICAL": "Immediate",
        "HIGH": "High",
        "MEDIUM": "Planned",
        "LOW": "Low",
        "INFO": "Optional",
        "INFORMATIONAL": "Optional"
    }
    return priorities.get(severity_upper, "Planned")


@mcp_server.tool()
async def explain_vulnerability(
    vuln_type: str,
    severity: str = "HIGH",
    details: str = ""
) -> Dict[str, Any]:
    """
    Explain a vulnerability finding in business terms.

    Returns structured explanation with business impact, technical details, and risk rating.
    Use this to help non-technical stakeholders understand security findings.

    Args:
        vuln_type: Type of vulnerability (XSS, SQLI, RCE, etc.)
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        details: Optional additional context about the finding

    Returns:
        Dictionary with vulnerability explanation, impact, and risk assessment
    """
    # Normalize vuln_type
    vuln_upper = vuln_type.upper().replace("-", "_")

    # Get knowledge from database or use generic
    knowledge = VULN_KNOWLEDGE.get(vuln_upper, {
        "business_impact": f"This {vuln_type} vulnerability represents a security risk that could be exploited by attackers to compromise the application or its data.",
        "technical_explanation": f"A {vuln_type} vulnerability has been identified. Review the specific details to understand the attack vector and potential impact.",
        "affected_area": "Application security"
    })

    return {
        "vuln_type": vuln_type,
        "severity": severity,
        "business_impact": knowledge["business_impact"],
        "technical_explanation": knowledge["technical_explanation"],
        "risk_rating": get_risk_rating(severity),
        "affected_area": knowledge["affected_area"],
        "additional_context": details if details else None
    }


@mcp_server.tool()
async def suggest_remediation(
    vuln_type: str,
    severity: str = "HIGH",
    url: str = "",
    parameter: str = ""
) -> Dict[str, Any]:
    """
    Suggest remediation steps for a vulnerability finding.

    Returns prioritized fix steps, code examples, and reference links.
    Provide url and parameter for context-aware recommendations.

    Args:
        vuln_type: Type of vulnerability (XSS, SQLI, RCE, etc.)
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        url: Optional URL where vulnerability was found
        parameter: Optional parameter name that is vulnerable

    Returns:
        Dictionary with remediation steps, code examples, and references
    """
    # Normalize vuln_type
    vuln_upper = vuln_type.upper().replace("-", "_")

    # Get remediation knowledge or use generic
    remediation = REMEDIATION_KNOWLEDGE.get(vuln_upper, {
        "remediation_steps": [
            "Review the vulnerability details and understand the attack vector",
            "Implement input validation and output encoding",
            "Apply security best practices for the affected component",
            "Test the fix thoroughly before deploying to production",
            "Consider a security code review for similar issues"
        ],
        "code_example": "# Consult security documentation for specific remediation guidance",
        "references": [
            "https://owasp.org/www-project-top-ten/",
            "https://cheatsheetseries.owasp.org/"
        ]
    })

    # Build context string
    context_parts = []
    if url:
        context_parts.append(f"URL: {url}")
    if parameter:
        context_parts.append(f"Parameter: {parameter}")
    context = " | ".join(context_parts) if context_parts else "No specific context provided"

    return {
        "vuln_type": vuln_type,
        "severity": severity,
        "priority": get_priority(severity),
        "remediation_steps": remediation["remediation_steps"],
        "code_example": remediation["code_example"],
        "references": remediation["references"],
        "context": context
    }
