# Low Level Design: TechContextMixin for Remaining Specialist Agents

## 1. Overview

### Current State
TechContextMixin implemented in:
- ✅ SQLiAgent (DB-specific payloads)
- ✅ XSSAgent (Frontend framework detection)
- ✅ CSTIAgent (Template engine detection)

### Remaining Agents
| Agent | Priority | Key Context Needed |
|-------|----------|-------------------|
| `header_injection_agent.py` | HIGH | Server type, proxy detection |
| `ssrf_agent.py` | HIGH | Cloud provider, internal network hints |
| `lfi_agent.py` | HIGH | OS type, web server, language |
| `rce_agent.py` | HIGH | OS type, language, shell type |
| `xxe_agent.py` | MEDIUM | XML parser type, language |
| `idor_agent.py` | MEDIUM | API patterns, auth mechanism |
| `jwt_agent.py` | MEDIUM | JWT library hints, algorithm support |
| `openredirect_agent.py` | LOW | Framework URL handling |
| `prototype_pollution_agent.py` | LOW | Node.js framework detection |

---

## 2. New Mixin Methods Required

### 2.1 Add to `bugtrace/agents/mixins/tech_context.py`

```python
# =========================================================================
# HEADER INJECTION-SPECIFIC CONTEXT
# =========================================================================

def generate_header_injection_context_prompt(self, stack: Dict) -> str:
    """Generate Header Injection-specific context."""
    server = stack.get("server", "Unknown")
    lang = stack.get("lang", "Unknown")
    waf = stack.get("waf")
    cdn = stack.get("cdn")

    prompt_parts = [
        "## TARGET TECHNOLOGY STACK (HEADER INJECTION CONTEXT)",
        f"- Web Server: {server}",
        f"- Backend Language: {lang}",
    ]

    if cdn:
        prompt_parts.append(f"- CDN: {cdn}")
    if waf:
        prompt_parts.append(f"- WAF: {waf}")

    prompt_parts.append("")
    prompt_parts.append("## HEADER INJECTION STRATEGIC IMPLICATIONS")

    # Server-specific
    if server.lower() in ["nginx", "apache"]:
        prompt_parts.extend([
            f"- {server}: Check for CRLF injection in Location header",
            f"- {server}: Test X-Forwarded-* header injection",
        ])

    # CDN-specific
    if cdn:
        prompt_parts.extend([
            f"- CDN ({cdn}): Cache poisoning via Host header",
            f"- CDN: X-Forwarded-Host manipulation for cache key",
        ])

    return "\n".join(prompt_parts)

def generate_header_injection_dedup_context(self, stack: Dict) -> str:
    """Dedup rules for header injection."""
    return """## HEADER INJECTION DEDUPLICATION RULES
- Same header type + same endpoint = DUPLICATE
- Different header types (Host vs X-Forwarded-For) = DIFFERENT
- Same header + different endpoints = DIFFERENT
- Response header injection vs Request header = DIFFERENT classes"""

# =========================================================================
# SSRF-SPECIFIC CONTEXT
# =========================================================================

def generate_ssrf_context_prompt(self, stack: Dict) -> str:
    """Generate SSRF-specific context."""
    infrastructure = stack.get("raw_profile", {}).get("infrastructure", [])
    lang = stack.get("lang", "Unknown")

    prompt_parts = [
        "## TARGET TECHNOLOGY STACK (SSRF CONTEXT)",
        f"- Backend Language: {lang}",
    ]

    # Cloud detection
    cloud_providers = self._detect_cloud_provider(infrastructure)
    if cloud_providers:
        prompt_parts.append(f"- Cloud Provider: {', '.join(cloud_providers)}")
        prompt_parts.append("")
        prompt_parts.append("## SSRF STRATEGIC IMPLICATIONS")

        if "aws" in cloud_providers:
            prompt_parts.extend([
                "- AWS detected: Target http://169.254.169.254/latest/meta-data/",
                "- AWS: IMDSv2 bypass via X-Forwarded-For",
                "- AWS: Check for IAM role credentials at /iam/security-credentials/",
            ])
        if "gcp" in cloud_providers:
            prompt_parts.extend([
                "- GCP detected: Target http://metadata.google.internal/",
                "- GCP: Use Metadata-Flavor: Google header",
            ])
        if "azure" in cloud_providers:
            prompt_parts.extend([
                "- Azure detected: Target http://169.254.169.254/metadata/",
                "- Azure: Metadata header required",
            ])

    return "\n".join(prompt_parts)

def _detect_cloud_provider(self, infrastructure: List[str]) -> List[str]:
    """Detect cloud providers from infrastructure tags."""
    detected = []
    infra_str = " ".join(infrastructure).lower()

    if any(x in infra_str for x in ["aws", "amazon", "ec2", "s3", "alb"]):
        detected.append("aws")
    if any(x in infra_str for x in ["gcp", "google", "gke", "cloud run"]):
        detected.append("gcp")
    if any(x in infra_str for x in ["azure", "microsoft", "aks"]):
        detected.append("azure")

    return detected

def generate_ssrf_dedup_context(self, stack: Dict) -> str:
    """Dedup rules for SSRF."""
    return """## SSRF DEDUPLICATION RULES
- Same parameter + same internal target = DUPLICATE
- Same parameter + different internal targets = DIFFERENT
- Different parameters = DIFFERENT
- Blind SSRF vs Reflected SSRF = DIFFERENT classes"""

# =========================================================================
# LFI-SPECIFIC CONTEXT
# =========================================================================

def generate_lfi_context_prompt(self, stack: Dict) -> str:
    """Generate LFI-specific context."""
    server = stack.get("server", "Unknown")
    lang = stack.get("lang", "Unknown")

    prompt_parts = [
        "## TARGET TECHNOLOGY STACK (LFI CONTEXT)",
        f"- Web Server: {server}",
        f"- Backend Language: {lang}",
    ]

    # OS detection from server
    os_type = self._infer_os_from_stack(stack)
    prompt_parts.append(f"- Likely OS: {os_type}")

    prompt_parts.append("")
    prompt_parts.append("## LFI STRATEGIC IMPLICATIONS")

    if os_type == "Linux":
        prompt_parts.extend([
            "- Linux: Target /etc/passwd, /proc/self/environ",
            "- Linux: Log poisoning via /var/log/apache2/access.log",
            "- Linux: PHP wrappers: php://filter/convert.base64-encode/resource=",
        ])
    elif os_type == "Windows":
        prompt_parts.extend([
            "- Windows: Target C:\\Windows\\win.ini, C:\\inetpub\\logs\\",
            "- Windows: UNC path for SSRF combo: \\\\attacker\\share",
        ])

    # Language-specific
    if lang == "PHP":
        prompt_parts.extend([
            "- PHP: Use wrappers (php://, data://, expect://)",
            "- PHP: Check for allow_url_include",
        ])
    elif lang == "Java":
        prompt_parts.append("- Java: Check for XXE via file:// protocol")

    return "\n".join(prompt_parts)

def _infer_os_from_stack(self, stack: Dict) -> str:
    """Infer OS from tech stack."""
    server = stack.get("server", "").lower()
    lang = stack.get("lang", "").lower()

    if "iis" in server or "asp" in lang or ".net" in lang:
        return "Windows"
    return "Linux"

def generate_lfi_dedup_context(self, stack: Dict) -> str:
    """Dedup rules for LFI."""
    os_type = self._infer_os_from_stack(stack)
    return f"""## LFI DEDUPLICATION RULES (OS: {os_type})
- Same parameter + same file target = DUPLICATE
- Same parameter + different files = DIFFERENT (unless same traversal depth)
- Different parameters = DIFFERENT
- Direct LFI vs Wrapper-based = DIFFERENT techniques"""

# =========================================================================
# RCE-SPECIFIC CONTEXT
# =========================================================================

def generate_rce_context_prompt(self, stack: Dict) -> str:
    """Generate RCE-specific context."""
    lang = stack.get("lang", "Unknown")
    os_type = self._infer_os_from_stack(stack)

    prompt_parts = [
        "## TARGET TECHNOLOGY STACK (RCE CONTEXT)",
        f"- Backend Language: {lang}",
        f"- Likely OS: {os_type}",
    ]

    prompt_parts.append("")
    prompt_parts.append("## RCE STRATEGIC IMPLICATIONS")

    # OS-specific commands
    if os_type == "Linux":
        prompt_parts.extend([
            "- Linux: Use $(cmd), `cmd`, ; cmd, | cmd, && cmd",
            "- Linux: Blind RCE via sleep, ping, curl to callback",
            "- Linux: Shell: /bin/bash, /bin/sh",
        ])
    else:
        prompt_parts.extend([
            "- Windows: Use & cmd, | cmd, %COMSPEC% /c cmd",
            "- Windows: Blind RCE via ping -n, timeout",
            "- Windows: Shell: cmd.exe, powershell.exe",
        ])

    # Language-specific
    if lang == "PHP":
        prompt_parts.append("- PHP: system(), exec(), passthru(), shell_exec()")
    elif lang == "Python":
        prompt_parts.append("- Python: os.system(), subprocess.*, eval()")
    elif lang == "Node.js":
        prompt_parts.append("- Node.js: child_process.exec(), eval()")
    elif lang == "Java":
        prompt_parts.append("- Java: Runtime.exec(), ProcessBuilder")

    return "\n".join(prompt_parts)

def generate_rce_dedup_context(self, stack: Dict) -> str:
    """Dedup rules for RCE."""
    return """## RCE DEDUPLICATION RULES
- Same parameter + same injection point = DUPLICATE
- Same parameter + different command separators = technique variants (keep best)
- Different parameters = DIFFERENT
- Blind RCE vs Output RCE = DIFFERENT validation needs"""

# =========================================================================
# XXE-SPECIFIC CONTEXT
# =========================================================================

def generate_xxe_context_prompt(self, stack: Dict) -> str:
    """Generate XXE-specific context."""
    lang = stack.get("lang", "Unknown")

    prompt_parts = [
        "## TARGET TECHNOLOGY STACK (XXE CONTEXT)",
        f"- Backend Language: {lang}",
    ]

    # Infer XML parser
    parser = self._infer_xml_parser(lang)
    prompt_parts.append(f"- Likely XML Parser: {parser}")

    prompt_parts.append("")
    prompt_parts.append("## XXE STRATEGIC IMPLICATIONS")

    if lang == "PHP":
        prompt_parts.extend([
            "- PHP: libxml2 parser, check LIBXML_NOENT flag",
            "- PHP: expect:// wrapper for RCE if enabled",
        ])
    elif lang == "Java":
        prompt_parts.extend([
            "- Java: DocumentBuilder, SAXParser, XMLReader",
            "- Java: Parameter entity for OOB data exfil",
        ])
    elif lang == "Python":
        prompt_parts.extend([
            "- Python: lxml, xml.etree (etree safer by default)",
            "- Python: defusedxml blocks XXE",
        ])
    elif lang == ".NET" or lang == "ASP.NET":
        prompt_parts.extend([
            "- .NET: XmlDocument, XmlReader",
            "- .NET: DtdProcessing must be enabled for XXE",
        ])

    return "\n".join(prompt_parts)

def _infer_xml_parser(self, lang: str) -> str:
    """Infer XML parser from language."""
    parsers = {
        "PHP": "libxml2",
        "Java": "DocumentBuilder/SAX",
        "Python": "lxml/etree",
        "ASP.NET": "XmlDocument",
        ".NET": "XmlDocument",
        "Node.js": "xml2js/libxmljs",
    }
    return parsers.get(lang, "Unknown")

def generate_xxe_dedup_context(self, stack: Dict) -> str:
    """Dedup rules for XXE."""
    return """## XXE DEDUPLICATION RULES
- Same XML endpoint + same entity type = DUPLICATE
- Internal entity vs External entity = DIFFERENT
- Blind XXE vs Error-based XXE = DIFFERENT techniques
- Different XML endpoints = DIFFERENT"""

# =========================================================================
# IDOR-SPECIFIC CONTEXT
# =========================================================================

def generate_idor_context_prompt(self, stack: Dict) -> str:
    """Generate IDOR-specific context."""
    lang = stack.get("lang", "Unknown")
    frameworks = stack.get("frameworks", [])

    prompt_parts = [
        "## TARGET TECHNOLOGY STACK (IDOR CONTEXT)",
        f"- Backend Language: {lang}",
    ]

    if frameworks:
        prompt_parts.append(f"- Frameworks: {', '.join(frameworks[:3])}")

    prompt_parts.append("")
    prompt_parts.append("## IDOR STRATEGIC IMPLICATIONS")

    # Framework-specific ID patterns
    if any("django" in f.lower() for f in frameworks):
        prompt_parts.append("- Django: Sequential integer IDs common, check /api/v1/users/{id}")
    if any("rails" in f.lower() for f in frameworks):
        prompt_parts.append("- Rails: Auto-increment IDs, check nested resources")
    if any("laravel" in f.lower() for f in frameworks):
        prompt_parts.append("- Laravel: UUID or integer IDs, check route model binding")

    prompt_parts.extend([
        "- Test ID types: sequential integers, UUIDs, encoded values",
        "- Check horizontal (same role) and vertical (privilege escalation)",
    ])

    return "\n".join(prompt_parts)

def generate_idor_dedup_context(self, stack: Dict) -> str:
    """Dedup rules for IDOR."""
    return """## IDOR DEDUPLICATION RULES
- Same endpoint + same ID parameter = DUPLICATE
- Same endpoint + different ID parameters (id vs user_id) = DIFFERENT
- Different endpoints = DIFFERENT
- Horizontal vs Vertical IDOR = DIFFERENT severity"""

# =========================================================================
# JWT-SPECIFIC CONTEXT
# =========================================================================

def generate_jwt_context_prompt(self, stack: Dict) -> str:
    """Generate JWT-specific context."""
    lang = stack.get("lang", "Unknown")

    prompt_parts = [
        "## TARGET TECHNOLOGY STACK (JWT CONTEXT)",
        f"- Backend Language: {lang}",
    ]

    # Infer JWT library
    jwt_lib = self._infer_jwt_library(lang)
    prompt_parts.append(f"- Likely JWT Library: {jwt_lib}")

    prompt_parts.append("")
    prompt_parts.append("## JWT STRATEGIC IMPLICATIONS")

    prompt_parts.extend([
        "- Test algorithm confusion (RS256 → HS256)",
        "- Test 'none' algorithm bypass",
        "- Test weak secret brute-force",
        "- Check for JWK injection in header",
    ])

    if lang == "Node.js":
        prompt_parts.append("- Node.js jsonwebtoken: Check for algorithm whitelist bypass")
    elif lang == "Python":
        prompt_parts.append("- Python PyJWT: algorithms parameter required in v2+")
    elif lang == "Java":
        prompt_parts.append("- Java JJWT: Check for setSigningKey vs parseClaimsJws")

    return "\n".join(prompt_parts)

def _infer_jwt_library(self, lang: str) -> str:
    """Infer JWT library from language."""
    libs = {
        "Node.js": "jsonwebtoken",
        "Python": "PyJWT",
        "Java": "JJWT/nimbus-jose-jwt",
        "PHP": "firebase/php-jwt",
        "Ruby": "ruby-jwt",
        "ASP.NET": "System.IdentityModel.Tokens.Jwt",
    }
    return libs.get(lang, "Unknown")

def generate_jwt_dedup_context(self, stack: Dict) -> str:
    """Dedup rules for JWT."""
    return """## JWT DEDUPLICATION RULES
- Same endpoint + same attack type = DUPLICATE
- Algorithm confusion vs None alg vs Weak secret = DIFFERENT attacks
- Different endpoints using same JWT = test once (GLOBAL scope)"""

# =========================================================================
# OPEN REDIRECT-SPECIFIC CONTEXT
# =========================================================================

def generate_openredirect_context_prompt(self, stack: Dict) -> str:
    """Generate Open Redirect-specific context."""
    lang = stack.get("lang", "Unknown")
    frameworks = stack.get("frameworks", [])

    prompt_parts = [
        "## TARGET TECHNOLOGY STACK (OPEN REDIRECT CONTEXT)",
        f"- Backend Language: {lang}",
    ]

    prompt_parts.append("")
    prompt_parts.append("## OPEN REDIRECT STRATEGIC IMPLICATIONS")

    # Framework-specific redirect handling
    if any("spring" in f.lower() for f in frameworks):
        prompt_parts.append("- Spring: Check redirect: prefix, forward: prefix")
    if any("django" in f.lower() for f in frameworks):
        prompt_parts.append("- Django: Check next parameter, LOGIN_REDIRECT_URL")
    if any("express" in f.lower() or "node" in lang.lower() for f in frameworks):
        prompt_parts.append("- Express: res.redirect() with unvalidated input")

    prompt_parts.extend([
        "- Test protocol-relative URLs: //evil.com",
        "- Test URL encoding bypasses: %2f%2fevil.com",
        "- Test backslash confusion: /\\evil.com",
    ])

    return "\n".join(prompt_parts)

def generate_openredirect_dedup_context(self, stack: Dict) -> str:
    """Dedup rules for Open Redirect."""
    return """## OPEN REDIRECT DEDUPLICATION RULES
- Same parameter + same endpoint = DUPLICATE
- Different redirect parameters (url vs next vs return) = DIFFERENT
- Different endpoints = DIFFERENT
- Same bypass technique variants = keep most reliable"""

# =========================================================================
# PROTOTYPE POLLUTION-SPECIFIC CONTEXT
# =========================================================================

def generate_prototype_pollution_context_prompt(self, stack: Dict) -> str:
    """Generate Prototype Pollution-specific context."""
    frameworks = stack.get("frameworks", [])
    raw_profile = stack.get("raw_profile", {})
    tech_tags = [t.lower() for t in raw_profile.get("tech_tags", [])]

    prompt_parts = [
        "## TARGET TECHNOLOGY STACK (PROTOTYPE POLLUTION CONTEXT)",
    ]

    # Detect Node.js specifics
    node_frameworks = [f for f in frameworks if any(x in f.lower() for x in ["express", "next", "nest", "koa"])]
    if node_frameworks:
        prompt_parts.append(f"- Node.js Frameworks: {', '.join(node_frameworks)}")

    prompt_parts.append("")
    prompt_parts.append("## PROTOTYPE POLLUTION STRATEGIC IMPLICATIONS")

    prompt_parts.extend([
        "- Test __proto__ pollution via JSON: {\"__proto__\": {\"admin\": true}}",
        "- Test constructor.prototype: {\"constructor\": {\"prototype\": {...}}}",
        "- Check for lodash.merge, jQuery.extend, deep-merge usage",
    ])

    if any("express" in f.lower() for f in frameworks):
        prompt_parts.append("- Express: Check body-parser, qs module settings")
    if any("next" in " ".join(tech_tags)):
        prompt_parts.append("- Next.js: Server-side props pollution")

    return "\n".join(prompt_parts)

def generate_prototype_pollution_dedup_context(self, stack: Dict) -> str:
    """Dedup rules for Prototype Pollution."""
    return """## PROTOTYPE POLLUTION DEDUPLICATION RULES
- Same endpoint + same pollution path = DUPLICATE
- __proto__ vs constructor.prototype = technique variants (keep both initially)
- Different endpoints = DIFFERENT (pollution may affect different code paths)
- Client-side vs Server-side = DIFFERENT vulnerability classes"""
```

---

## 3. Agent Modification Pattern

### 3.1 Standard Implementation for Each Agent

```python
# 1. Add import
from bugtrace.agents.mixins.tech_context import TechContextMixin

# 2. Add mixin to class
class XxxAgent(BaseAgent, TechContextMixin):

# 3. Add attributes to __init__
self._tech_stack_context: Dict = {}
self._xxx_prime_directive: str = ""

# 4. Add _load_xxx_tech_context method
async def _load_xxx_tech_context(self) -> None:
    scan_dir = getattr(self, 'report_dir', None)
    if not scan_dir:
        scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
        scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

    if not scan_dir or not Path(scan_dir).exists():
        self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
        self._xxx_prime_directive = ""
        return

    self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
    self._xxx_prime_directive = self.generate_xxx_context_prompt(self._tech_stack_context)

    logger.info(f"[{self.name}] Tech context loaded: {self._tech_stack_context.get('lang', 'unknown')}")

# 5. Call in start_queue_consumer
async def start_queue_consumer(self, scan_context: str) -> None:
    self._queue_mode = True
    self._scan_context = scan_context

    # v3.2: Load context-aware tech stack
    await self._load_xxx_tech_context()

    # ... rest of method

# 6. Update _llm_analyze_and_dedup to use context
async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
    tech_stack = getattr(self, '_tech_stack_context', {}) or {}
    prime_directive = getattr(self, '_xxx_prime_directive', '')
    dedup_context = self.generate_xxx_dedup_context(tech_stack)

    system_prompt = f"""You are an expert XXX security analyst.

{prime_directive}

{dedup_context}

## TARGET CONTEXT
- Language: {tech_stack.get('lang', 'generic')}
...
"""
```

---

## 4. Files to Modify

### 4.1 Mixin File
```
bugtrace/agents/mixins/tech_context.py
  + generate_header_injection_context_prompt()
  + generate_header_injection_dedup_context()
  + generate_ssrf_context_prompt()
  + generate_ssrf_dedup_context()
  + _detect_cloud_provider()
  + generate_lfi_context_prompt()
  + generate_lfi_dedup_context()
  + _infer_os_from_stack()
  + generate_rce_context_prompt()
  + generate_rce_dedup_context()
  + generate_xxe_context_prompt()
  + generate_xxe_dedup_context()
  + _infer_xml_parser()
  + generate_idor_context_prompt()
  + generate_idor_dedup_context()
  + generate_jwt_context_prompt()
  + generate_jwt_dedup_context()
  + _infer_jwt_library()
  + generate_openredirect_context_prompt()
  + generate_openredirect_dedup_context()
  + generate_prototype_pollution_context_prompt()
  + generate_prototype_pollution_dedup_context()
```

### 4.2 Agent Files
```
bugtrace/agents/header_injection_agent.py
bugtrace/agents/ssrf_agent.py
bugtrace/agents/lfi_agent.py
bugtrace/agents/rce_agent.py
bugtrace/agents/xxe_agent.py
bugtrace/agents/idor_agent.py
bugtrace/agents/jwt_agent.py
bugtrace/agents/openredirect_agent.py
bugtrace/agents/prototype_pollution_agent.py
```

---

## 5. Implementation Priority

### Phase 1 (Critical - Cloud/OS Detection)
1. **SSRF Agent** - Cloud provider detection for metadata endpoints
2. **LFI Agent** - OS detection for path traversal
3. **RCE Agent** - OS detection for command syntax

### Phase 2 (High - Server/Language Specific)
4. **Header Injection Agent** - Server/CDN specific
5. **XXE Agent** - XML parser detection

### Phase 3 (Medium - Framework Specific)
6. **IDOR Agent** - Framework ID patterns
7. **JWT Agent** - JWT library detection

### Phase 4 (Low - Specialized)
8. **Open Redirect Agent** - Framework redirect handling
9. **Prototype Pollution Agent** - Node.js specific

---

## 6. Testing Checklist

For each agent implementation:
- [ ] Syntax check passes: `python3 -m py_compile bugtrace/agents/xxx_agent.py`
- [ ] Import works: `python3 -c "from bugtrace.agents.xxx_agent import XxxAgent"`
- [ ] Mixin methods available: `hasattr(XxxAgent, 'generate_xxx_context_prompt')`
- [ ] Tech context loads without error
- [ ] LLM deduplication uses tech context in prompt
