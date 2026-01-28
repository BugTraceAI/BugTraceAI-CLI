"""
Output Guardrails - Prevent harmful actions during bug bounty scans.

This module validates outputs before execution to:
- Block destructive commands
- Block out-of-scope targets
- Block dangerous SQL payloads
- Allow legitimate bug bounty testing
"""

import re
from typing import Tuple, List, Optional
from urllib.parse import urlparse
from bugtrace.utils.logger import get_logger

logger = get_logger("core.guardrails")


class OutputGuardrails:
    """
    Validate outputs before execution to prevent harm.
    
    Designed for bug bounty: blocks destructive actions while
    allowing legitimate security testing payloads.
    """
    
    # Dangerous shell command patterns
    DANGEROUS_COMMANDS = [
        (r"rm\s+-rf\s+/", "Recursive delete from root"),
        (r"rm\s+-rf\s+~", "Recursive delete home"),
        (r"rm\s+-rf\s+\*", "Recursive delete wildcard"),
        (r">\s*/dev/", "Write to device"),
        (r"mkfs\.", "Format filesystem"),
        (r"dd\s+if=.*of=/dev/", "Raw disk write"),
        (r":\(\)\s*\{.*\}", "Fork bomb"),
        (r"/dev/tcp/", "Reverse shell via /dev/tcp"),
        (r"nc\s+-e", "Netcat reverse shell"),
        (r"bash\s+-i\s+>&", "Bash reverse shell"),
        (r"chmod\s+777\s+/", "Chmod root"),
        (r"shutdown", "System shutdown"),
        (r"reboot", "System reboot"),
        (r"init\s+0", "System halt"),
    ]
    
    # Dangerous SQL patterns (could destroy data)
    DANGEROUS_SQL = [
        (r"DROP\s+TABLE", "Drop table"),
        (r"DROP\s+DATABASE", "Drop database"),
        (r"TRUNCATE\s+TABLE", "Truncate table"),
        (r"DELETE\s+FROM\s+\w+\s*;", "Delete without WHERE"),
        (r"UPDATE\s+\w+\s+SET\s+.*;\s*$", "Update without WHERE"),
        (r"ALTER\s+TABLE.*DROP", "Alter table drop column"),
    ]
    
    # Patterns that are OK for bug bounty testing
    ALLOWED_PATTERNS = [
        r"<script>alert\(",  # XSS testing
        r"' OR '1'='1",     # SQLi testing
        r"UNION SELECT",     # SQLi enumeration (read-only)
        r"' AND '1'='1",    # Boolean SQLi
        r"SLEEP\(",         # Time-based SQLi
        r"BENCHMARK\(",     # Time-based SQLi
        r"{{.*}}",          # SSTI testing
        r"%0d%0a",          # Header injection
        r"\.\./",           # Path traversal
    ]
    
    def __init__(self, scope_domains: Optional[List[str]] = None):
        """
        Initialize guardrails.
        
        Args:
            scope_domains: List of allowed domains for bug bounty scope
        """
        self.scope_domains = scope_domains or []
        self.blocked_count = 0
        self.allowed_count = 0
        
        logger.info(f"Guardrails initialized. Scope: {len(self.scope_domains)} domains")
    
    def validate_command(self, command: str) -> Tuple[bool, str]:
        """
        Check if shell command is safe to execute.
        
        Args:
            command: Shell command to validate
            
        Returns:
            (is_safe, reason)
        """
        for pattern, description in self.DANGEROUS_COMMANDS:
            if re.search(pattern, command, re.IGNORECASE):
                self.blocked_count += 1
                logger.warning(f"Guardrail BLOCKED command: {description}")
                return False, f"Dangerous command blocked: {description}"
        
        self.allowed_count += 1
        return True, "OK"
    
    def validate_payload(self, payload: str, vuln_type: str) -> Tuple[bool, str]:
        """
        Check if vulnerability payload is safe for bug bounty.
        
        Blocks destructive payloads while allowing detection payloads.
        
        Args:
            payload: The payload string
            vuln_type: Type of vulnerability (SQLi, XSS, etc.)
            
        Returns:
            (is_safe, reason)
        """
        if not payload:
            return True, "Empty payload"
        
        # Check for destructive SQL
        if vuln_type in ["SQLi", "SQL Injection"]:
            for pattern, description in self.DANGEROUS_SQL:
                if re.search(pattern, payload, re.IGNORECASE):
                    self.blocked_count += 1
                    logger.warning(f"Guardrail BLOCKED SQL: {description}")
                    return False, f"Destructive SQL blocked: {description}"
        
        # Check for shell commands in payloads
        for pattern, description in self.DANGEROUS_COMMANDS:
            if re.search(pattern, payload, re.IGNORECASE):
                self.blocked_count += 1
                logger.warning(f"Guardrail BLOCKED payload: {description}")
                return False, f"Dangerous payload blocked: {description}"
        
        self.allowed_count += 1
        return True, "OK"
    
    def validate_url(self, url: str) -> Tuple[bool, str]:
        """
        Check if URL is in bug bounty scope.
        
        Args:
            url: URL to validate
            
        Returns:
            (in_scope, reason)
        """
        if not self.scope_domains:
            # No scope defined = allow all
            return True, "No scope restrictions"
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            for allowed in self.scope_domains:
                allowed = allowed.lower()
                # Check exact match or subdomain
                if domain == allowed or domain.endswith(f".{allowed}"):
                    return True, f"In scope: {allowed}"
            
            self.blocked_count += 1
            logger.warning(f"Guardrail BLOCKED out-of-scope: {domain}")
            return False, f"Out of scope: {domain}"
            
        except Exception as e:
            return False, f"Invalid URL: {e}"
    
    def set_scope(self, domains: List[str]):
        """Set allowed domains for bug bounty scope."""
        self.scope_domains = [d.lower() for d in domains]
        logger.info(f"Scope updated: {self.scope_domains}")
    
    def get_stats(self) -> dict:
        """Get guardrail statistics."""
        return {
            "blocked": self.blocked_count,
            "allowed": self.allowed_count,
            "scope_domains": self.scope_domains
        }
    
    # =========================================================================
    # INPUT GUARDRAILS - Detect prompt injection and malicious inputs
    # =========================================================================
    
    # Prompt injection patterns
    PROMPT_INJECTION_PATTERNS = [
        (r"ignore\s+(previous|all|above)\s+instructions?", "Instruction override"),
        (r"forget\s+(everything|all|your)", "Memory manipulation"),
        (r"you\s+are\s+now\s+a", "Role hijacking"),
        (r"act\s+as\s+if\s+you\s+were", "Role hijacking"),
        (r"pretend\s+you\s+are", "Role hijacking"),
        (r"disregard\s+your\s+training", "Training override"),
        (r"override\s+your\s+rules", "Rule override"),
        (r"system\s*:\s*you", "System prompt injection"),
        (r"\[SYSTEM\]", "System prompt injection"),
        (r"<\|im_start\|>", "Token injection"),
        (r"<\|endoftext\|>", "Token injection"),
        (r"###\s*instruction", "Instruction injection"),
    ]
    
    def validate_input(self, user_input: str) -> Tuple[bool, str]:
        """
        Detect prompt injection attempts in user input.
        
        Args:
            user_input: Input string to validate
            
        Returns:
            (is_safe, reason)
        """
        if not user_input:
            return True, "Empty input"
        
        input_lower = user_input.lower()
        
        for pattern, description in self.PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, input_lower, re.IGNORECASE):
                self.blocked_count += 1
                logger.warning(f"Guardrail BLOCKED input: {description}")
                return False, f"Prompt injection detected: {description}"
        
        # Check for encoded payloads (base64)
        if self._detect_encoded_injection(user_input):
            self.blocked_count += 1
            logger.warning("Guardrail BLOCKED: Encoded injection detected")
            return False, "Encoded injection detected"
        
        self.allowed_count += 1
        return True, "OK"
    
    def _detect_encoded_injection(self, text: str) -> bool:
        """Detect base64/hex encoded prompt injections."""
        import base64

        # Check for base64 patterns
        base64_pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
        matches = re.findall(base64_pattern, text)

        for match in matches:
            if self._check_base64_injection(match):
                return True

        return False

    def _check_base64_injection(self, match: str) -> bool:
        """Check if base64 match contains injection patterns."""
        import base64

        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            # Check if decoded content contains injection patterns
            for pattern, _ in self.PROMPT_INJECTION_PATTERNS:
                if re.search(pattern, decoded.lower()):
                    return True
        except (ValueError, UnicodeDecodeError) as e:
            logger.debug(f"Base64 decode failed: {e}")

        return False
    
    def validate_llm_response(self, response: str) -> Tuple[bool, str]:
        """
        Validate LLM response before using it.
        
        Args:
            response: LLM response to validate
            
        Returns:
            (is_safe, reason)
        """
        if not response:
            return True, "Empty response"
        
        # Check for dangerous commands in response
        for pattern, description in self.DANGEROUS_COMMANDS:
            if re.search(pattern, response, re.IGNORECASE):
                logger.warning(f"Guardrail flagged LLM response: {description}")
                # Don't block, just flag - LLM might be explaining something
                return True, f"Warning: Contains pattern '{description}'"
        
        return True, "OK"
    
    def validate_scope_url(self, url: str, target_url: str) -> Tuple[bool, str]:
        """
        Check if URL is in scope relative to the original target.
        Automatically extracts scope from target URL if not set.
        
        Args:
            url: URL to validate
            target_url: Original target URL for scope inference
            
        Returns:
            (in_scope, reason)
        """
        # If explicit scope is set, use it
        if self.scope_domains:
            return self.validate_url(url)
        
        # Otherwise, infer scope from target
        try:
            target_parsed = urlparse(target_url)
            url_parsed = urlparse(url)
            
            target_domain = target_parsed.netloc.lower()
            url_domain = url_parsed.netloc.lower()
            
            # Same domain or subdomain = in scope
            if url_domain == target_domain or url_domain.endswith(f".{target_domain}"):
                return True, f"In scope: same domain as target"
            
            # Extract root domain (e.g., vulnweb.com from testphp.vulnweb.com)
            target_parts = target_domain.split(".")
            url_parts = url_domain.split(".")
            
            if len(target_parts) >= 2 and len(url_parts) >= 2:
                target_root = ".".join(target_parts[-2:])
                url_root = ".".join(url_parts[-2:])
                
                if target_root == url_root:
                    return True, f"In scope: same root domain"
            
            self.blocked_count += 1
            logger.warning(f"URL {url_domain} out of scope (target: {target_domain})")
            return False, f"Out of scope: {url_domain} (expected: {target_domain})"
            
        except Exception as e:
            return False, f"Invalid URL: {e}"


# Global instance
guardrails = OutputGuardrails()
