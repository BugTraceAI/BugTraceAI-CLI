#!/usr/bin/env python3
"""
Batch script to add expert deduplication to remaining agents.
"""

AGENTS = [
    ("csti_agent.py", "CSTI", "netloc, path, parameter, template_engine"),
    ("openredirect_agent.py", "OPEN_REDIRECT", "netloc, path, parameter.lower()"),
    ("idor_agent.py", "IDOR", "netloc, normalized_path, resource_type"),
    ("jwt_agent.py", "JWT", "netloc, vuln_type"),
    ("prototype_pollution_agent.py", "PROTOTYPE_POLLUTION", "netloc, normalized_path, parameter.lower()"),
    ("header_injection_agent.py", "HEADER_INJECTION", "header_name.lower()"),
]

INIT_TEMPLATE = """
        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # Agent-specific fingerprint"""

FINGERPRINT_TEMPLATE = """    def _generate_{vuln_lower}_fingerprint(self, {params}) -> tuple:
        \"\"\"
        Generate {vuln_type} finding fingerprint for expert deduplication.

        Returns:
            Tuple fingerprint for deduplication
        \"\"\"
        from urllib.parse import urlparse

        parsed = urlparse(url)
        normalized_path = parsed.path.rstrip('/')

        # {vuln_type} signature
        fingerprint = ("{vuln_type}", {fingerprint_parts})

        return fingerprint
"""

DEDUP_CHECK_TEMPLATE = """
        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        fingerprint = self._generate_{vuln_lower}_fingerprint({fingerprint_args})

        if fingerprint in self._emitted_findings:
            logger.info(f"[{{self.name}}] Skipping duplicate {vuln_type} finding (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)
"""

print("✅ Template created. Apply manually to each agent following the pattern.")
print("Agents to update:", [a[0] for a in AGENTS])
