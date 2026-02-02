#!/usr/bin/env python3
"""
Apply fingerprint methods and dedup checks to remaining 6 agents.
"""
import re

# Agent configurations: (file, vuln_type, fingerprint_logic)
AGENTS = [
    ("csti_agent.py", "CSTI", "parsed.netloc, normalized_path, parameter.lower()"),
    ("openredirect_agent.py", "OPEN_REDIRECT", "parsed.netloc, normalized_path, parameter.lower()"),
    ("idor_agent.py", "IDOR", "parsed.netloc, normalized_path, resource_type"),
    ("jwt_agent.py", "JWT", "parsed.netloc, vuln_type"),
    ("prototype_pollution_agent.py", "PROTOTYPE_POLLUTION", "parsed.netloc, normalized_path, parameter.lower()"),
    ("header_injection_agent.py", "HEADER_INJECTION", "header_name.lower()"),
]

def generate_fingerprint_method(vuln_type, fingerprint_parts):
    """Generate fingerprint method code."""
    vuln_lower = vuln_type.lower().replace("_", "")

    # Determine parameters based on fingerprint logic
    if "header_name" in fingerprint_parts:
        params = "header_name: str"
    elif "vuln_type" in fingerprint_parts:
        params = "url: str, vuln_type: str"
    elif "resource_type" in fingerprint_parts:
        params = "url: str, resource_type: str"
    else:
        params = "url: str, parameter: str"

    method = f'''    def _generate_{vuln_lower}_fingerprint(self, {params}) -> tuple:
        """
        Generate {vuln_type} finding fingerprint for expert deduplication.

        Returns:
            Tuple fingerprint for deduplication
        """
        from urllib.parse import urlparse

        parsed = urlparse(url) if 'url' in '{params}' else None
        normalized_path = parsed.path.rstrip('/') if parsed else ""

        # {vuln_type} signature
        fingerprint = ("{vuln_type}", {fingerprint_parts})

        return fingerprint

'''
    return method

def generate_dedup_check(vuln_type, fingerprint_args):
    """Generate deduplication check code."""
    vuln_lower = vuln_type.lower().replace("_", "")

    check = f'''        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        fingerprint = self._generate_{vuln_lower}_fingerprint({fingerprint_args})

        if fingerprint in self._emitted_findings:
            logger.info(f"[{{self.name}}] Skipping duplicate {vuln_type} finding (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

'''
    return check

print("✅ Script ready. Apply fingerprint methods and dedup checks to agents.")
print(f"Processing {len(AGENTS)} agents...")

for filename, vuln_type, fp_logic in AGENTS:
    print(f"\n📝 {filename}: {vuln_type}")
    print(f"   Fingerprint: ({vuln_type}, {fp_logic})")
