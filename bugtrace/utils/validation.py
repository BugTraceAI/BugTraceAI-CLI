import re
from typing import Tuple, Dict

def validate_payload_format(finding_dict: Dict) -> Tuple[bool, str]:
    """
    V3.5 Reactor Architecture: Pre-flight payload validator.
    Ensures findings have raw, executable payloads and not conversational text.
    """
    payload = finding_dict.get("payload", "")
    
    # Legitimately empty/NA payloads for some types
    if not payload or str(payload).strip().upper() in ["N/A", "NONE", ""]:
        return True, ""
        
    payload_str = str(payload)
    
    # Forbidden patterns (conversational markers)
    conversational_patterns = [
        r"^(Inject|Use|Try|Attempt|Test for|Increment|Decrement|Set|Access|Exploit|Navigate|Check|Verify|Submit)",
        r"\(e\.g\.,",  # Examples in parentheses
        r"to (verify|exfiltrate|access|bypass|leak|confirm|test|execute)", 
        r"(such as|Alternatively|progress to|Start with|for instance|like)",
        r"(or use|or try|or attempt)",  # Multiple options
        r"&lt;",       # HTML escaped characters (hallucinations)
        r"&gt;",
        r"&quot;",
        r"payload (could|should|must) be",
        r"strategy:",
        r"logic:",
        r"vulnerability (exists|is present)"
    ]
    
    for pattern in conversational_patterns:
        if re.search(pattern, payload_str, re.IGNORECASE):
            return False, f"HALLUCINATION REJECTED: Payload contains conversational pattern '{pattern}'. Payload: '{payload_str[:50]}...'"
            
    return True, ""
