import re
import json
import base64
from typing import List, Optional

# JWT Regex: Header.Payload.Signature
# Base64Url pattern for each part
JWT_REGEX = r'(ey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})'

def find_jwts(text: str) -> List[str]:
    """Find all potential JWTs in a block of text."""
    if not text:
        return []
    
    matches = re.findall(JWT_REGEX, text)
    valid_jwts = []
    
    for match in matches:
        if _is_valid_jwt_format(match):
            valid_jwts.append(match)
            
    return list(set(valid_jwts)) # Deduplicate

def _is_valid_jwt_format(token: str) -> bool:
    """Perform a shallow validation by decoding the header and payload."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
            
        # Try to decode header
        header_raw = _base64_decode(parts[0])
        header = json.loads(header_raw)
        
        # Check for mandatory JWT fields in header
        if "alg" not in header:
            return False
            
        # Try to decode payload
        payload_raw = _base64_decode(parts[1])
        json.loads(payload_raw) # Should be valid JSON
        
        return True
    except:
        return False

def _base64_decode(data: str) -> str:
    """Base64Url decode helper."""
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data).decode('utf-8')
