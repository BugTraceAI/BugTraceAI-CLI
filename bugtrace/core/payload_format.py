"""
Payload Format Utilities

This module provides utilities for reading and writing specialist queue files.

v3.2 Format (JSON Lines - recommended):
- Location: specialists/wet/{specialist}.json
- Format: One JSON object per line
- Example: {"timestamp": 1706882445.123, "specialist": "xss", "finding": {...}}

v3.1 Legacy Format (XML-like with Base64):
- Location: queues/{specialist}.queue (deprecated)
- Format: XML-like blocks with Base64 encoded payloads

Author: BugtraceAI Team
Date: 2026-02-02
Version: 2.0.0
"""

import base64
import json
import re
from typing import Dict, List, Any, Optional, Iterator
from pathlib import Path


def encode_payload(data: Dict[str, Any]) -> str:
    """
    Encode a dictionary as Base64 JSON.
    
    Args:
        data: Dictionary to encode
        
    Returns:
        Base64 encoded string
    """
    json_str = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    return base64.b64encode(json_str.encode('utf-8')).decode('ascii')


def decode_payload(b64_string: str) -> Dict[str, Any]:
    """
    Decode a Base64 JSON string back to a dictionary.

    Args:
        b64_string: Base64 encoded JSON string

    Returns:
        Decoded dictionary
    """
    json_bytes = base64.b64decode(b64_string)
    return json.loads(json_bytes.decode('utf-8'))


# =============================================================================
# Payload Field Encoding (v3.2)
# =============================================================================

def encode_payload_field(payload_str: str) -> str:
    """
    Encode a payload string to base64 for safe JSON storage.

    Complex payloads (XML, special chars, quotes) can break JSON.
    Base64 encoding ensures safe storage and transport.

    Args:
        payload_str: Raw payload string

    Returns:
        Base64 encoded string
    """
    if not payload_str:
        return ""
    return base64.b64encode(payload_str.encode('utf-8')).decode('ascii')


def decode_payload_field(b64_payload: str) -> str:
    """
    Decode a base64 payload string back to raw format for testing.

    Args:
        b64_payload: Base64 encoded payload

    Returns:
        Raw payload string
    """
    if not b64_payload:
        return ""
    try:
        return base64.b64decode(b64_payload).decode('utf-8')
    except Exception:
        # Not base64 encoded, return as-is (backward compatibility)
        return b64_payload


def is_base64_payload(payload_str: str) -> bool:
    """
    Check if a payload string is already base64 encoded.

    Args:
        payload_str: Payload string to check

    Returns:
        True if base64, False otherwise
    """
    if not payload_str:
        return False
    # Base64 pattern: only A-Za-z0-9+/= and length multiple of 4 (with padding)
    import re
    if not re.match(r'^[A-Za-z0-9+/]+=*$', payload_str):
        return False
    try:
        base64.b64decode(payload_str)
        return True
    except Exception:
        return False


def encode_finding_payloads(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Encode payload fields in a finding dict to base64.

    Encodes: payload, exploitation_strategy, reproduction (if contains payload)

    Args:
        finding: Finding dictionary

    Returns:
        Finding with base64 encoded payloads
    """
    result = dict(finding)

    # Fields that contain payloads to encode
    payload_fields = ['payload', 'exploitation_strategy']

    for field in payload_fields:
        if field in result and result[field]:
            value = str(result[field])
            # Only encode if not already base64 and has special chars
            if not is_base64_payload(value) and _needs_encoding(value):
                result[f"{field}_b64"] = encode_payload_field(value)
                result[field] = f"[B64:{len(value)}chars]"  # Placeholder showing original length

    return result


def decode_finding_payloads(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decode base64 payload fields in a finding dict back to raw format.

    Args:
        finding: Finding dictionary with potential _b64 fields

    Returns:
        Finding with decoded payloads
    """
    result = dict(finding)

    # Fields to check for base64 versions
    payload_fields = ['payload', 'exploitation_strategy']

    for field in payload_fields:
        b64_field = f"{field}_b64"
        if b64_field in result and result[b64_field]:
            # Decode and replace
            result[field] = decode_payload_field(result[b64_field])
            del result[b64_field]

    return result


def _needs_encoding(value: str) -> bool:
    """
    Check if a value needs base64 encoding for safe JSON storage.

    Args:
        value: String value to check

    Returns:
        True if encoding recommended
    """
    # Needs encoding if contains:
    # - XML/HTML tags
    # - Newlines
    # - Excessive quotes
    # - Non-ASCII
    # - Very long strings
    if len(value) > 500:
        return True
    if '<' in value and '>' in value:
        return True
    if '\n' in value or '\r' in value:
        return True
    if value.count('"') > 3 or value.count("'") > 3:
        return True
    try:
        value.encode('ascii')
    except UnicodeEncodeError:
        return True
    return False


# =============================================================================
# v3.2 JSON Lines Format (RECOMMENDED)
# =============================================================================

def write_wet_item(
    file_path: Path,
    specialist: str,
    finding: Dict[str, Any],
    scan_context: str
) -> None:
    """
    Write a finding to a specialists/wet/*.json file in JSON Lines format.

    Args:
        file_path: Path to the .json file
        specialist: Specialist name (e.g., "xss", "sqli")
        finding: Finding dictionary
        scan_context: Scan context identifier
    """
    import time

    entry = {
        "timestamp": time.time(),
        "specialist": specialist,
        "scan_context": scan_context,
        "finding": finding
    }

    with open(file_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False, separators=(',', ':')) + "\n")


def read_wet_items(file_path: Path) -> Iterator[Dict[str, Any]]:
    """
    Read and parse all items from a specialists/wet/*.json file.

    Args:
        file_path: Path to the .json file

    Yields:
        Dictionary with keys: timestamp, specialist, scan_context, finding
    """
    if not file_path.exists():
        return

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


# =============================================================================
# v3.1 Legacy Format (XML-like with Base64) - DEPRECATED
# =============================================================================

def write_queue_item(
    file_path: Path,
    specialist: str,
    finding: Dict[str, Any],
    scan_context: str
) -> None:
    """
    DEPRECATED: Use write_wet_item() instead.

    Write a finding to a .queue file in XML-like format.

    Args:
        file_path: Path to the .queue file
        specialist: Specialist name (e.g., "xss", "sqli")
        finding: Finding dictionary
        scan_context: Scan context identifier
    """
    import time
    
    finding_b64 = encode_payload(finding)
    
    entry = (
        f"<QUEUE_ITEM>\n"
        f"  <TIMESTAMP>{time.time()}</TIMESTAMP>\n"
        f"  <SPECIALIST>{specialist}</SPECIALIST>\n"
        f"  <SCAN_CONTEXT>{scan_context}</SCAN_CONTEXT>\n"
        f"  <FINDING_B64>{finding_b64}</FINDING_B64>\n"
        f"</QUEUE_ITEM>\n"
    )
    
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(entry)


def read_queue_items(file_path: Path) -> Iterator[Dict[str, Any]]:
    """
    Read and parse all items from a .queue file.
    
    Args:
        file_path: Path to the .queue file
        
    Yields:
        Dictionary with keys: timestamp, specialist, scan_context, finding
    """
    if not file_path.exists():
        return
    
    content = file_path.read_text(encoding='utf-8')
    
    # Parse all QUEUE_ITEM blocks
    pattern = re.compile(
        r'<QUEUE_ITEM>\s*'
        r'<TIMESTAMP>(.*?)</TIMESTAMP>\s*'
        r'<SPECIALIST>(.*?)</SPECIALIST>\s*'
        r'<SCAN_CONTEXT>(.*?)</SCAN_CONTEXT>\s*'
        r'<FINDING_B64>(.*?)</FINDING_B64>\s*'
        r'</QUEUE_ITEM>',
        re.DOTALL
    )
    
    for match in pattern.finditer(content):
        timestamp_str, specialist, scan_context, finding_b64 = match.groups()
        
        try:
            finding = decode_payload(finding_b64.strip())
            yield {
                "timestamp": float(timestamp_str.strip()),
                "specialist": specialist.strip(),
                "scan_context": scan_context.strip(),
                "finding": finding
            }
        except Exception as e:
            # Log but continue parsing
            print(f"Warning: Failed to parse queue item: {e}")
            continue


def read_findings_file(file_path: Path) -> Iterator[Dict[str, Any]]:
    """
    Read and parse all items from a .findings file.
    
    Args:
        file_path: Path to the .findings file
        
    Yields:
        Dictionary with keys: timestamp, type, data
    """
    if not file_path.exists():
        return
    
    content = file_path.read_text(encoding='utf-8')
    
    # Parse all FINDING blocks
    pattern = re.compile(
        r'<FINDING>\s*'
        r'<TIMESTAMP>(.*?)</TIMESTAMP>\s*'
        r'<TYPE>(.*?)</TYPE>\s*'
        r'<DATA_B64>(.*?)</DATA_B64>\s*'
        r'</FINDING>',
        re.DOTALL
    )
    
    for match in pattern.finditer(content):
        timestamp_str, finding_type, data_b64 = match.groups()
        
        try:
            data = decode_payload(data_b64.strip())
            yield {
                "timestamp": float(timestamp_str.strip()),
                "type": finding_type.strip(),
                "data": data
            }
        except Exception as e:
            print(f"Warning: Failed to parse finding: {e}")
            continue


def read_llm_audit_log(file_path: Path) -> Iterator[Dict[str, Any]]:
    """
    Read and parse all items from the LLM audit log.
    
    Args:
        file_path: Path to the llm_audit.log file
        
    Yields:
        Dictionary with keys: timestamp, module, model, prompt, response
    """
    if not file_path.exists():
        return
    
    content = file_path.read_text(encoding='utf-8')
    
    # Parse all LLM_CALL blocks
    pattern = re.compile(
        r'<LLM_CALL>\s*'
        r'<TIMESTAMP>(.*?)</TIMESTAMP>\s*'
        r'<MODULE>(.*?)</MODULE>\s*'
        r'<MODEL>(.*?)</MODEL>\s*'
        r'<PROMPT_B64>(.*?)</PROMPT_B64>\s*'
        r'<RESPONSE_B64>(.*?)</RESPONSE_B64>\s*'
        r'</LLM_CALL>',
        re.DOTALL
    )
    
    for match in pattern.finditer(content):
        timestamp_str, module, model, prompt_b64, response_b64 = match.groups()
        
        try:
            prompt = base64.b64decode(prompt_b64.strip()).decode('utf-8')
            response = base64.b64decode(response_b64.strip()).decode('utf-8')
            
            yield {
                "timestamp": timestamp_str.strip(),
                "module": module.strip(),
                "model": model.strip(),
                "prompt": prompt,
                "response": response
            }
        except Exception as e:
            print(f"Warning: Failed to parse LLM call: {e}")
            continue


# Convenience function for CLI usage
def print_queue_summary(file_path: Path) -> None:
    """Print a summary of queue items for debugging."""
    items = list(read_queue_items(file_path))
    print(f"\n📋 Queue File: {file_path.name}")
    print(f"   Total Items: {len(items)}")
    
    for i, item in enumerate(items, 1):
        finding = item['finding']
        print(f"\n   [{i}] {finding.get('type', 'Unknown')}")
        print(f"       Parameter: {finding.get('parameter', 'N/A')}")
        print(f"       URL: {finding.get('url', 'N/A')[:60]}...")
        if finding.get('payload'):
            print(f"       Payload: {finding.get('payload')[:50]}...")
