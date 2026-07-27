"""
JSON parsing utilities for LLM responses.

Handles common LLM output patterns:
- Plain JSON
- JSON wrapped in markdown code blocks
- Empty responses
- Non-JSON text with embedded JSON
"""
import json
from typing import Any


def safe_json_loads(response: str, fallback: Any = None) -> Any:
    """
    Safely parse JSON from an LLM response.
    
    Tries to parse the entire response as JSON first, then attempts to extract
    JSON from markdown code blocks. Returns fallback if parsing fails.
    
    Args:
        response: Raw LLM response text
        fallback: Value to return if parsing fails (default: None)
    
    Returns:
        Parsed JSON object or fallback value
    """
    if not response or not response.strip():
        return fallback
    
    response = response.strip()
    
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass
    
    # Try to extract from markdown code blocks
    for pattern in ("```json", "```"):
        if pattern in response:
            try:
                start = response.find(pattern) + len(pattern)
                end = response.find("```", start)
                if end > start:
                    block = response[start:end].strip()
                    return json.loads(block)
            except json.JSONDecodeError:
                continue
    
    # Decode from each possible opening token in source order. This preserves
    # an outer array instead of incorrectly returning its first object.
    decoder = json.JSONDecoder()
    for start, char in enumerate(response):
        if char not in "[{":
            continue
        try:
            parsed, _ = decoder.raw_decode(response[start:])
            return parsed
        except json.JSONDecodeError:
            continue

    return fallback


def extract_json_list(payload: Any, key: str, fallback: Any = None) -> Any:
    """Return a list from either a direct array or an object field."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return fallback
