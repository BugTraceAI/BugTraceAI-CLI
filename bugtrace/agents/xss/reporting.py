"""
XSS scan reporting functions.

I/O layer -- writes phase reports to the filesystem as Markdown files.
Each function takes a report_dir Path and all data as explicit parameters
(no self, no instance state).

The get_snippet function is pure (no I/O).

Extracted from xss_agent.py (lines 2039-2257).
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol

import logging

logger = logging.getLogger("agents.xss_v4")


# =========================================================================
# Timestamp helper
# =========================================================================

def _now() -> str:
    """Return the current timestamp in ISO 8601 format."""
    return datetime.now().isoformat()


# =========================================================================
# Protocol for FuzzResult (avoids importing go_bridge)
# =========================================================================

class FuzzResultLike(Protocol):
    """Structural type for FuzzResult-compatible objects."""
    total_requests: int
    duration_ms: int
    requests_per_second: float
    reflections: list


class ReflectionLike(Protocol):
    """Structural type for Reflection-compatible objects."""
    payload: str
    context: str
    encoded: bool
    status_code: int
    is_suspicious: bool


# =========================================================================
# Protocol for XSSFinding (avoids importing types)
# =========================================================================

class FindingLike(Protocol):
    """Structural type for XSSFinding-compatible objects."""
    parameter: str
    payload: str
    context: str
    confidence: float
    evidence: Dict[str, Any]
    exploit_url: str
    screenshot_path: Optional[str]


# =========================================================================
# Pure helper
# =========================================================================

def get_snippet(text: str, target: str, max_len: int = 200) -> str:
    """
    Extract a snippet of text surrounding a target substring.

    Returns the portion of text centered around the first occurrence
    of target, with up to 50 chars before and 100 chars after.

    Args:
        text: The full text to search in.
        target: The substring to find and center on.
        max_len: Maximum length of the returned snippet (unused,
                 kept for API compatibility).

    Returns:
        The extracted snippet, or empty string if target is not found.
    """
    idx = text.find(target)
    if idx == -1:
        return ""
    start = max(0, idx - 50)
    end = min(len(text), idx + len(target) + 100)
    return text[start:end].strip()


# =========================================================================
# Phase 1: Bombardment report
# =========================================================================

def save_phase1_report(
    report_dir: Path,
    url: str,
    param: str,
    payloads: List[str],
    result: FuzzResultLike,
) -> None:
    """
    Save Phase 1 bombardment report to Markdown.

    Args:
        report_dir: Directory where the report file will be written.
        url: The target URL being scanned.
        param: The parameter being tested.
        payloads: List of payloads that were sent.
        result: FuzzResult-like object with bombardment statistics.
    """
    report_path = report_dir / "phase1_bombardment.md"

    payload_listing = chr(10).join(payloads[:50])
    overflow_note = (
        f'... and {len(payloads) - 50} more'
        if len(payloads) > 50 else ""
    )

    content = f"""# Phase 1: BOMBARDEO TOTAL

**Target:** {url}
**Parameter:** {param}
**Timestamp:** {_now()}

## Statistics
- Total Payloads Sent: {len(payloads)}
- Total Requests: {result.total_requests}
- Duration: {result.duration_ms}ms
- Speed: {result.requests_per_second:.1f} req/s
- Reflections Found: {len(result.reflections)}

## Payload Sources
1. OMNIPROBE_PAYLOAD (context detection)
2. Curated List (bugtrace/data/xss_curated_list.txt)
3. Proven Payloads (dynamic memory)
4. GOLDEN_PAYLOADS (defaults)
5. FRAGMENT_PAYLOADS (DOM XSS)

## Payloads Sent
```
{payload_listing}
{overflow_note}
```

## Reflections Summary
| Payload | Context | Encoded | Status |
|---------|---------|---------|--------|
"""
    for ref in result.reflections[:30]:
        content += f"| `{ref.payload[:40]}...` | {ref.context} | {ref.encoded} | {ref.status_code} |\n"

    if len(result.reflections) > 30:
        content += f"\n*... and {len(result.reflections) - 30} more reflections*\n"

    report_path.write_text(content)
    logger.debug(f"Phase 1 report saved to {report_path}")


# =========================================================================
# Phase 2: Analysis report
# =========================================================================

def save_phase2_report(
    report_dir: Path,
    analysis: Dict,
) -> None:
    """
    Save Phase 2 analysis report to Markdown.

    Args:
        report_dir: Directory where the report file will be written.
        analysis: Dictionary containing reflection analysis results
                  (keys: reflections, contexts, interactsh_confirmed,
                  high_confidence_candidates, escaping, confirmed_payload).
    """
    report_path = report_dir / "phase2_analysis.md"

    content = f"""# Phase 2: ANALISIS

**Timestamp:** {_now()}

## Summary
- Total Reflections: {len(analysis.get('reflections', []))}
- Contexts Found: {', '.join(analysis.get('contexts', []))}
- Interactsh Confirmed: {'YES' if analysis.get('interactsh_confirmed') else 'No'}
- High Confidence Candidates: {len(analysis.get('high_confidence_candidates', []))}

## Server Escaping Behavior
```json
{json.dumps(analysis.get('escaping', {}), indent=2)}
```

## Reflection Details
"""
    for i, ref in enumerate(analysis.get('reflections', [])[:50], 1):
        suspicious = 'YES' if ref['is_suspicious'] else 'No'
        content += f"""
### Reflection {i}
- **Payload:** `{ref['payload'][:80]}...`
- **Context:** {ref['context']}
- **Encoded:** {ref['encoded']} ({ref.get('encoding_type', 'N/A')})
- **Status Code:** {ref['status_code']}
- **Suspicious:** {suspicious}
"""

    if analysis.get('interactsh_confirmed'):
        content += f"""
## INTERACTSH CONFIRMATION
**XSS CONFIRMED via OOB callback!**
- Confirmed Payload: `{analysis.get('confirmed_payload', 'N/A')}`
"""

    report_path.write_text(content)
    logger.debug(f"Phase 2 report saved to {report_path}")


# =========================================================================
# Phase 3: Amplification report
# =========================================================================

def save_phase3_report(
    report_dir: Path,
    url: str,
    param: str,
    payloads: List[str],
    result: FuzzResultLike,
) -> None:
    """
    Save Phase 3 amplification report to Markdown.

    Args:
        report_dir: Directory where the report file will be written.
        url: The target URL.
        param: The parameter being tested.
        payloads: List of amplified payloads that were sent.
        result: FuzzResult-like object with amplification statistics.
    """
    report_path = report_dir / "phase3_amplified.md"

    payload_listing = chr(10).join(payloads[:30])
    overflow_note = (
        f'... and {len(payloads) - 30} more'
        if len(payloads) > 30 else ""
    )

    content = f"""# Phase 3: AMPLIFICACION INTELIGENTE

**Target:** {url}
**Parameter:** {param}
**Timestamp:** {_now()}

## Phase 3.1: LLM Visual Generation
Generated visual payloads with "HACKED BY BUGTRACEAI" banner.

## Phase 3.2: Breakout Amplification
Multiplied visual payloads by breakouts.json prefixes.

## Phase 3.3: Second Bombardment Statistics
- Amplified Payloads: {len(payloads)}
- Total Requests: {result.total_requests}
- Duration: {result.duration_ms}ms
- Speed: {result.requests_per_second:.1f} req/s
- Reflections Found: {len(result.reflections)}

## Sample Amplified Payloads
```
{payload_listing}
{overflow_note}
```

## Reflections from Amplified Attack
| Payload | Context | Encoded | Suspicious |
|---------|---------|---------|------------|
"""
    for ref in result.reflections[:30]:
        suspicious = "!" if ref.is_suspicious else ""
        content += f"| `{ref.payload[:40]}...` | {ref.context} | {ref.encoded} | {suspicious} |\n"

    report_path.write_text(content)
    logger.debug(f"Phase 3 report saved to {report_path}")


# =========================================================================
# Phase 4: Validation results report
# =========================================================================

def save_phase4_report(
    report_dir: Path,
    finding: Optional[FindingLike],
    validation_method: str,
    exploit_url_fallback: str = "",
) -> None:
    """
    Save Phase 4 validation results report to Markdown.

    Args:
        report_dir: Directory where the report file will be written.
        finding: The confirmed XSSFinding, or None if no XSS was found.
        validation_method: Description of how the XSS was validated.
        exploit_url_fallback: Fallback exploit URL if finding.exploit_url
                              is empty (e.g. from build_attack_url).
    """
    report_path = report_dir / "phase4_results.md"

    if finding:
        exploit_url = finding.exploit_url or exploit_url_fallback

        content = f"""# Phase 4: VALIDATION RESULTS

**Timestamp:** {_now()}
**Status:** XSS CONFIRMED

## Finding Details
- **Parameter:** {finding.parameter}
- **Payload:**
```
{finding.payload}
```
- **Context:** {finding.context}
- **Validation Method:** {validation_method}
- **Confidence:** {finding.confidence:.0%}

## Evidence
```json
{json.dumps(finding.evidence, indent=2, default=str)}
```

## Exploit URL
```
{exploit_url}
```

## Reproduction Steps
1. Open the exploit URL in a browser
2. The "HACKED BY BUGTRACEAI" banner should appear at the top of the page
3. This confirms JavaScript execution in the user's browser context

"""
        if finding.screenshot_path:
            content += f"""
## Screenshot Evidence
![XSS Screenshot]({finding.screenshot_path})
"""
    else:
        content = f"""# Phase 4: VALIDATION RESULTS

**Timestamp:** {_now()}
**Status:** No XSS Confirmed

## Summary
Pipeline V2 completed all phases but could not confirm XSS execution.

### Possible Reasons:
1. Server escaping is effective
2. WAF blocked payloads
3. Context doesn't allow execution
4. Payloads need manual adjustment

### Recommendations:
1. Review phase2_analysis.md for escaping behavior
2. Check phase3_amplified.md for reflection contexts
3. Try manual testing with browser developer tools
"""

    report_path.write_text(content)
    logger.debug(f"Phase 4 report saved to {report_path}")


__all__ = [
    "get_snippet",
    "save_phase1_report",
    "save_phase2_report",
    "save_phase3_report",
    "save_phase4_report",
]
