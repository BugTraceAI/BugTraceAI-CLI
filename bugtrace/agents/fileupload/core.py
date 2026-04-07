"""
File Upload Agent — PURE functions.

All functions in this module are free functions (no self), side-effect free,
and receive all data as explicit parameters.

Contents:
    - get_upload_strategy: Extract upload strategy from LLM response or fallback
    - create_upload_finding: Build finding dict for successful upload
    - extract_form_metadata: Extract rich metadata from a form dict
    - build_llm_prompt: Build LLM prompt for upload bypass strategy
"""

from typing import Dict, List, Optional, Tuple


def get_upload_strategy(
    attempt: int,
    strategy: Optional[Dict],
    form: Dict,
) -> Optional[Tuple[str, str, str, Optional[str]]]:  # PURE
    """Get upload strategy from LLM response or fallback.

    Args:
        attempt: The current bypass attempt number (0-based).
        strategy: LLM-generated strategy dict, or None.
        form: The upload form metadata dict.

    Returns:
        Tuple of (filename, payload_content, content_type, validation_url), or None to stop.
    """
    if not strategy or not strategy.get('vulnerable') == 'true':
        if attempt == 0:
            # Fallback strategy for Level 0 if LLM fails or says no
            return (
                'BT7331_RCE_payload.php',
                '<?php echo "BT7331_SUCCESS"; ?>',
                'application/x-php',
                None,
            )
        return None

    filename = strategy.get('filename', 'rce.php')
    payload = strategy.get('payload_content', '<?php echo "BT7331_SUCCESS"; ?>')
    content_type = strategy.get('content_type', 'application/x-php')
    validation_url = strategy.get('validation_url')
    return (filename, payload, content_type, validation_url)


def create_upload_finding(
    url: str,
    filename: str,
    uploaded_url: str,
    response_text: str,
    valid_execution: bool,
) -> Dict:  # PURE
    """Create finding dictionary for successful upload.

    Args:
        url: The base URL where the upload was tested.
        filename: The uploaded filename.
        uploaded_url: The predicted URL of the uploaded file.
        response_text: The response text from the upload.
        valid_execution: Whether the uploaded file was confirmed to execute.

    Returns:
        Finding dictionary with all required fields.
    """
    evidence = f"Response confirms upload: {response_text[:100]}"
    if "RCE_FLAG" in response_text:
        evidence = f"RCE Flag Found in response: {response_text}"

    method_desc = "RCE via Execution" if valid_execution else "Arbitrary File Upload (Name Trigger)"
    return {
        "type": "File Upload / RCE",
        "vulnerability": "Unrestricted File Upload / RCE",
        "url": url,
        "exploit_url": uploaded_url,
        "filename": filename,
        "confidence": 1.0,
        "method": method_desc,
        "evidence": evidence,
        "validated": True,
        "severity": "CRITICAL",
        "status": "VALIDATED_CONFIRMED",
        "description": (
            f"Unrestricted file upload vulnerability allowing Remote Code Execution. "
            f"Uploaded malicious file '{filename}' was successfully executed on the server. "
            f"Method: {method_desc}"
        ),
        "reproduction": (
            f"# Upload malicious file:\n"
            f"curl -X POST '{url}' -F 'file=@{filename}'\n"
            f"# Access uploaded file:\n"
            f"curl '{uploaded_url}'"
        ),
    }


def extract_form_metadata(form: Dict) -> Dict[str, any]:  # PURE
    """Extract rich metadata from a form dict for logging/display.

    Args:
        form: The upload form dict.

    Returns:
        Dict with file_count, field_count, accept_filters, and action.
    """
    file_inputs = form.get('file_inputs', [])
    all_fields = form.get('all_fields', {})
    accept_filters = [fi.get('accept', 'none') for fi in file_inputs]

    return {
        "file_count": len(file_inputs),
        "field_count": len(all_fields),
        "accept_filters": accept_filters,
        "action": form.get('action', ''),
    }


def build_llm_prompt(
    form_data: Dict,
    system_prompt: str,
    previous_response: str = "",
) -> Tuple[str, str]:  # PURE
    """Build LLM prompt for upload bypass strategy.

    Args:
        form_data: The upload form metadata dict.
        system_prompt: The agent's system prompt.
        previous_response: Response from previous failed attempt, or empty string.

    Returns:
        Tuple of (system_prompt, user_prompt).
    """
    file_inputs = form_data.get('file_inputs', [])
    accept_filters = [fi.get('accept', 'any') for fi in file_inputs]
    all_fields = form_data.get('all_fields', {})

    user_prompt = f"""Analyze this upload form and generate a bypass for RCE:

Form Action: {form_data['action']}
Method: {form_data['method']}
Enctype: {form_data.get('enctype', 'multipart/form-data')}

File Inputs ({len(file_inputs)}):
{chr(10).join([f"  - {fi['name']} (accept: {fi.get('accept', 'any')}, multiple: {fi.get('multiple', False)})" for fi in file_inputs])}

Other Form Fields ({len(all_fields)}):
{chr(10).join([f"  - {name}: {value}" for name, value in list(all_fields.items())[:10]])}

Accept Filters: {', '.join(accept_filters) if accept_filters else 'No restrictions detected'}
"""

    if previous_response:
        user_prompt += (
            f"\n\nPrevious attempt failed with this response:\n"
            f"{previous_response[:2000]}"
            f"\n\nTry a different bypass (e.g. extension change, content-type spoofing, "
            f"magic bytes, double extensions)."
        )

    return (system_prompt, user_prompt)
