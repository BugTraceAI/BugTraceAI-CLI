"""
File Upload Agent — I/O functions.

All functions in this module perform HTTP I/O, browser interaction, or LLM calls.
Dependencies are passed as explicit parameters.

Contents:
    - discover_upload_forms: Discover upload forms from HTML via browser
    - upload_file: Perform multipart HTTP upload
    - validate_execution: Check if uploaded file executes code
    - llm_get_strategy: Call LLM for upload bypass strategy
    - test_form: Orchestrate testing a single form with bypass loops

Author: BugtraceAI Team
Date: 2026-03-09
Version: 3.4.9-beta
"""

import logging
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup

from bugtrace.core.http_orchestrator import orchestrator, DestinationType

from bugtrace.agents.fileupload.core import (
    get_upload_strategy,
    create_upload_finding,
    build_llm_prompt,
)

logger = logging.getLogger(__name__)


async def discover_upload_forms(
    url: str,
    tested_upload_endpoints: Set[str],
) -> Tuple[List[Dict], Set[str]]:  # I/O
    """Discover upload forms from HTML via Playwright browser.

    Extracts all upload-related endpoints from:
    1. HTML forms with <input type="file">
    2. Accept attributes (allowed extensions)
    3. All form fields (hidden, text, etc.)
    4. Multiple file inputs in same form
    5. Drag-and-drop zones (data-upload, dropzone classes)

    Args:
        url: The page URL to scan.
        tested_upload_endpoints: Set of already-tested endpoint URLs (for dedup).

    Returns:
        Tuple of (forms_list, updated_tested_endpoints).
    """
    from bugtrace.tools.visual.browser import browser_manager

    updated_endpoints = set(tested_upload_endpoints)

    try:
        state = await browser_manager.capture_state(url)
        html = state.get("html", "")

        if not html:
            logger.warning(f"No HTML content from {url}")
            return [], updated_endpoints

        soup = BeautifulSoup(html, 'html.parser')
        forms: List[Dict] = []

        # Extract all forms with file inputs
        for form_idx, form in enumerate(soup.find_all('form')):
            file_inputs = form.find_all('input', {'type': 'file'})
            if not file_inputs:
                continue

            action = form.get('action', '')
            action_url = urljoin(url, action) if action else url

            # Dedup check at endpoint level
            if action_url in updated_endpoints:
                logger.info(f"Skipping duplicate endpoint: {action_url}")
                continue

            # Extract ALL form fields (not just file inputs)
            all_fields: Dict[str, str] = {}
            for tag in form.find_all(['input', 'textarea', 'select']):
                field_name = tag.get('name')
                if field_name:
                    input_type = tag.get('type', 'text').lower()
                    if input_type not in ['submit', 'button', 'reset']:
                        all_fields[field_name] = tag.get('value', '')

            # Extract file input details
            file_inputs_metadata: List[Dict] = []
            for file_input in file_inputs:
                file_inputs_metadata.append({
                    'name': file_input.get('name', 'file'),
                    'accept': file_input.get('accept', ''),
                    'multiple': file_input.has_attr('multiple'),
                    'required': file_input.has_attr('required'),
                })

            form_data = {
                'action': action_url,
                'method': form.get('method', 'POST').upper(),
                'enctype': form.get('enctype', 'multipart/form-data'),
                'id': form.get('id', f'form_{form_idx}'),
                'file_inputs': file_inputs_metadata,
                'all_fields': all_fields,
            }

            forms.append(form_data)
            updated_endpoints.add(action_url)

        # Also detect drag-and-drop zones (JavaScript upload)
        dropzones = soup.find_all(attrs={'data-upload': True})
        for dz in dropzones:
            upload_url = dz.get('data-upload')
            if upload_url and upload_url not in updated_endpoints:
                forms.append({
                    'action': urljoin(url, upload_url),
                    'method': 'POST',
                    'enctype': 'multipart/form-data',
                    'id': dz.get('id', 'dropzone'),
                    'file_inputs': [{
                        'name': 'file', 'accept': '',
                        'multiple': True, 'required': False,
                    }],
                    'all_fields': {},
                    'dropzone': True,
                })
                updated_endpoints.add(upload_url)

        logger.info(f"Discovered {len(forms)} upload forms/endpoints on {url}")
        for form in forms:
            file_count = len(form.get('file_inputs', []))
            field_count = len(form.get('all_fields', {}))
            logger.info(f"  -> {form['action']} ({file_count} file inputs, {field_count} fields)")

        return forms, updated_endpoints

    except Exception as e:
        logger.error(f"Discovery failed: {e}", exc_info=True)
        return [], updated_endpoints


async def upload_file(
    form: Dict,
    filename: str,
    content: str,
    content_type: str,
    base_url: str,
    cookies: List[Dict] = None,
    headers: Dict[str, str] = None,
) -> Tuple[bool, str, str]:  # I/O
    """Perform the actual HTTP multipart upload.

    Includes ALL form fields (hidden, text, etc.) to satisfy
    server-side validation that might reject incomplete forms.

    Args:
        form: The upload form metadata dict.
        filename: Name of the file to upload.
        content: File content as string.
        content_type: MIME type for the file.
        base_url: The base URL for predicting uploaded file location.
        cookies: List of cookie dicts to inject for authentication.
        headers: Dict of headers to inject for authentication.

    Returns:
        Tuple of (success, response_text, predicted_upload_url).
    """
    action_url = form['action']
    data = aiohttp.FormData()

    # Add ALL non-file fields first (hidden, text, etc.)
    all_fields = form.get('all_fields', {})
    for field_name, field_value in all_fields.items():
        data.add_field(field_name, field_value)

    # Add the file upload (use first file input)
    file_inputs = form.get('file_inputs', [])
    input_name = file_inputs[0]['name'] if file_inputs else 'file'

    data.add_field(
        input_name,
        content,
        filename=filename,
        content_type=content_type,
    )

    try:
        async with orchestrator.session(DestinationType.TARGET) as session:
            # Apply authentication (v3.4)
            if cookies:
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
                session.cookie_jar.update_cookies({"Cookie": cookie_str})
            if headers:
                session._default_headers.update(headers)
            
            async with session.post(action_url, data=data) as resp:
                text = await resp.text()
                predicted_url = urljoin(base_url, f"/uploads/{filename}")
                return resp.status in [200, 201], text, predicted_url
    except Exception as e:
        logger.debug(f"Upload operation failed: {e}")
        return False, "", ""


async def validate_execution(url: str, cookies: List[Dict] = None, headers: Dict[str, str] = None) -> bool:  # I/O
    """Check if the uploaded file actually executes code.

    Args:
        url: The URL of the uploaded file.
        cookies: List of cookie dicts to inject for authentication.
        headers: Dict of headers to inject for authentication.

    Returns:
        True if execution markers are found in the response.
    """
    try:
        async with orchestrator.session(DestinationType.TARGET) as session:
            # Apply authentication (v3.4)
            if cookies:
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
                session.cookie_jar.update_cookies({"Cookie": cookie_str})
            if headers:
                session._default_headers.update(headers)
            
            async with session.get(url) as resp:
                if resp.status == 404:
                    return False
                text = await resp.text()
                return "BT7331_SUCCESS" in text or "RCE_FLAG" in text
    except Exception as e:
        logger.debug(f"_validate_execution failed: {e}")
        return False


async def llm_get_strategy(
    form_data: Dict,
    system_prompt: str,
    previous_response: str = "",
) -> Dict:  # I/O
    """Call LLM to generate or refine the upload bypass strategy.

    Args:
        form_data: The upload form metadata dict.
        system_prompt: The agent's system prompt.
        previous_response: Response from previous failed attempt, or empty string.

    Returns:
        Dict with strategy keys (filename, payload_content, content_type, vulnerable).
    """
    sys_prompt, user_prompt = build_llm_prompt(form_data, system_prompt, previous_response)

    from bugtrace.core.llm_client import llm_client
    response = await llm_client.generate(
        prompt=user_prompt,
        system_prompt=sys_prompt,
        module_name="FILE_UPLOAD",
    )

    from bugtrace.utils.parsers import XmlParser
    tags = ["payload_content", "filename", "content_type", "vulnerable", "validation_url"]
    return XmlParser.extract_tags(response, tags)


async def test_form(
    form: Dict,
    base_url: str,
    system_prompt: str,
    max_bypass_attempts: int = 5,
    log_fn=None,
    cookies: List[Dict] = None,
    headers: Dict[str, str] = None,
) -> Optional[Dict]:  # I/O
    """Orchestrate testing for a specific form with bypass loops.

    Args:
        form: The upload form metadata dict.
        base_url: The base URL of the target.
        system_prompt: The agent's system prompt for LLM calls.
        max_bypass_attempts: Maximum bypass attempts (default 5).
        log_fn: Optional callable(message, level) for logging.
        cookies: List of cookie dicts to inject for authentication.
        headers: Dict of headers to inject for authentication.

    Returns:
        Finding dict if vulnerable, or None.
    """
    if log_fn:
        log_fn(f"Testing upload form: {form['id']}", "INFO")

    # Log accepted extensions if specified
    file_inputs = form.get('file_inputs', [])
    for fi in file_inputs:
        if fi.get('accept'):
            logger.info(f"  Accept filter: {fi['accept']}")

    previous_response = ""

    for attempt in range(max_bypass_attempts + 1):
        if attempt > 0 and log_fn:
            log_fn(f"Bypass attempt {attempt}/{max_bypass_attempts}", "INFO")

        # Phase 1: Call LLM for strategy (or bypass)
        strategy = await llm_get_strategy(form, system_prompt, previous_response)
        strategy_result = get_upload_strategy(attempt, strategy, form)

        if not strategy_result:
            break

        filename, payload, content_type, strategy_validation_url = strategy_result
        if log_fn:
            log_fn(f"Attempting upload: {filename} ({content_type})", "INFO")

        # Phase 2: Execute Upload
        success, response_text, predicted_url = await upload_file(
            form, filename, payload, content_type, base_url,
            cookies=cookies, headers=headers
        )
        previous_response = response_text

        # Override predicted URL with strategy validation URL if provided
        uploaded_url = strategy_validation_url if strategy_validation_url else predicted_url

        if success:
            # Phase 3: Validate Execution
            valid_execution = await validate_execution(uploaded_url, cookies=cookies, headers=headers)
            valid_upload = (
                f"Uploaded: {filename}" in response_text
                or "RCE_FLAG" in response_text
            )

            if valid_execution or valid_upload:
                if log_fn:
                    log_fn("File Upload Vulnerability CONFIRMED!", "SUCCESS")
                return create_upload_finding(
                    base_url, filename, uploaded_url, response_text, valid_execution
                )
        else:
            if log_fn:
                log_fn(
                    f"Upload blocked or failed. {len(response_text)} bytes returned.",
                    "WARN",
                )

    return None
