"""
Mock Open Redirect Vulnerable Server

Provides endpoints for testing OpenRedirectAgent:
- /redirect?url= : Basic query parameter redirect (vulnerable)
- /redirect-safe?url= : Whitelist-validated redirect (safe)
- /goto/{path} : Path-based redirect (vulnerable)
- /js-redirect?next= : JavaScript-based redirect (vulnerable)
- /meta-redirect?url= : Meta refresh redirect (vulnerable)
- /header-only : Returns redirect header only

Usage:
    python -m tests.mocks.mock_openredirect_server
    # Runs on http://127.0.0.1:5080
"""

from aiohttp import web
import asyncio
from urllib.parse import urlparse

# Whitelist for safe redirect testing
SAFE_DOMAINS = ["example.com", "trusted.com", "localhost"]


async def vulnerable_redirect(request: web.Request) -> web.Response:
    """
    Vulnerable: Accepts any URL without validation.
    TEST CASE: Basic open redirect via query parameter.
    """
    url = request.query.get("url", "/")
    return web.HTTPFound(location=url)


async def safe_redirect(request: web.Request) -> web.Response:
    """
    Safe: Validates redirect URL against whitelist.
    TEST CASE: Should NOT be flagged as vulnerable.
    """
    url = request.query.get("url", "/")

    # Parse and validate
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()

        # Allow relative URLs
        if not host:
            return web.HTTPFound(location=url)

        # Check whitelist
        if any(host == domain or host.endswith(f".{domain}") for domain in SAFE_DOMAINS):
            return web.HTTPFound(location=url)

        # Reject external domains
        return web.Response(text="Invalid redirect URL", status=400)

    except Exception:
        return web.Response(text="Invalid URL format", status=400)


async def path_redirect(request: web.Request) -> web.Response:
    """
    Vulnerable: Path-based redirect without validation.
    TEST CASE: Open redirect via URL path.
    """
    path = request.match_info.get("path", "")
    # Decode if URL-encoded
    return web.HTTPFound(location=path)


async def js_redirect(request: web.Request) -> web.Response:
    """
    Vulnerable: JavaScript-based redirect with user input.
    TEST CASE: JavaScript window.location redirect.
    """
    next_url = request.query.get("next", "/")
    html = f"""<!DOCTYPE html>
<html>
<head><title>Redirecting...</title></head>
<body>
<script>
var url = "{next_url}";
window.location = url;
</script>
<noscript>
<p>JavaScript is required. <a href="{next_url}">Click here</a> to continue.</p>
</noscript>
</body>
</html>"""
    return web.Response(text=html, content_type="text/html")


async def meta_redirect(request: web.Request) -> web.Response:
    """
    Vulnerable: Meta refresh redirect with user input.
    TEST CASE: Meta refresh tag redirect.
    """
    url = request.query.get("url", "/")
    html = f"""<!DOCTYPE html>
<html>
<head>
<meta http-equiv="refresh" content="0;url={url}">
<title>Redirecting...</title>
</head>
<body>
<p>Redirecting to <a href="{url}">{url}</a>...</p>
</body>
</html>"""
    return web.Response(text=html, content_type="text/html")


async def header_only_redirect(request: web.Request) -> web.Response:
    """
    Vulnerable: Returns 302 with Location header.
    TEST CASE: HTTP header-based redirect detection.
    """
    url = request.query.get("url", "http://evil.com")
    return web.HTTPFound(location=url)


async def internal_redirect(request: web.Request) -> web.Response:
    """
    Safe: Redirects to internal path only.
    TEST CASE: Should NOT be flagged as vulnerable.
    """
    # Always redirects to internal path regardless of input
    return web.HTTPFound(location="/dashboard")


async def encoding_vulnerable(request: web.Request) -> web.Response:
    """
    Vulnerable: Naive filter bypass via encoding.
    TEST CASE: Encoding bypass techniques.
    """
    url = request.query.get("url", "/")

    # Naive filter: blocks "evil.com"
    if "evil.com" in url.lower():
        return web.Response(text="Blocked: evil domain", status=403)

    # But doesn't handle encoding - vulnerable!
    return web.HTTPFound(location=url)


async def whitelist_vulnerable(request: web.Request) -> web.Response:
    """
    Vulnerable: Naive whitelist check (contains).
    TEST CASE: Whitelist bypass via @ symbol.
    """
    url = request.query.get("url", "/")

    # Naive check: just checks if trusted.com is in the URL
    if "trusted.com" in url:
        return web.HTTPFound(location=url)

    return web.Response(text="URL not in whitelist", status=403)


async def index(request: web.Request) -> web.Response:
    """Index page listing all endpoints."""
    html = """<!DOCTYPE html>
<html>
<head><title>Mock Open Redirect Server</title></head>
<body>
<h1>Mock Open Redirect Server</h1>
<h2>Vulnerable Endpoints (should be detected)</h2>
<ul>
    <li><a href="/redirect?url=http://evil.com">/redirect?url=</a> - Basic open redirect</li>
    <li><a href="/goto/http://evil.com">/goto/{url}</a> - Path-based redirect</li>
    <li><a href="/js-redirect?next=http://evil.com">/js-redirect?next=</a> - JavaScript redirect</li>
    <li><a href="/meta-redirect?url=http://evil.com">/meta-redirect?url=</a> - Meta refresh redirect</li>
    <li><a href="/header-only?url=http://evil.com">/header-only?url=</a> - Header-only redirect</li>
    <li><a href="/encoding?url=%2f%2fevil.com">/encoding?url=</a> - Encoding bypass test</li>
    <li><a href="/whitelist?url=http://trusted.com@evil.com">/whitelist?url=</a> - Whitelist bypass test</li>
</ul>
<h2>Safe Endpoints (should NOT be detected)</h2>
<ul>
    <li><a href="/redirect-safe?url=http://trusted.com">/redirect-safe?url=</a> - Whitelist validated</li>
    <li><a href="/internal">/internal</a> - Internal redirect only</li>
</ul>
</body>
</html>"""
    return web.Response(text=html, content_type="text/html")


def create_app() -> web.Application:
    """Create the aiohttp application."""
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/redirect", vulnerable_redirect)
    app.router.add_get("/redirect-safe", safe_redirect)
    app.router.add_get("/goto/{path:.*}", path_redirect)
    app.router.add_get("/js-redirect", js_redirect)
    app.router.add_get("/meta-redirect", meta_redirect)
    app.router.add_get("/header-only", header_only_redirect)
    app.router.add_get("/internal", internal_redirect)
    app.router.add_get("/encoding", encoding_vulnerable)
    app.router.add_get("/whitelist", whitelist_vulnerable)
    return app


async def start_server(host: str = "127.0.0.1", port: int = 5080):
    """Start the mock server."""
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"Mock Open Redirect Server running on http://{host}:{port}")
    return runner


if __name__ == "__main__":
    async def main():
        runner = await start_server()
        try:
            while True:
                await asyncio.sleep(3600)
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            await runner.cleanup()

    asyncio.run(main())
