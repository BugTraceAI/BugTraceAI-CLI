# Chrome DevTools Protocol (CDP) Integration

> ✅ **STATUS: IMPLEMENTED** (2026-01-08) - CDP client is now available in `bugtrace/core/cdp_client.py` for more reliable XSS validation.

## Overview

The **Chrome DevTools MCP** (Model Context Protocol) is Google's official server that enables AI agents to control and inspect Chrome browsers via CDP (Chrome DevTools Protocol). This document outlines how to integrate it with BugTraceAI for enhanced browser automation.

---

## Current State: Playwright

Currently, BugTraceAI uses **Playwright** for browser automation:

```python
# bugtrace/tools/visual/browser.py
from playwright.async_api import async_playwright

class BrowserManager:
    async def verify_xss(self, url):
        async with self.get_page() as page:
            await page.goto(url)
            await page.screenshot(path=screenshot_path)
```

**Pros:**

- Reliable, well-tested
- Good async support
- Built-in accessibility tree

**Cons:**

- Limited real-time debugging
- No console/network inspection during automation
- Separate from standard MCP tools

---

## Future State: Chrome DevTools MCP

The Chrome DevTools MCP provides standardized tools that AI agents can use:

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `navigate_page` | Navigate to a URL |
| `click_element` | Click on page elements |
| `type_text` | Type text into inputs |
| `take_screenshot` | Capture screenshots |
| `get_console_logs` | Get browser console output |
| `get_network_logs` | Inspect network requests |
| `run_javascript` | Execute JS in page context |
| `performance_start_trace` | Start performance profiling |

### Installation

```bash
# Install Chrome DevTools MCP server
npm install -g @anthropic/chrome-devtools-mcp

# Or use npx
npx @anthropic/chrome-devtools-mcp
```

### MCP Configuration

Add to your MCP config (`.mcp/config.json`):

```json
{
  "servers": {
    "chrome-devtools": {
      "command": "npx",
      "args": ["@anthropic/chrome-devtools-mcp"],
      "env": {
        "CHROME_PATH": "/usr/bin/google-chrome"
      }
    }
  }
}
```

---

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      ReportValidator                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Browser Automation Router                                      │
│   ├─ If MCP available → Use Chrome DevTools MCP                 │
│   └─ Else → Use Playwright (fallback)                           │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Chrome DevTools MCP                      Playwright            │
│   ├─ navigate_page                         ├─ page.goto()        │
│   ├─ take_screenshot                       ├─ page.screenshot()  │
│   ├─ run_javascript                        ├─ page.evaluate()    │
│   ├─ get_console_logs                      └─ (limited)          │
│   └─ get_network_logs                                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Proposed Implementation

### 1. MCP Browser Client

```python
# bugtrace/tools/mcp/chrome_devtools.py

from typing import Optional, Dict, Any
import json

class ChromeDevToolsMCP:
    """
    Browser automation via Chrome DevTools MCP.
    
    This provides richer debugging than Playwright alone,
    including network inspection, console logs, and performance traces.
    """
    
    def __init__(self, mcp_client):
        self.mcp = mcp_client
        
    async def navigate(self, url: str) -> Dict[str, Any]:
        """Navigate to URL and return page info."""
        return await self.mcp.call_tool("navigate_page", {"url": url})
    
    async def screenshot(self, path: str) -> str:
        """Take screenshot and save to path."""
        result = await self.mcp.call_tool("take_screenshot", {})
        # Save base64 image
        with open(path, "wb") as f:
            f.write(base64.b64decode(result["image"]))
        return path
    
    async def run_javascript(self, code: str) -> Any:
        """Run JavaScript in page context."""
        return await self.mcp.call_tool("run_javascript", {"code": code})
    
    async def get_console_logs(self) -> list:
        """Get all console logs since last call."""
        return await self.mcp.call_tool("get_console_logs", {})
    
    async def get_network_logs(self) -> list:
        """Get all network requests since last call."""
        return await self.mcp.call_tool("get_network_logs", {})
```

### 2. Enhanced Validation with Network Inspection

```python
async def validate_ssrf_with_mcp(self, url: str, payload: str):
    """
    SSRF validation using network inspection.
    
    This is something Playwright can't easily do - 
    we can monitor outgoing requests from the browser.
    """
    # Navigate to trigger SSRF
    await self.mcp.navigate(f"{url}?target={payload}")
    
    # Check network logs for SSRF attempt
    network_logs = await self.mcp.get_network_logs()
    
    for request in network_logs:
        if payload in request.get("url", ""):
            return {"validated": True, "evidence": f"SSRF triggered: {request}"}
    
    return {"validated": False}
```

### 3. Console-Based XSS Detection

```python
async def validate_xss_with_console(self, url: str):
    """
    XSS validation using console monitoring.
    
    Instead of hooking alert(), we monitor console for XSS markers.
    """
    await self.mcp.navigate(url)
    
    # Check for our XSS proof in console
    logs = await self.mcp.get_console_logs()
    
    for log in logs:
        if "BUGTRACE_XSS" in log.get("message", ""):
            return {"validated": True, "evidence": log["message"]}
    
    return {"validated": False}
```

---

## Benefits of MCP Integration

| Feature | Playwright | Chrome DevTools MCP |
|---------|------------|---------------------|
| Navigation | ✅ | ✅ |
| Screenshots | ✅ | ✅ |
| Console Logs | ⚠️ Limited | ✅ Full access |
| Network Logs | ⚠️ Limited | ✅ Full access |
| Performance | ⚠️ Manual | ✅ Built-in traces |
| CDP Direct | ⚠️ Indirect | ✅ Native |
| AI Agent Ready | ⚠️ Custom | ✅ MCP Standard |

---

## Migration Path

1. **Phase 1** (Current): Playwright-based validation with Vision LLM
2. **Phase 2**: Add MCP client alongside Playwright
3. **Phase 3**: Use MCP for enhanced features (network/console)
4. **Phase 4**: Gradually migrate core automation to MCP

---

## Configuration

Add to `bugtraceaicli.conf`:

```ini
# Browser Automation Settings
BROWSER_BACKEND=playwright  # Options: playwright, mcp, auto
MCP_CHROME_DEVTOOLS_ENABLED=false
MCP_CHROME_PATH=/usr/bin/google-chrome
```

---

## Resources

- [Chrome DevTools MCP GitHub](https://github.com/anthropics/mcp-servers/tree/main/chrome-devtools)
- [Model Context Protocol Spec](https://modelcontextprotocol.io/)
- [Playwright MCP (Microsoft)](https://github.com/anthropics/mcp-servers/tree/main/playwright)
- [Chrome DevTools Protocol Docs](https://chromedevtools.github.io/devtools-protocol/)

---

**Created**: 2026-01-07
**Status**: Planned
**Priority**: Medium
