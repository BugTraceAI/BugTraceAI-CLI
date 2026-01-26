# Model Context Protocol (MCP) Integration - Feature Tasks

## Feature Overview
Add MCP support for standardized tool ecosystem and community extensions.

**Why**: Standard protocol for tool integration, community marketplace
**Competitor Gap**: CAI (MCP stdio/HTTP), Decepticon (LangGraph + MCP)
**Phase**: 2 - Competitive Parity
**Duration**: 2 weeks
**Effort**: $15k

---

## 🔵 Core MCP Features

### FEATURE-051: Add MCP Client Support
**Complexity**: 🔵 MEDIUM (3 days)

```python
# Install: pip install mcp
from mcp import Client, StdioServerParameters

class MCPToolClient:
    def __init__(self):
        self.clients = {}

    async def connect_server(self, name, command):
        server = StdioServerParameters(
            command=command,
            args=[],
            env=os.environ
        )

        client = Client(server)
        await client.connect()
        self.clients[name] = client

        # Discover tools
        tools = await client.list_tools()
        logger.info(f"MCP server {name} provides {len(tools)} tools")

        return tools

# Usage
mcp_client = MCPToolClient()
await mcp_client.connect_server("sqlmap", ["python", "mcp_servers/sqlmap_server.py"])
```

### FEATURE-052: Convert SQLMap to MCP Tool
**Complexity**: 🔵 MEDIUM (3 days)

```python
# mcp_servers/sqlmap_server.py
from mcp.server import Server
from mcp.types import Tool, TextContent

server = Server("sqlmap-mcp")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="test_sqli",
            description="Test URL for SQL injection",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "POST"]},
                    "data": {"type": "string"}
                },
                "required": ["url"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name, arguments):
    if name == "test_sqli":
        result = await run_sqlmap(
            url=arguments["url"],
            method=arguments.get("method", "GET"),
            data=arguments.get("data")
        )
        return [TextContent(type="text", text=json.dumps(result))]
```

### FEATURE-053: Convert Nuclei to MCP Tool
**Complexity**: 🔵 MEDIUM (2 days)

```python
# mcp_servers/nuclei_server.py
@server.call_tool()
async def call_tool(name, arguments):
    if name == "nuclei_scan":
        result = subprocess.run(
            ["nuclei", "-u", arguments["url"], "-t", arguments["templates"], "-json"],
            capture_output=True
        )
        return [TextContent(type="text", text=result.stdout.decode())]
```

### FEATURE-054: Agent-Side MCP Tool Discovery
**Complexity**: 🔵 MEDIUM (3 days)

```python
# bugtrace/agents/base_agent.py
class BaseAgent:
    async def discover_tools(self):
        # Discover all available MCP tools
        self.available_tools = []

        for server_name, client in mcp_client.clients.items():
            tools = await client.list_tools()
            self.available_tools.extend(tools)

        logger.info(f"Agent {self.name} has access to {len(self.available_tools)} MCP tools")

    async def use_tool(self, tool_name, arguments):
        # Dynamically call MCP tool
        for server_name, client in mcp_client.clients.items():
            try:
                result = await client.call_tool(tool_name, arguments)
                return result
            except:
                continue

        raise ValueError(f"Tool {tool_name} not found")
```

### FEATURE-055: LLM-Driven Tool Selection
**Complexity**: 🟠 COMPLEX (1 week)

```python
async def analyze_with_tools(self, url):
    # LLM decides which tools to use
    prompt = f"""
    Target URL: {url}

    Available tools:
    {json.dumps([tool.dict() for tool in self.available_tools], indent=2)}

    Which tools should I use to test this URL? Return JSON:
    [
      {{"tool": "test_sqli", "arguments": {{"url": "{url}", "method": "GET"}}}},
      {{"tool": "test_xss", "arguments": {{"url": "{url}", "parameter": "search"}}}}
    ]
    """

    response = await llm_client.generate(prompt, "tool_selection")
    tool_calls = json.loads(response)

    # Execute tools
    results = []
    for tool_call in tool_calls:
        result = await self.use_tool(tool_call["tool"], tool_call["arguments"])
        results.append(result)

    return results
```

---

## 🟠 Advanced MCP Features

### FEATURE-056: HTTP MCP Server Support
**Complexity**: 🔵 MEDIUM (2 days)

```python
# Connect to HTTP MCP servers
from mcp import HttpServerParameters

server = HttpServerParameters(
    url="https://mcp-server.example.com",
    headers={"Authorization": f"Bearer {settings.MCP_API_KEY}"}
)

client = Client(server)
await client.connect()
```

### FEATURE-057: MCP Tool Marketplace Integration
**Complexity**: 🟠 COMPLEX (1 week)

```python
# Browse and install community MCP tools
class MCPMarketplace:
    def list_tools(self):
        # Fetch from marketplace API
        response = requests.get("https://mcp-marketplace.com/api/tools")
        return response.json()

    def install_tool(self, tool_id):
        # Download and configure MCP server
        tool_config = self.get_tool_config(tool_id)
        self.download_server(tool_config["server_url"])
        self.add_to_config(tool_config)

# Usage
marketplace = MCPMarketplace()
tools = marketplace.list_tools()
marketplace.install_tool("community/burp-scanner")
```

### FEATURE-058: Custom MCP Tool SDK
**Complexity**: 🔵 MEDIUM (3 days)

```python
# bugtrace/mcp/tool_builder.py
class MCPToolBuilder:
    def create_tool(self, name, description, handler):
        @server.call_tool()
        async def call_tool(tool_name, arguments):
            if tool_name == name:
                return await handler(arguments)

        return Tool(
            name=name,
            description=description,
            inputSchema=self._generate_schema(handler)
        )

# Example: Create custom fuzzer tool
async def custom_fuzzer(args):
    return {"result": "fuzzing complete"}

builder = MCPToolBuilder()
tool = builder.create_tool("custom_fuzzer", "My custom fuzzer", custom_fuzzer)
```

---

## 🟢 Nice-to-Have

### FEATURE-059: MCP Tool Caching
**Complexity**: 🟣 QUICK (1 day)

```python
# Cache tool results to avoid redundant calls
class MCPToolCache:
    def __init__(self):
        self.cache = {}

    async def call_with_cache(self, tool_name, arguments):
        cache_key = f"{tool_name}:{json.dumps(arguments)}"

        if cache_key in self.cache:
            return self.cache[cache_key]

        result = await mcp_client.call_tool(tool_name, arguments)
        self.cache[cache_key] = result
        return result
```

### FEATURE-060: MCP Tool Metrics
**Complexity**: 🟣 QUICK (1 day)

```python
# Track MCP tool usage
mcp_tool_calls = Counter('mcp_tool_calls_total', 'MCP tool calls', ['tool_name', 'status'])

async def call_tool_with_metrics(tool_name, arguments):
    try:
        result = await mcp_client.call_tool(tool_name, arguments)
        mcp_tool_calls.labels(tool_name=tool_name, status='success').inc()
        return result
    except Exception as e:
        mcp_tool_calls.labels(tool_name=tool_name, status='error').inc()
        raise
```

### FEATURE-061: MCP Server Health Checks
**Complexity**: 🟣 QUICK (1 day)

```python
async def check_mcp_servers():
    for name, client in mcp_client.clients.items():
        try:
            await client.ping()
            logger.info(f"MCP server {name}: healthy")
        except:
            logger.error(f"MCP server {name}: unhealthy")
```

---

## Summary

**Total Tasks**: 11
- 🟣 Quick: 3 (3 days)
- 🔵 Medium: 6 (16 days)
- 🟠 Complex: 2 (14 days)

**Estimated Effort**: 2 weeks
**Investment**: ~$15k

**Competitive Gap Closed**: CAI (MCP integration), Decepticon (LangGraph + MCP)

**MCP Servers to Create**:
1. sqlmap_server.py
2. nuclei_server.py
3. burp_scanner_server.py (if Burp integration)
4. custom_fuzzer_server.py
5. waf_tester_server.py

**Configuration**:
```yaml
[MCP]
ENABLED=true
SERVERS=sqlmap,nuclei,custom_fuzzer

[MCP_SERVER_SQLMAP]
COMMAND=python
ARGS=mcp_servers/sqlmap_server.py

[MCP_SERVER_NUCLEI]
COMMAND=python
ARGS=mcp_servers/nuclei_server.py
```
