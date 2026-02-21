"""MCP server for BugTraceAI AI assistant integration.

This module provides the Model Context Protocol (MCP) server that exposes
BugTraceAI's scanning and reporting capabilities to AI assistants.

Supports two transports:
- STDIO (default): For local AI assistant integration (Claude Code, Cursor, etc.)
- SSE (--sse flag): For remote/network access (OpenClaw, remote MCP clients)

The server uses FastMCP for simple tool and resource registration.
Tools and resources are registered in separate modules (Plan 02 and Plan 03).
"""

import sys
import logging
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from loguru import logger

# Create the FastMCP server instance at module level
# This allows other modules (tools, resources) to import and register against it
mcp_server = FastMCP(
    "BugTraceAI",
    dependencies=["bugtrace"]
)

# LAN-accessible transport security settings for SSE mode
_LAN_TRANSPORT_SECURITY = TransportSecuritySettings(
    enable_dns_rebinding_protection=False,
)


def run_mcp_server(
    transport: str = "stdio",
    host: str = "0.0.0.0",
    port: int = 8001
) -> None:
    """Start the MCP server with the specified transport.

    CRITICAL: Configures all logging to stderr BEFORE any other imports.
    STDIO transport uses stdout for JSON-RPC communication, so stdout must be clean.

    Args:
        transport: Transport protocol - "stdio" (default) or "sse" (HTTP/SSE for network access)
        host: Host to bind SSE server to (default: 0.0.0.0, only used with SSE)
        port: Port for SSE server (default: 8001, only used with SSE)
    """
    # Step 1: Remove default loguru sink (which outputs to stdout)
    logger.remove()

    # Step 2: Add stderr sink for all loguru logging
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level="INFO"
    )

    # Step 3: Configure Python stdlib logging to stderr
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Step 4: Register tools and resources by importing modules
    # The @mcp_server.tool() and @mcp_server.resource() decorators execute on import
    import bugtrace.mcp.tools      # noqa: F401
    import bugtrace.mcp.resources  # noqa: F401
    import bugtrace.mcp.explain    # noqa: F401

    # Step 5: Configure transport and start the MCP server
    if transport == "sse":
        mcp_server.settings.host = host
        mcp_server.settings.port = port
        mcp_server.settings.transport_security = _LAN_TRANSPORT_SECURITY
        logger.info(f"Starting BugTraceAI MCP server on SSE transport at http://{host}:{port}/sse")
    else:
        logger.info("Starting BugTraceAI MCP server on STDIO transport")

    mcp_server.run(transport=transport)
