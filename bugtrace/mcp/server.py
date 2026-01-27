"""MCP server for BugTraceAI AI assistant integration.

This module provides the Model Context Protocol (MCP) server that exposes
BugTraceAI's scanning and reporting capabilities to AI assistants via STDIO transport.

The server uses FastMCP for simple tool and resource registration.
Tools and resources are registered in separate modules (Plan 02 and Plan 03).
"""

import sys
import logging
from mcp.server.fastmcp import FastMCP
from loguru import logger

# Create the FastMCP server instance at module level
# This allows other modules (tools, resources) to import and register against it
mcp_server = FastMCP(
    "BugTraceAI",
    dependencies=["bugtrace"]
)


def run_mcp_server() -> None:
    """Start the MCP server with STDIO transport.

    CRITICAL: Configures all logging to stderr BEFORE any other imports.
    STDIO transport uses stdout for JSON-RPC communication, so stdout must be clean.

    Flow:
    1. Remove default loguru sink (stdout)
    2. Add stderr sink for loguru
    3. Configure stdlib logging to stderr
    4. Start MCP server on STDIO transport
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

    # Step 4: Register tools by importing the tools module
    # The @mcp_server.tool() decorators execute on import, registering tools
    import bugtrace.mcp.tools  # noqa: F401

    # Step 5: Start the MCP server with STDIO transport
    # This blocks until the server is shut down
    logger.info("Starting BugTraceAI MCP server on STDIO transport")
    mcp_server.run(transport="stdio")
