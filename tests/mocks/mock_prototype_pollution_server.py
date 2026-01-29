"""
Mock Prototype Pollution Server for Testing

Provides vulnerable and safe endpoints for testing PrototypePollutionAgent:
- Vulnerable: Object.assign, lodash-like merge, query param parsing
- Safe: Endpoints with prototype guards, immutable operations

Usage:
    python -m tests.mocks.mock_prototype_pollution_server
    # Runs on http://localhost:8089
"""

import asyncio
import json
from aiohttp import web

# Simulated global state (to demonstrate pollution persistence)
_global_config = {}


async def vulnerable_merge_endpoint(request: web.Request) -> web.Response:
    """
    Vulnerable endpoint: Simulates Object.assign with user input.
    VULNERABLE: Directly merges user JSON into config object.
    """
    global _global_config

    try:
        body = await request.json()

        # VULNERABLE: Direct merge without prototype guard
        # In real code: Object.assign(config, body)
        for key, value in body.items():
            if key == "__proto__" and isinstance(value, dict):
                # Simulate pollution by adding to global state
                _global_config.update(value)
            elif key == "constructor" and isinstance(value, dict):
                proto = value.get("prototype", {})
                _global_config.update(proto)
            else:
                _global_config[key] = value

        return web.json_response({
            "status": "merged",
            "config": _global_config,
        })

    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)


async def vulnerable_query_endpoint(request: web.Request) -> web.Response:
    """
    Vulnerable endpoint: Parses __proto__ from query parameters.
    VULNERABLE: Query string parsing allows prototype pollution.
    """
    global _global_config

    # Check for __proto__ in query params
    for key in request.query.keys():
        if "__proto__" in key or "constructor" in key:
            # Simulate pollution
            value = request.query.get(key)
            if value:
                _global_config["polluted"] = value

    return web.json_response({
        "status": "parsed",
        "config": _global_config,
    })


async def vulnerable_timing_endpoint(request: web.Request) -> web.Response:
    """
    Vulnerable endpoint: Simulates RCE timing attack.
    VULNERABLE: Executes sleep based on polluted property.
    """
    global _global_config

    try:
        body = await request.json()

        # Check for NODE_OPTIONS pollution (simulated)
        proto = body.get("__proto__", {})
        node_options = proto.get("NODE_OPTIONS", "")

        if "sleep" in node_options.lower() or "eval" in node_options.lower():
            # Simulate 5 second delay (RCE timing proof)
            await asyncio.sleep(5)
            return web.json_response({
                "status": "executed",
                "rce_confirmed": True,
            })

        # Normal merge
        for key, value in body.items():
            if key != "__proto__":
                _global_config[key] = value

        return web.json_response({
            "status": "merged",
            "config": _global_config,
        })

    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)


async def vulnerable_output_endpoint(request: web.Request) -> web.Response:
    """
    Vulnerable endpoint: Simulates RCE with command output.
    VULNERABLE: Returns simulated command output when polluted.
    """
    global _global_config

    try:
        body = await request.json()

        # Check for RCE payload
        proto = body.get("__proto__", {})
        env = proto.get("env", {})

        if "EVIL" in env:
            # Simulate command execution output
            return web.json_response({
                "status": "executed",
                "output": "uid=1000(node) gid=1000(node) groups=1000(node)",
                "rce_confirmed": True,
            })

        return web.json_response({
            "status": "merged",
            "config": _global_config,
        })

    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)


async def safe_immutable_endpoint(request: web.Request) -> web.Response:
    """
    Safe endpoint: Uses Object.create(null) pattern.
    SAFE: No prototype chain, pollution impossible.
    Filters exact and encoding bypass variants of __proto__/constructor.
    """
    try:
        body = await request.json()

        # Safe: Create object without prototype
        # In real code: Object.create(null)
        safe_config = {}
        for key, value in body.items():
            # Filter dangerous keys (exact match and encoding variants)
            key_lower = key.lower().replace("_", "")
            if any(dangerous in key_lower for dangerous in ["proto", "constructor", "prototype"]):
                # Skip dangerous keys (log but don't error - immutable pattern just ignores)
                continue
            safe_config[key] = value

        return web.json_response({
            "status": "safe",
            "config": safe_config,
        })

    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)


async def safe_frozen_endpoint(request: web.Request) -> web.Response:
    """
    Safe endpoint: Simulates Object.freeze pattern.
    SAFE: Prototype frozen, modification rejected.
    Rejects exact and encoding bypass variants of __proto__/constructor.
    """
    try:
        body = await request.json()

        # Check for pollution attempts (exact and encoding variants)
        for key in body.keys():
            key_lower = key.lower().replace("_", "")
            if any(dangerous in key_lower for dangerous in ["proto", "constructor", "prototype"]):
                return web.json_response({
                    "status": "rejected",
                    "error": "Prototype modification not allowed",
                }, status=400)

        return web.json_response({
            "status": "safe",
            "config": body,
        })

    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)


async def echo_endpoint(request: web.Request) -> web.Response:
    """Echo endpoint for testing JSON body acceptance."""
    try:
        body = await request.json()
        return web.json_response({"echo": body})
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)


async def reset_state(request: web.Request) -> web.Response:
    """Reset global state between tests."""
    global _global_config
    _global_config = {}
    return web.json_response({"status": "reset"})


def create_app() -> web.Application:
    """Create the mock server application."""
    app = web.Application()

    # Vulnerable endpoints
    app.router.add_post("/api/config/merge", vulnerable_merge_endpoint)
    app.router.add_get("/api/config/query", vulnerable_query_endpoint)
    app.router.add_post("/api/config/timing", vulnerable_timing_endpoint)
    app.router.add_post("/api/config/output", vulnerable_output_endpoint)

    # Safe endpoints
    app.router.add_post("/api/safe/immutable", safe_immutable_endpoint)
    app.router.add_post("/api/safe/frozen", safe_frozen_endpoint)

    # Utility endpoints
    app.router.add_post("/api/echo", echo_endpoint)
    app.router.add_post("/api/reset", reset_state)

    return app


async def start_server(host: str = "localhost", port: int = 8089):
    """Start the mock server."""
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"Mock Prototype Pollution server running on http://{host}:{port}")
    return runner


if __name__ == "__main__":
    async def main():
        runner = await start_server()
        try:
            while True:
                await asyncio.sleep(3600)
        except KeyboardInterrupt:
            await runner.cleanup()

    asyncio.run(main())
