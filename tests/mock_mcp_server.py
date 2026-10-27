#!/usr/bin/env python3
"""
Mock standalone Anthropic MCP JSON-RPC stdio server for portability testing.
"""

import json
import sys
import time


def handle_request(req: dict) -> dict:
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-mcp-server", "version": "1.0.0"},
            },
        }

    if method == "notifications/initialized":
        return {}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "query_database",
                        "description": "Executes read-only SQL query",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"sql": {"type": "string"}},
                            "required": ["sql"],
                        },
                    },
                    {
                        "name": "drop_database",
                        "description": "Destructive drop database operation",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"db_name": {"type": "string"}},
                            "required": ["db_name"],
                        },
                    },
                    {
                        "name": "fetch_huge_log",
                        "description": "Returns a large payload for token budget testing",
                        "inputSchema": {"type": "object"},
                    },
                    {
                        "name": "slow_tool",
                        "description": "Sleeps 50ms to exercise pipelining",
                        "inputSchema": {"type": "object"},
                    },
                ]
            },
        }

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})

        if name == "slow_tool":
            # Deterministic delay to exercise pipelining (out-of-order replies)
            time.sleep(0.05)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": f"slow:{args.get('n', 0)}"}]},
            }

        if name == "query_database":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {"type": "text", "text": json.dumps({"rows": [{"id": 42, "status": "active"}]})}
                    ]
                },
            }

        if name == "drop_database":
            # If this executes, write a flag file or print to stderr to prove execution
            sys.stderr.write(f"CRITICAL: drop_database executed on {args.get('db_name')}\n")
            sys.stderr.flush()
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": "database dropped"}]},
            }

        if name == "fetch_huge_log":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": "CRITICAL_LOG_ENTRY_" * 1000}]  # ~19,000 chars
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Unknown tool: {name}"},
        }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


async def main():
    import asyncio
    import threading

    loop = asyncio.get_running_loop()
    write_lock = threading.Lock()
    pending = set()
    stdin = sys.stdin

    def worker(req: dict):
        try:
            resp = handle_request(req)
        except Exception as e:
            sys.stderr.write(f"Error handling line: {e}\n")
            sys.stderr.flush()
            return
        if resp:  # Notifications return empty dict
            with write_lock:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()

    while True:
        line = await loop.run_in_executor(None, stdin.readline)
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            sys.stderr.write(f"Error handling line: {e}\n")
            sys.stderr.flush()
            continue
        # Each request runs in a worker thread so slow tools don't block
        # the reader loop: this exercises the adapter's out-of-order,
        # id-matched pipelining the way a real MCP server would.
        fut = asyncio.ensure_future(
            loop.run_in_executor(None, worker, req)
        )
        pending.add(fut)
        fut.add_done_callback(pending.discard)

    if pending:
        await asyncio.gather(*pending)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
