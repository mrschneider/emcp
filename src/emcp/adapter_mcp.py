"""
EMCP Adapter: wraps legacy Anthropic MCP JSON-RPC servers with PlatSec and Token Budgeting.
Supports in-memory dispatchers and real external OS processes over stdio (pipes).
"""

from __future__ import annotations
import json
import subprocess
import threading
from typing import Any, Callable, Dict, List, Optional

from .constants import Capability, EmcpError
from .server import EmcpServer


class McpLegacyAdapter(EmcpServer):
    """
    Exposes an in-memory legacy Anthropic MCP server as an EMCP service with Tool-PIN,
    PlatSec capability enforcement, and Token Budget Escrow.
    """

    def __init__(
        self,
        name: str,
        jsonrpc_dispatcher: Callable[[Dict[str, Any]], Any],
        tool_capabilities: Optional[Dict[str, Capability]] = None,
        allowed_capabilities: Capability = Capability.NONE,
    ):
        super().__init__(name=name, allowed_capabilities=allowed_capabilities)
        self.dispatcher = jsonrpc_dispatcher
        self.tool_capabilities = tool_capabilities or {}
        self._import_mcp_tools()

    def _import_mcp_tools(self) -> None:
        """Discovers tools exposed by the underlying MCP JSON-RPC server."""
        try:
            req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
            resp = self.dispatcher(req)
            tools = resp.get("result", {}).get("tools", [])
            for t in tools:
                t_name = t["name"]
                t_desc = t.get("description", "")
                t_schema = t.get("inputSchema", {})
                req_caps = self.tool_capabilities.get(t_name, Capability.NONE)

                def make_handler(name: str):
                    def handler(**kwargs):
                        call_req = {
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/call",
                            "params": {"name": name, "arguments": kwargs},
                        }
                        call_resp = self.dispatcher(call_req)
                        if "error" in call_resp:
                            raise RuntimeError(call_resp["error"].get("message", "MCP error"))
                        return call_resp.get("result", {})

                    return handler

                self.tool(
                    name=t_name,
                    description=t_desc,
                    required_caps=req_caps,
                    input_schema=t_schema,
                )(make_handler(t_name))

        except Exception:
            pass


class McpStdioProcessAdapter(EmcpServer):
    """
    Spawns an actual Anthropic MCP server executable as a child OS process over stdio pipes.
    Executes the JSON-RPC 2.0 handshake, discovers tools, and wraps execution in PlatSec
    capability bitmasks and Token Budget Escrow.
    """

    def __init__(
        self,
        name: str,
        command: List[str],
        tool_capabilities: Optional[Dict[str, Capability]] = None,
        allowed_capabilities: Capability = Capability.NONE,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ):
        super().__init__(name=name, allowed_capabilities=allowed_capabilities)
        self.command = command
        self.tool_capabilities = tool_capabilities or {}
        self._lock = threading.Lock()
        self._req_id = 0

        # Launch MCP process
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=cwd,
            env=env,
        )

        self._handshake()
        self._import_tools()

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _send_jsonrpc(self, method: str, params: Optional[Dict[str, Any]] = None, is_notification: bool = False) -> Optional[Dict[str, Any]]:
        with self._lock:
            if not self.proc or self.proc.poll() is not None:
                raise RuntimeError("MCP child process is not running")

            req: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
            if not is_notification:
                req["id"] = self._next_id()
            if params is not None:
                req["params"] = params

            line = json.dumps(req) + "\n"
            if not self.proc.stdin:
                raise RuntimeError("Process stdin unavailable")
            self.proc.stdin.write(line)
            self.proc.stdin.flush()

            if is_notification:
                return None

            if not self.proc.stdout:
                raise RuntimeError("Process stdout unavailable")

            resp_line = self.proc.stdout.readline()
            if not resp_line:
                raise RuntimeError("MCP process closed stdout unexpectedly")

            return json.loads(resp_line.strip())

    def _handshake(self) -> None:
        """Executes official Anthropic MCP protocol initialization handshake."""
        resp = self._send_jsonrpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "emcp-bridge", "version": "0.1.0"},
            },
        )
        if not resp or "result" not in resp:
            raise RuntimeError(f"MCP handshake failed: {resp}")

        self._send_jsonrpc("notifications/initialized", is_notification=True)

    def _import_tools(self) -> None:
        """Queries tools/list over stdio and binds each tool into EMCP."""
        resp = self._send_jsonrpc("tools/list", {})
        if not resp:
            return

        tools = resp.get("result", {}).get("tools", [])
        for t in tools:
            t_name = t["name"]
            t_desc = t.get("description", "")
            t_schema = t.get("inputSchema", {})
            req_caps = self.tool_capabilities.get(t_name, Capability.NONE)

            def make_handler(name: str):
                def handler(**kwargs):
                    call_resp = self._send_jsonrpc(
                        "tools/call",
                        {"name": name, "arguments": kwargs},
                    )
                    if not call_resp or "error" in call_resp:
                        err_msg = call_resp["error"].get("message", "MCP error") if call_resp else "Empty response"
                        raise RuntimeError(err_msg)

                    res = call_resp.get("result", {})
                    # If MCP returns standard content array, extract text
                    if "content" in res and isinstance(res["content"], list):
                        texts = [item.get("text", "") for item in res["content"] if item.get("type") == "text"]
                        if texts:
                            return {"text": "\n".join(texts)}
                    return res

                return handler

            self.tool(
                name=t_name,
                description=t_desc,
                required_caps=req_caps,
                input_schema=t_schema,
            )(make_handler(t_name))

    def close(self) -> None:
        """Terminates the underlying child process."""
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=1.0)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
