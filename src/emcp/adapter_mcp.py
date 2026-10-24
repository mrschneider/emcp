"""
EMCP Adapter: wraps legacy Anthropic MCP JSON-RPC servers with PlatSec and Token Budgeting.
"""

from __future__ import annotations
from typing import Any, Callable, Dict, Optional

from .constants import Capability, EmcpError
from .frame import EmcpFrame
from .server import EmcpServer


class McpLegacyAdapter(EmcpServer):
    """
    Exposes a legacy Anthropic MCP server as an EMCP service with Tool-PIN,
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

                # Create wrapper closure
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

        except Exception as e:
            # If discovery fails during init, server starts with empty tool table
            pass
