"""
Unit and integration test suite for EMCP (Enhanced Model Context Protocol).
"""

import unittest

from emcp import (
    Capability,
    EmcpClient,
    EmcpError,
    EmcpFrame,
    EmcpServer,
    McpLegacyAdapter,
    ToolConstraints,
    ToolIdentity,
    format_pin,
)


class TestEmcpCore(unittest.IsolatedAsyncioTestCase):
    def test_frame_serialization(self):
        """Header 48-byte packing and 4-slot parsing roundtrip."""
        frame = EmcpFrame(
            verb="tools/call",
            args={"query": "SELECT * FROM users"},
            caller_pin=0x1111_2222_3333_4444,
            target_pin=0x5555_6666_7777_8888,
            capabilities_mask=int(Capability.CAP_DATABASE_QUERY),
            constraints=ToolConstraints(token_budget=1500, timeout_ms=3000),
        )

        packed = frame.pack()
        self.assertGreater(len(packed), 48)

        unpacked = EmcpFrame.unpack(packed)
        self.assertEqual(unpacked.caller_pin, frame.caller_pin)
        self.assertEqual(unpacked.target_pin, frame.target_pin)
        self.assertEqual(unpacked.capabilities_mask, frame.capabilities_mask)
        self.assertEqual(unpacked.verb, "tools/call")
        self.assertEqual(unpacked.args, {"query": "SELECT * FROM users"})
        self.assertEqual(unpacked.constraints.token_budget, 1500)
        self.assertEqual(unpacked.constraints.timeout_ms, 3000)

    def test_tool_identity_and_pin(self):
        """Cryptographic Tool-PIN derivation."""
        ident = ToolIdentity.generate()
        self.assertIsInstance(ident.pin, int)
        self.assertGreater(ident.pin, 0)
        formatted = format_pin(ident.pin)
        self.assertTrue(formatted.startswith("0x"))
        self.assertEqual(len(formatted), 21)

    async def test_platsec_enforcement_on_tool_call(self):
        """PlatSec blocks execution if caller lacks required capabilities."""
        server = EmcpServer(
            name="file-server",
            allowed_capabilities=Capability.CAP_READ_FS | Capability.CAP_WRITE_FS,
        )

        executed = []

        @server.tool(name="delete_file", required_caps=Capability.CAP_WRITE_FS)
        def delete_file(path: str):
            executed.append(path)
            return {"deleted": True}

        # 1. Caller WITH write capability succeeds
        authorized_client = EmcpClient(allowed_capabilities=Capability.CAP_WRITE_FS)
        reply = await authorized_client.call_tool(server, "delete_file", {"path": "/tmp/a.txt"})
        self.assertEqual(reply.status, EmcpError.EMCP_SUCCESS)
        self.assertEqual(reply.args, {"deleted": True})
        self.assertEqual(executed, ["/tmp/a.txt"])

        # 2. Caller WITHOUT write capability is rejected at protocol layer
        unauthorized_client = EmcpClient(allowed_capabilities=Capability.CAP_READ_FS)
        reply = await unauthorized_client.call_tool(server, "delete_file", {"path": "/tmp/b.txt"})
        self.assertEqual(reply.status, EmcpError.EMCP_ERR_CAPABILITY_DENIED)
        # Handler was never called!
        self.assertEqual(len(executed), 1)

    async def test_token_budget_escrow_overflow(self):
        """Tool output exceeding token budget triggers EMCP_ERR_TOKEN_OVERFLOW."""
        server = EmcpServer(name="verbose-server", allowed_capabilities=Capability.NONE)

        @server.tool(name="generate_giant_payload")
        def giant_payload():
            # Produces ~5000 characters (~1250 tokens)
            return {"data": "X" * 5000}

        client = EmcpClient()

        # Call with tight token budget of 100 tokens
        reply = await client.call_tool(
            server,
            "generate_giant_payload",
            token_budget=100,
        )
        self.assertEqual(reply.status, EmcpError.EMCP_ERR_TOKEN_OVERFLOW)
        self.assertIn("exceeding envelope", reply.args["error"])

    async def test_mcp_legacy_adapter(self):
        """Wraps standard MCP JSON-RPC server and exposes as EMCP service."""

        def mock_jsonrpc(req: dict) -> dict:
            method = req.get("method")
            if method == "tools/list":
                return {
                    "result": {
                        "tools": [
                            {
                                "name": "sql_query",
                                "description": "Execute read-only SQL query",
                                "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}}},
                            }
                        ]
                    }
                }
            elif method == "tools/call":
                args = req.get("params", {}).get("arguments", {})
                return {"result": {"rows": [{"id": 1, "query": args.get("sql")}]}}
            return {"error": {"message": "unknown method"}}

        adapter = McpLegacyAdapter(
            name="legacy-sql",
            jsonrpc_dispatcher=mock_jsonrpc,
            tool_capabilities={"sql_query": Capability.CAP_DATABASE_QUERY},
            allowed_capabilities=Capability.CAP_DATABASE_QUERY,
        )

        client = EmcpClient(allowed_capabilities=Capability.CAP_DATABASE_QUERY)

        # 1. Discover tools
        tools_list = await client.list_tools(adapter)
        self.assertEqual(len(tools_list.get("tools", [])), 1)
        self.assertEqual(tools_list["tools"][0]["name"], "sql_query")

        # 2. Invoke tool
        reply = await client.call_tool(adapter, "sql_query", {"sql": "SELECT 1"})
        self.assertEqual(reply.status, EmcpError.EMCP_SUCCESS)
        self.assertEqual(reply.args, {"rows": [{"id": 1, "query": "SELECT 1"}]})


if __name__ == "__main__":
    unittest.main()
