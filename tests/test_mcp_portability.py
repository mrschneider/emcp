"""
End-to-end integration and portability test for Anthropic MCP stdio servers via McpStdioProcessAdapter.
"""

import os
import sys
import unittest

from emcp import (
    Capability,
    EmcpClient,
    EmcpError,
    McpStdioProcessAdapter,
)

SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "mock_mcp_server.py")


class TestMcpStdioPortability(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Map tools from legacy MCP server to EMCP PlatSec capabilities
        tool_capabilities = {
            "query_database": Capability.CAP_DATABASE_QUERY,
            "drop_database": Capability.CAP_DATABASE_MUTATE,
            "fetch_huge_log": Capability.NONE,
        }

        # Spawn the real standalone MCP JSON-RPC server over OS stdio pipes
        self.adapter = McpStdioProcessAdapter(
            name="live-mcp-db",
            command=[sys.executable, SERVER_SCRIPT],
            tool_capabilities=tool_capabilities,
            allowed_capabilities=Capability.CAP_DATABASE_QUERY | Capability.CAP_DATABASE_MUTATE,
        )

    async def asyncTearDown(self):
        self.adapter.close()

    async def test_stdio_tool_discovery(self):
        """Discovers tools via standard JSON-RPC tools/list over stdio pipe."""
        client = EmcpClient(allowed_capabilities=Capability.CAP_DATABASE_QUERY)
        tools = await client.list_tools(self.adapter)

        tool_names = [t["name"] for t in tools.get("tools", [])]
        self.assertIn("query_database", tool_names)
        self.assertIn("drop_database", tool_names)
        self.assertIn("fetch_huge_log", tool_names)

    async def test_stdio_authorized_invocation(self):
        """Successfully executes an authorized tool over stdio pipes."""
        client = EmcpClient(allowed_capabilities=Capability.CAP_DATABASE_QUERY)
        reply = await client.call_tool(
            self.adapter,
            "query_database",
            {"sql": "SELECT 1"},
            token_budget=1000,
        )

        self.assertEqual(reply.status, EmcpError.EMCP_SUCCESS)
        self.assertIn("active", str(reply.args))

    async def test_stdio_platsec_blocks_destructive_tool(self):
        """
        PlatSec BLOCKS a destructive tool invocation before sending JSON-RPC to the MCP process.
        """
        # Client ONLY possesses read-query capability, lacks MUTATE
        unprivileged_client = EmcpClient(allowed_capabilities=Capability.CAP_DATABASE_QUERY)

        reply = await unprivileged_client.call_tool(
            self.adapter,
            "drop_database",
            {"db_name": "production_crm"},
        )

        # Protocol gate rejected call
        self.assertEqual(reply.status, EmcpError.EMCP_ERR_CAPABILITY_DENIED)
        self.assertIn("PlatSec access denied", reply.args["error"])

    async def test_stdio_token_budget_prevents_context_blowup(self):
        """
        Token budget escrow rejects unbounded output from legacy MCP server.
        """
        client = EmcpClient(allowed_capabilities=Capability.NONE)

        # Enforce strict 100 token ceiling on tool returning ~5000 tokens
        reply = await client.call_tool(
            self.adapter,
            "fetch_huge_log",
            {},
            token_budget=100,
        )

        self.assertEqual(reply.status, EmcpError.EMCP_ERR_TOKEN_OVERFLOW)
        self.assertIn("exceeding envelope", reply.args["error"])


if __name__ == "__main__":
    unittest.main()
