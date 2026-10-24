#!/usr/bin/env python3
"""
EMCP Interactive CLI Playground.
Demonstrates live kernel-grade tool execution, PlatSec capability gating,
and Token Budget Escrow over real OS pipes.
"""

import asyncio
import os
import sys

# Ensure src is in pythonpath
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from emcp import (
    Capability,
    EmcpClient,
    EmcpError,
    McpStdioProcessAdapter,
    ToolIdentity,
    format_pin,
)

SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "tests", "mock_mcp_server.py")


def banner():
    print("\033[1;36m" + "=" * 70)
    print("   EMCP (Enhanced Model Context Protocol) — Interactive Playground")
    print("=" * 70 + "\033[0m")
    print("Testing live Anthropic MCP stdio server with operating-system guarantees:\n")


async def main():
    banner()

    # 1. Identity & Cryptographic Addressing
    client_identity = ToolIdentity.generate()
    print(f"\033[1;34m[1/4] Caller Identity Generated:\033[0m")
    print(f"  • Tool-PIN: \033[1;32m{client_identity.pin_hex}\033[0m (64-bit Ed25519 derivative)")
    print(f"  • Public key: {client_identity.public_bytes.hex()[:32]}...\n")

    # 2. Spawning real MCP JSON-RPC Server over OS stdio pipe
    print(f"\033[1;34m[2/4] Spawning Legacy Anthropic MCP Server over stdio pipe...\033[0m")
    tool_capabilities = {
        "query_database": Capability.CAP_DATABASE_QUERY,
        "drop_database": Capability.CAP_DATABASE_MUTATE,
        "fetch_huge_log": Capability.NONE,
    }

    adapter = McpStdioProcessAdapter(
        name="production-db",
        command=[sys.executable, SERVER_SCRIPT],
        tool_capabilities=tool_capabilities,
        allowed_capabilities=Capability.CAP_DATABASE_QUERY | Capability.CAP_DATABASE_MUTATE,
    )

    try:
        # Discover tools
        client = EmcpClient(
            identity=client_identity,
            allowed_capabilities=Capability.CAP_DATABASE_QUERY,  # Read-only caller!
        )
        catalog = await client.list_tools(adapter)
        print("  ✓ Handshake completed via stdio")
        print("  ✓ Discovered tools:")
        for t in catalog.get("tools", []):
            req_cap = t.get("requiredCapabilities", 0)
            print(f"    - \033[1;37m{t['name']}\033[0m (required caps: \033[1;33m0x{req_cap:016X}\033[0m)")
        print()

        # 3. Authorized Tool Call
        print(f"\033[1;34m[3/4] Scenario A: Authorized Tool Call (SELECT query)...\033[0m")
        print("  Dispatching 48-byte EMCP frame with CAP_DATABASE_QUERY...")
        reply = await client.call_tool(
            adapter,
            "query_database",
            {"sql": "SELECT * FROM users LIMIT 1"},
            token_budget=1000,
        )
        print(f"  ✓ Status: \033[1;32m{EmcpError(reply.status).name} ({int(reply.status)})\033[0m")
        print(f"  ✓ Output: {reply.args}")
        print(f"  ✓ Remaining token budget in envelope: {reply.constraints.token_budget} tokens\n")

        # 4. Prompt Injection Attack Blocked by PlatSec
        print(f"\033[1;34m[4/4] Scenario B: Prompt Injection Attack (DROP DATABASE)...\033[0m")
        print("  Simulating model manipulated into calling drop_database...")
        print("  Caller capabilities: CAP_DATABASE_QUERY (lacks CAP_DATABASE_MUTATE)")
        
        reply_attack = await client.call_tool(
            adapter,
            "drop_database",
            {"db_name": "production_crm"},
        )
        if reply_attack.status == EmcpError.EMCP_ERR_CAPABILITY_DENIED:
            print(f"  \033[1;31m🛑 [ATTACK BLOCKED BY PLATSEC]\033[0m")
            print(f"  • Frame Status: \033[1;31m{EmcpError(reply_attack.status).name} ({int(reply_attack.status)})\033[0m")
            print(f"  • Reason: {reply_attack.args.get('error')}")
            print("  • Result: The child MCP process was NEVER contacted. Attack neutralized at wire layer.")
        else:
            print("  FAIL: Tool executed unexpectedly!")
        print()

        # 5. Context Blowup Defense
        print(f"\033[1;34m[Bonus] Scenario C: Context Blowup Defense (Token Budget Escrow)...\033[0m")
        print("  Tool returns 20,000 characters. Caller enforces token_budget = 100...")
        reply_overflow = await client.call_tool(
            adapter,
            "fetch_huge_log",
            {},
            token_budget=100,
        )
        if reply_overflow.status == EmcpError.EMCP_ERR_TOKEN_OVERFLOW:
            print(f"  \033[1;33m⚠️  [CONTEXT SHIELD ENGAGED]\033[0m")
            print(f"  • Frame Status: \033[1;33m{EmcpError(reply_overflow.status).name} ({int(reply_overflow.status)})\033[0m")
            print(f"  • Reason: {reply_overflow.args.get('error')}")
            print("  • Result: Ledger rolled back. Model context saved from blowup.")
        print()

    finally:
        adapter.close()
        print("\033[1;32m[OK] Playground execution completed cleanly.\033[0m")


if __name__ == "__main__":
    asyncio.run(main())
