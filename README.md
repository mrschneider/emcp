# EMCP: Enhanced Model Context Protocol

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)
![Rust](https://img.shields.io/badge/rust-edition%202021-orange)
![Wire Format](https://img.shields.io/badge/wire-48%20byte%20binary-red)

**EMCP** (Enhanced Model Context Protocol) is a kernel-grade tool execution and multi-agent mesh protocol. While Anthropic's standard MCP standardizes *how tools are described* (via JSON Schema), EMCP standardizes *how tools are executed with strict operating-system guarantees*: cryptographic capabilities, token budget escrow, sub-millisecond zero-copy wire framing, and disruption-tolerant delivery.

---

## Why EMCP? (The Breakdown of Standard MCP)

Standard MCP treats tool execution as conversational JSON-RPC 2.0 text over `stdio` or SSE. In production multi-agent environments, this design creates four fatal failure modes:

1. **Ambient Authority & Prompt Injection:** Standard MCP has no protocol-level capability checks. If a model is manipulated via prompt injection into calling a registered filesystem or bash tool, the tool executes with the host process's full permissions.
2. **Context Blowup & Token Exhaustion:** Standard tools can return unbounded payloads (e.g. 500 KB logs), instantly detonating the LLM's context window and burning API budgets without prior agreement.
3. **Pass-Fail Networking:** If a remote tool link drops during invocation, the request is lost with `Connection reset` or a generic timeout.
4. **Transport Serialization Bloat:** Parsing strings and escaping JSON-RPC messages creates high tail latencies for high-frequency tools.

---

## MCP vs. EMCP Comparison

| Feature | Standard MCP (Anthropic) | EMCP (Enhanced) | Operational Impact |
| :--- | :--- | :--- | :--- |
| **Wire Protocol** | JSON-RPC 2.0 text over stdio/SSE | Fixed **48-byte binary header** + 4 structured slots | Microsecond transit, zero-copy socket parsing |
| **Security Gate** | None (ambient authority) | **Symbian PlatSec 64-bit Bitmask** | Unprivileged frames denied at wire layer before LLM/tool wakes up |
| **Cost Control** | Unbounded output | **Upfront Token Budget Escrow** | Prevents context explosion with automatic ledger rollback |
| **Addressing** | Local `stdio` or transient `host:port` | **64-bit Cryptographic Tool-PIN** | Tools addressed by Ed25519 identity, mobile across nodes/edges |
| **High Availability** | Single instance point-of-failure | **DDS C4I QoS & Exclusive Ownership** | Automatic failover to replica tool instances upon missed liveliness lease |
| **Resiliency** | Fragile connection reset | **RFC 9171 DTN Custody Transfer** | Offline buffering with atomic custody handover (`CUSTODY_ACCEPTED`) |
| **Deadlock Guard** | Silent hanging | **QNX Deadlock Graph Engine** | Prevents circular tool/subagent recursion (`A → B → A`) |

---

## Interactive Playground

- **Live Web Playground:** [mrschneider.github.io/emcp/playground](https://mrschneider.github.io/emcp/playground/) (interactive browser simulator testing PlatSec gates, budget sliders, and 48-byte hex wire framing).
- **Terminal CLI Playground:** Run directly in your shell against a live child MCP process over stdio:
  ```bash
  python3 playground.py
  ```

---

## Quickstart

### 1. Creating a Secure EMCP Tool Server

```python
import asyncio
from emcp import EmcpServer, Capability

server = EmcpServer(name="ops-tools", allowed_capabilities=Capability.CAP_READ_FS | Capability.CAP_WRITE_FS)

@server.tool(
    name="read_config",
    description="Reads a configuration file",
    required_caps=Capability.CAP_READ_FS,
    default_max_tokens=1000
)
def read_config(path: str):
    return {"path": path, "content": "port=8080"}

@server.tool(
    name="wipe_disk",
    description="Destructive action requiring sysadmin capability",
    required_caps=Capability.CAP_SYS_ADMIN,
    default_max_tokens=500
)
def wipe_disk():
    return {"status": "purged"}
```

### 2. Invoking with PlatSec Capability Protection

```python
from emcp import EmcpClient, Capability

async def main():
    # Client with read-only capability
    client = EmcpClient(allowed_capabilities=Capability.CAP_READ_FS)

    # 1. Read config succeeds
    reply = await client.call_tool(server, "read_config", {"path": "/etc/app.conf"})
    print(reply.args)  # {'path': '/etc/app.conf', 'content': 'port=8080'}

    # 2. Destructive action is BLOCKED at protocol layer (handler never invoked!)
    reply = await client.call_tool(server, "wipe_disk")
    print(reply.status) # EmcpError.EMCP_ERR_CAPABILITY_DENIED (3)

asyncio.run(main())
```

### 3. Wrapping Legacy Anthropic MCP Servers

EMCP provides seamless backward compatibility. Wrap existing JSON-RPC servers without altering their code:

```python
from emcp import McpLegacyAdapter, Capability

# Pass existing JSON-RPC handler
adapter = McpLegacyAdapter(
    name="legacy-sql",
    jsonrpc_dispatcher=legacy_mcp_dispatcher,
    tool_capabilities={"execute_sql": Capability.CAP_DATABASE_QUERY},
    allowed_capabilities=Capability.CAP_DATABASE_QUERY
)
```

---

## Directory Layout

```
.
├── ARCHITECTURE.md          # Canonical EMCP Specification
├── README.md                # Overview & Comparative Pitch
├── pyproject.toml           # Python SDK packaging
├── crates/
│   ├── emcp-core/           # Rust zero-copy framing, PlatSec & token budget
│   └── emcp-daemon/         # High-concurrency Tokio relay & stdio proxy
├── src/
│   └── emcp/
│       ├── __init__.py      # Package export
│       ├── constants.py     # OpCodes, Capabilities, and Error codes
│       ├── frame.py         # 48-byte binary frame serializer
│       ├── security.py      # Ed25519 identity, PlatSec gate & Tool-PIN
│       ├── budget.py        # Token budget escrow ledger
│       ├── server.py        # @emcp.tool decorator and dispatcher
│       ├── client.py        # EmcpClient tool caller
│       ├── qos.py           # DDS C4I Tool QoS contracts & ownership failover
│       ├── dtn.py           # RFC 9171 DTN custody transfer for remote tools
│       └── adapter_mcp.py   # Legacy Anthropic MCP JSON-RPC & stdio bridge
└── tests/
    ├── test_emcp.py         # Core test suite (PlatSec, budget, framing)
    ├── test_mcp_portability.py # End-to-end stdio subprocess portability tests
    └── test_tactical_emcp.py # DDS QoS tool failover & DTN custody tests
```

---

## License

MIT License. Designed and maintained by Architecture Team / Infrastructure Operations.
