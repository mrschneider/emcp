# EMCP (Enhanced Model Context Protocol)
## Architectural Specification & Protocol Reference
**Version:** 0.1.0  
**Status:** Canonical Reference Specification  
**Authors:** Architecture Team / Infrastructure Operations  

---

## 1. Executive Summary & Design Rationale

The **Enhanced Model Context Protocol (EMCP)** bridges Anthropic's Model Context Protocol (MCP) tool description schemas with microkernel operating-system principles derived from **Symbian OS (EKA2)**, **QNX Neutrino**, and **DARPA DTN (RFC 9171)**.

### 1.1 The Ambient Authority Problem in Standard MCP
In the standard MCP specification, tools expose JSON schemas and execute via conversational JSON-RPC 2.0 messages. The protocol treats tool invocation as an ambient capability: any actor capable of generating an LLM completion can trigger sensitive tools (filesystems, network egress, shell commands, databases).

EMCP introduces five kernel-grade constraints:
1. **Capability-Gated Invocation (PlatSec):** No tool executes unless the incoming frame carries a cryptographically verifiable 64-bit capability bitmask matching the tool's required bitmask.
2. **Upfront Token Budget Escrow:** Before execution begins, the caller reserves an escrow envelope in tokens. Over-budget tool output is rejected atomically before contaminating the model context.
3. **Deterministic 48-byte Binary Header:** Replaces verbose JSON-RPC text envelopes with network-byte-order binary framing.
4. **Tool-PIN Addressing:** Global 64-bit cryptographic addressing derived from Ed25519 public keys (`First8Bytes(SHA-256(PK))`), enabling transparent tool routing across distributed nodes without host/port binding.
5. **Disruption-Tolerant Handover (DTN):** Support for remote tool execution across degraded or partitioned edge links with store-and-forward custody confirmation.

---

## 2. Layered Architecture

```
+-------------------------------------------------------------------------+
| Layer 4: Application & Tool Abstraction                                 |
|   - @emcp.tool decorator, inputSchema, legacy MCP JSON-RPC adapters     |
+-------------------------------------------------------------------------+
| Layer 3: Kernel Governance & Resource Accounting                        |
|   - PlatSec capability gate, TokenBudgetLedger escrow, DeadlockGraph   |
+-------------------------------------------------------------------------+
| Layer 2: Synchronous Rendezvous & Framing                               |
|   - 48-byte binary header, 4 structured slots (Verb, Args, Const, Env)  |
+-------------------------------------------------------------------------+
| Layer 1: Cryptographic Identity & Routing                               |
|   - 64-bit Tool-PIN, Ed25519 signatures, EMCP Relay / Stdio Proxy     |
+-------------------------------------------------------------------------+
| Layer 0: Transport                                                      |
|   - Local process stdio, Unix Domain Sockets, TCP/mTLS                  |
+-------------------------------------------------------------------------+
```

---

## 3. Binary Wire Format Specification

Every EMCP frame consists of a fixed **48-byte header** (64-bit aligned, big-endian) followed by a 4-slot payload.

### 3.1 Header Structure (48 Bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic (0x45, 0x4D)   |  Ver (0x01)   |  MsgType (8b) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            OpCode (16b)       |         Flags (16b)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Caller PIN (64b)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Target Tool-PIN (64b)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Transaction ID / UUID (64b)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   PlatSec Capability Mask (64b)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Status / Error Code (32b)    |  Payload Length (32b)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2 Four-Slot Payload Layout
Payload length indicates the size of the following block:
```
[Slot0 Len: u32][Slot1 Len: u32][Slot2 Len: u32][Slot3 Len: u32]
[Slot 0: Verb string (UTF-8)]
[Slot 1: Arguments JSON or raw data]
[Slot 2: Constraints (token_budget: u32, timeout_ms: u32, max_depth_hops: u8)]
[Slot 3: Crypto Envelope (session_handle: u32, Ed25519 signature)]
```

---

## 4. PlatSec Capability Model

Capabilities are defined as a 64-bit bitmask. A tool declaring required capabilities will only execute if:

$$\text{GrantedMask} \ \& \ \text{RequiredMask} == \text{RequiredMask}$$

| Bit | Symbol | Description |
| :--- | :--- | :--- |
| `1 << 0` | `CAP_READ_FS` | Reading files or inspecting directory structure |
| `1 << 1` | `CAP_WRITE_FS` | Writing, creating, or deleting filesystem resources |
| `1 << 2` | `CAP_NET_HTTP` | Outbound HTTP/HTTPS requests |
| `1 << 3` | `CAP_NET_RAW` | Raw socket I/O (TCP/UDP) |
| `1 << 4` | `CAP_SHELL_EXEC` | Spawning host terminal subprocesses |
| `1 << 5` | `CAP_DATABASE_QUERY`| Read-only database queries (SELECT) |
| `1 << 6` | `CAP_DATABASE_MUTATE`| Modifying database schema or records (INSERT/UPDATE/DELETE) |
| `1 << 7` | `CAP_SYS_ADMIN` | Modifying system configurations, daemons, or credentials |
| `1 << 8` | `CAP_PII_ACCESS` | Accessing sensitive user personal data |
| `1 << 9` | `CAP_SUBAGENT_SPAWN`| Spawning recursive agent tasks or delegations |

---

## 5. Token Budget Escrow Lifecycle

To prevent context-window blowup:
1. **Escrow:** When `EmcpClient` issues a `tools/call`, it specifies `token_budget` in Slot 2. The server reserves this budget in `TokenBudgetLedger`.
2. **Execution:** The tool runs. As output is generated, the ledger meters spent tokens.
3. **Commit:** On success, actual tokens consumed are deducted from server capacity, and unspent tokens are released.
4. **Overflow / Rollback:** If output exceeds the agreed ceiling, the server aborts the reply with `EMCP_ERR_TOKEN_OVERFLOW` and refunds the ledger. The LLM receives an actionable error instead of a context explosion.

---

## 6. Legacy MCP Compatibility Bridge (`McpLegacyAdapter`)

EMCP does not discard existing ecosystem tooling. The `McpLegacyAdapter`:
- Connects to standard MCP servers via `stdio` (JSON-RPC 2.0).
- Dynamically queries `tools/list`.
- Maps existing tools into EMCP services with assigned PlatSec capability requirements and token ceilings.
- Allows Claude, Hermes, and OpenAI agents using EMCP to safely consume third-party MCP servers with full kernel protection.

---

## 7. Distributed High-Availability & Tactical Resiliency

### 7.1 OMG DDS / C4I Quality of Service for Tools (`qos.py`)
To prevent agent execution freezes and enable high-availability tool meshes:
* **RxO Contract Evaluator (`QosContractEvaluator`):** Validates caller requirements against tool capabilities. If a caller requires a turnaround deadline of 500ms but a remote tool only guarantees 3000ms, the binding is rejected upfront.
* **Redundant Tool Ownership & Automatic Failover (`ToolOwnershipArbitrator`):** Allows multiple instances of the same tool to be deployed across redundant farm nodes (e.g., primary tool on `.70` with strength 200, replica on `.18` with strength 100). The arbitrator tracks heartbeat liveliness leases; if the primary tool hangs or crashes, incoming calls are automatically routed to the replica tool instance without agent disruption.
* **Turnaround Deadline Monitor (`ToolDeadlineMonitor`):** Enforces strict SLA timeouts on long-running tool executions, firing alerts and triggering out-of-band cancellation pulses (`PULSE_CANCEL`) upon breach.

### 7.2 RFC 9171 / DARPA DTN Custody Transfer for Tools (`dtn.py`)
To execute tools reliably across partitioned, wireless, or intermittent edge links:
* **Custody Transfer Handover (`ToolCustodyStore`):** Invocations and results are encapsulated in `ToolBundle`s. Upstream nodes retain message custody until downstream explicitly acknowledges custody responsibility (`CUSTODY_ACCEPTED`).
* **Resiliency Controls:** Bounded buffer memory accounting, duplicate suppression rings, and proactive TTL expiration pruning protect edge nodes against routing loops and memory exhaustion during extended network outages.

