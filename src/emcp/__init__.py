"""
EMCP: Enhanced Model Context Protocol
Kernel-grade Tool Execution and Multi-Agent Mesh Protocol.
"""

from .constants import (
    DEFAULT_MAX_PAYLOAD_SIZE,
    DEFAULT_TIMEOUT_MS,
    EMCP_MAGIC,
    EMCP_VERSION,
    HEADER_SIZE,
    RELAY_PIN,
    Capability,
    EmcpError,
    FrameFlags,
    MsgType,
    OpCode,
)
from .frame import (
    CryptoEnvelope,
    EmcpFrame,
    ToolConstraints,
)
from .security import (
    PlatSecGate,
    ToolIdentity,
    compute_pin,
    format_pin,
)
from .budget import (
    EscrowEntry,
    TokenBudgetLedger,
)
from .server import (
    EmcpServer,
    ToolDefinition,
)
from .client import (
    EmcpClient,
)
from .adapter_mcp import (
    McpLegacyAdapter,
    McpStdioProcessAdapter,
)

__all__ = [
    # Constants
    "EMCP_MAGIC",
    "EMCP_VERSION",
    "HEADER_SIZE",
    "DEFAULT_MAX_PAYLOAD_SIZE",
    "DEFAULT_TIMEOUT_MS",
    "RELAY_PIN",
    "Capability",
    "EmcpError",
    "FrameFlags",
    "MsgType",
    "OpCode",
    # Frame
    "CryptoEnvelope",
    "EmcpFrame",
    "ToolConstraints",
    # Security
    "PlatSecGate",
    "ToolIdentity",
    "compute_pin",
    "format_pin",
    # Budget
    "EscrowEntry",
    "TokenBudgetLedger",
    # Server & Client
    "EmcpServer",
    "ToolDefinition",
    "EmcpClient",
    # Adapter
    "McpLegacyAdapter",
    "McpStdioProcessAdapter",
]
