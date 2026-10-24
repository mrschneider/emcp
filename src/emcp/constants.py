"""
EMCP Protocol Constants, OpCodes, Capabilities, and Error Codes.
"""

from enum import IntEnum, IntFlag

EMCP_MAGIC = b"EM"
EMCP_VERSION = 1
HEADER_SIZE = 48
DEFAULT_MAX_PAYLOAD_SIZE = 16 * 1024 * 1024
DEFAULT_TIMEOUT_MS = 5000
RELAY_PIN = 0x0000_0000_0000_0001


class MsgType(IntEnum):
    MSG_SEND = 1          # Synchronous tool invocation request
    MSG_RECEIVE = 2       # Tool worker dequeue
    MSG_REPLY = 3         # Tool completion reply
    MSG_PULSE = 4         # Out-of-band pulse (cancel/heartbeat)
    MSG_RELAY_CONTROL = 5 # Registration and mesh control


class FrameFlags(IntFlag):
    FLAG_NONE = 0
    FLAG_URGENT = 1 << 0
    FLAG_ENCRYPTED = 1 << 1
    FLAG_COMPRESSED = 1 << 2
    FLAG_SIGNED = 1 << 3


class Capability(IntFlag):
    NONE = 0
    CAP_READ_FS = 1 << 0          # Storage and file read access
    CAP_WRITE_FS = 1 << 1         # Storage and file write/delete
    CAP_NET_HTTP = 1 << 2         # Egress HTTP/HTTPS requests
    CAP_NET_RAW = 1 << 3          # Direct raw socket access
    CAP_SHELL_EXEC = 1 << 4       # Spawning terminal commands
    CAP_DATABASE_QUERY = 1 << 5   # Read-only database access
    CAP_DATABASE_MUTATE = 1 << 6  # Read-write database access
    CAP_SYS_ADMIN = 1 << 7        # Infrastructure modifications
    CAP_PII_ACCESS = 1 << 8       # Confidential/PII context
    CAP_SUBAGENT_SPAWN = 1 << 9   # Spawning child agents/delegation


class OpCode(IntEnum):
    OP_TOOLS_LIST = 0x0100
    OP_TOOLS_CALL = 0x0101
    OP_RESOURCES_LIST = 0x0102
    OP_RESOURCES_READ = 0x0103
    OP_PROMPTS_LIST = 0x0104
    OP_PROMPTS_GET = 0x0105
    OP_RELAY_REGISTER = 0x0001
    OP_RELAY_PING = 0x0002


class EmcpError(IntEnum):
    EMCP_SUCCESS = 0
    EMCP_ERR_INVALID_MAGIC = 1
    EMCP_ERR_UNKNOWN_PIN = 2
    EMCP_ERR_CAPABILITY_DENIED = 3
    EMCP_ERR_DEADLOCK_DETECTED = 4
    EMCP_ERR_TIMEOUT = 5
    EMCP_ERR_CANCELLED = 6
    EMCP_ERR_TOKEN_OVERFLOW = 7
    EMCP_ERR_SIGNATURE_INVALID = 8
    EMCP_ERR_MALFORMED_FRAME = 9
    EMCP_ERR_TOOL_NOT_FOUND = 10
    EMCP_ERR_TOOL_EXECUTION_FAILED = 11
