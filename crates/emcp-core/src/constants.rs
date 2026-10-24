#![allow(dead_code)]
//! EMCP Protocol Constants, OpCodes, Capabilities, and Error Codes.

pub const EMCP_MAGIC: [u8; 2] = [0x45, 0x4D]; // ASCII "EM"
pub const EMCP_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 48;

pub const DEFAULT_MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024; // 16 MB max guard
pub const DEFAULT_TIMEOUT_MS: u32 = 5000;
pub const RELAY_PIN: u64 = 0x0000_0000_0000_0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    MsgSend = 1,          // Synchronous tool invocation request
    MsgReceive = 2,       // Tool worker dequeue
    MsgReply = 3,         // Tool completion reply
    MsgPulse = 4,         // Out-of-band pulse (cancel/heartbeat)
    MsgRelayControl = 5,  // Registration and mesh control
    Unknown = 255,
}

impl From<u8> for MsgType {
    fn from(v: u8) -> Self {
        match v {
            1 => MsgType::MsgSend,
            2 => MsgType::MsgReceive,
            3 => MsgType::MsgReply,
            4 => MsgType::MsgPulse,
            5 => MsgType::MsgRelayControl,
            _ => MsgType::Unknown,
        }
    }
}

pub mod flags {
    pub const FLAG_NONE: u16 = 0;
    pub const FLAG_URGENT: u16 = 1 << 0;
    pub const FLAG_ENCRYPTED: u16 = 1 << 1;
    pub const FLAG_COMPRESSED: u16 = 1 << 2;
    pub const FLAG_SIGNED: u16 = 1 << 3;
}

pub mod opcode {
    pub const OP_TOOLS_LIST: u16 = 0x0100;
    pub const OP_TOOLS_CALL: u16 = 0x0101;
    pub const OP_RESOURCES_LIST: u16 = 0x0102;
    pub const OP_RESOURCES_READ: u16 = 0x0103;
    pub const OP_PROMPTS_LIST: u16 = 0x0104;
    pub const OP_PROMPTS_GET: u16 = 0x0105;
    pub const OP_RELAY_REGISTER: u16 = 0x0001;
    pub const OP_RELAY_PING: u16 = 0x0002;
}

pub mod capability {
    pub const CAP_NONE: u64 = 0;
    pub const CAP_READ_FS: u64 = 1 << 0;
    pub const CAP_WRITE_FS: u64 = 1 << 1;
    pub const CAP_NET_HTTP: u64 = 1 << 2;
    pub const CAP_NET_RAW: u64 = 1 << 3;
    pub const CAP_SHELL_EXEC: u64 = 1 << 4;
    pub const CAP_DATABASE_QUERY: u64 = 1 << 5;
    pub const CAP_DATABASE_MUTATE: u64 = 1 << 6;
    pub const CAP_SYS_ADMIN: u64 = 1 << 7;
    pub const CAP_PII_ACCESS: u64 = 1 << 8;
    pub const CAP_SUBAGENT_SPAWN: u64 = 1 << 9;
}

pub mod error_code {
    pub const EMCP_SUCCESS: u32 = 0;
    pub const EMCP_ERR_INVALID_MAGIC: u32 = 1;
    pub const EMCP_ERR_UNKNOWN_PIN: u32 = 2;
    pub const EMCP_ERR_CAPABILITY_DENIED: u32 = 3;
    pub const EMCP_ERR_DEADLOCK_DETECTED: u32 = 4;
    pub const EMCP_ERR_TIMEOUT: u32 = 5;
    pub const EMCP_ERR_CANCELLED: u32 = 6;
    pub const EMCP_ERR_TOKEN_OVERFLOW: u32 = 7;
    pub const EMCP_ERR_SIGNATURE_INVALID: u32 = 8;
    pub const EMCP_ERR_MALFORMED_FRAME: u32 = 9;
    pub const EMCP_ERR_TOOL_NOT_FOUND: u32 = 10;
    pub const EMCP_ERR_TOOL_EXECUTION_FAILED: u32 = 11;
}
