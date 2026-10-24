#![allow(dead_code)]
//! EMCP 48-byte binary frame parser and slot serializer.

use bytes::{BufMut, Bytes, BytesMut};
use crate::constants::{
    error_code, flags, opcode, MsgType, DEFAULT_TIMEOUT_MS, EMCP_MAGIC, EMCP_VERSION, HEADER_SIZE, RELAY_PIN,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmcpHeader {
    pub magic: [u8; 2],
    pub version: u8,
    pub msg_type: u8,
    pub opcode: u16,
    pub flags: u16,
    pub caller_pin: u64,
    pub target_pin: u64,
    pub transaction_id: u64,
    pub capabilities_mask: u64,
    pub status: u32,
    pub payload_len: u32,
}

impl EmcpHeader {
    pub fn from_bytes(raw: &[u8; HEADER_SIZE]) -> Result<Self, u32> {
        let magic = [raw[0], raw[1]];
        if magic != EMCP_MAGIC {
            return Err(error_code::EMCP_ERR_INVALID_MAGIC);
        }

        let version = raw[2];
        let msg_type = raw[3];
        let opcode = u16::from_be_bytes([raw[4], raw[5]]);
        let flags = u16::from_be_bytes([raw[6], raw[7]]);
        let caller_pin = u64::from_be_bytes(raw[8..16].try_into().unwrap());
        let target_pin = u64::from_be_bytes(raw[16..24].try_into().unwrap());
        let transaction_id = u64::from_be_bytes(raw[24..32].try_into().unwrap());
        let capabilities_mask = u64::from_be_bytes(raw[32..40].try_into().unwrap());
        let status = u32::from_be_bytes(raw[40..44].try_into().unwrap());
        let payload_len = u32::from_be_bytes(raw[44..48].try_into().unwrap());

        Ok(Self {
            magic,
            version,
            msg_type,
            opcode,
            flags,
            caller_pin,
            target_pin,
            transaction_id,
            capabilities_mask,
            status,
            payload_len,
        })
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..2].copy_from_slice(&self.magic);
        buf[2] = self.version;
        buf[3] = self.msg_type;
        buf[4..6].copy_from_slice(&self.opcode.to_be_bytes());
        buf[6..8].copy_from_slice(&self.flags.to_be_bytes());
        buf[8..16].copy_from_slice(&self.caller_pin.to_be_bytes());
        buf[16..24].copy_from_slice(&self.target_pin.to_be_bytes());
        buf[24..32].copy_from_slice(&self.transaction_id.to_be_bytes());
        buf[32..40].copy_from_slice(&self.capabilities_mask.to_be_bytes());
        buf[40..44].copy_from_slice(&self.status.to_be_bytes());
        buf[44..48].copy_from_slice(&self.payload_len.to_be_bytes());
        buf
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolConstraints {
    pub token_budget: u32,
    pub timeout_ms: u32,
    pub max_depth_hops: u8,
}

impl Default for ToolConstraints {
    fn default() -> Self {
        Self {
            token_budget: 0,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_depth_hops: 10,
        }
    }
}

impl ToolConstraints {
    pub fn to_bytes(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];
        buf[0..4].copy_from_slice(&self.token_budget.to_be_bytes());
        buf[4..8].copy_from_slice(&self.timeout_ms.to_be_bytes());
        buf[8] = self.max_depth_hops;
        buf
    }

    pub fn from_bytes(raw: &[u8]) -> Self {
        if raw.len() < 9 {
            return Self::default();
        }
        let token_budget = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        let timeout_ms = u32::from_be_bytes(raw[4..8].try_into().unwrap());
        let max_depth_hops = raw[8];
        Self {
            token_budget,
            timeout_ms,
            max_depth_hops,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmcpFrame {
    pub header: EmcpHeader,
    pub payload: Bytes,
}

impl EmcpFrame {
    pub fn new(header: EmcpHeader, payload: Bytes) -> Self {
        Self { header, payload }
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.header.to_bytes());
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }

    /// Packs standard 4-slot payload: [lens(4x u32)] + verb + args + constraints + envelope
    pub fn pack_slots(
        verb: &str,
        args_json: &serde_json::Value,
        constraints: ToolConstraints,
        session_handle: u32,
    ) -> Bytes {
        let slot0 = verb.as_bytes();
        let slot1 = serde_json::to_vec(args_json).unwrap_or_default();
        let slot2 = constraints.to_bytes();
        let slot3 = session_handle.to_be_bytes();

        let l0 = slot0.len() as u32;
        let l1 = slot1.len() as u32;
        let l2 = slot2.len() as u32;
        let l3 = slot3.len() as u32;

        let mut buf = BytesMut::with_capacity(16 + slot0.len() + slot1.len() + slot2.len() + slot3.len());
        buf.put_u32(l0);
        buf.put_u32(l1);
        buf.put_u32(l2);
        buf.put_u32(l3);
        buf.extend_from_slice(slot0);
        buf.extend_from_slice(&slot1);
        buf.extend_from_slice(&slot2);
        buf.extend_from_slice(&slot3);
        buf.freeze()
    }

    pub fn create_reply(
        &self,
        status: u32,
        result_json: Option<&serde_json::Value>,
        remaining_budget: u32,
    ) -> Self {
        let empty = serde_json::json!({});
        let val = result_json.unwrap_or(&empty);
        let constraints = ToolConstraints {
            token_budget: remaining_budget,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_depth_hops: 10,
        };
        let payload = Self::pack_slots("tools/reply", val, constraints, 0);

        let header = EmcpHeader {
            magic: EMCP_MAGIC,
            version: EMCP_VERSION,
            msg_type: MsgType::MsgReply as u8,
            opcode: if self.header.opcode != 0 { self.header.opcode } else { opcode::OP_TOOLS_CALL },
            flags: flags::FLAG_NONE,
            caller_pin: RELAY_PIN,
            target_pin: self.header.caller_pin,
            transaction_id: self.header.transaction_id,
            capabilities_mask: self.header.capabilities_mask,
            status,
            payload_len: payload.len() as u32,
        };

        Self::new(header, payload)
    }
}
