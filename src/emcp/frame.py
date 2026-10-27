"""
EMCP 48-byte binary frame and 4-slot payload serializer.
"""

from __future__ import annotations
import json
import struct
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple

from .constants import (
    DEFAULT_MAX_PAYLOAD_SIZE,
    DEFAULT_TIMEOUT_MS,
    EMCP_MAGIC,
    EMCP_VERSION,
    HEADER_SIZE,
    EmcpError,
    FrameFlags,
    MsgType,
    OpCode,
    RELAY_PIN,
)

HEADER_STRUCT = struct.Struct(">2sBBHHQQQQII")
assert HEADER_STRUCT.size == HEADER_SIZE == 48


@dataclass
class ToolConstraints:
    token_budget: int = 0
    timeout_ms: int = DEFAULT_TIMEOUT_MS
    max_depth_hops: int = 10

    def pack(self) -> bytes:
        return struct.pack(">IIB", self.token_budget, self.timeout_ms, self.max_depth_hops)

    @classmethod
    def unpack(cls, data: bytes) -> ToolConstraints:
        if len(data) < 9:
            return cls()
        token_budget, timeout_ms, max_depth_hops = struct.unpack(">IIB", data[:9])
        return cls(token_budget=token_budget, timeout_ms=timeout_ms, max_depth_hops=max_depth_hops)


@dataclass
class CryptoEnvelope:
    session_handle: int = 0
    signature: bytes = b""

    def pack(self) -> bytes:
        sig = self.signature or b""
        return struct.pack(">I", self.session_handle) + sig

    @classmethod
    def unpack(cls, data: bytes) -> CryptoEnvelope:
        if len(data) < 4:
            return cls(session_handle=0, signature=b"")
        session_handle = struct.unpack(">I", data[:4])[0]
        sig = data[4:]
        return cls(session_handle=session_handle, signature=sig)


@dataclass
class EmcpFrame:
    magic: bytes = EMCP_MAGIC
    version: int = EMCP_VERSION
    msg_type: MsgType = MsgType.MSG_SEND
    opcode: int = OpCode.OP_TOOLS_CALL
    flags: FrameFlags = FrameFlags.FLAG_NONE
    caller_pin: int = 0
    target_pin: int = 0
    transaction_id: int = 0
    capabilities_mask: int = 0
    status: int = EmcpError.EMCP_SUCCESS

    # Payload slots (TIpcArgs)
    verb: str = ""
    args: Any = None
    constraints: ToolConstraints = field(default_factory=ToolConstraints)
    envelope: CryptoEnvelope = field(default_factory=CryptoEnvelope)
    raw_payload: Optional[bytes] = None

    def __setattr__(self, name: str, value: object) -> None:
        """Mutation invalidates caches: raw_payload (parsed wire) and
        _args_json (server single-encode stash), so a changed field is
        re-encoded and never sent stale."""
        if name == "args" and "_args_json" in self.__dict__:
            object.__setattr__(self, "_args_json", None)
        if name != "raw_payload" and self.__dict__.get("raw_payload") is not None:
            object.__setattr__(self, "raw_payload", None)
        object.__setattr__(self, name, value)

    def _encode_args(self) -> bytes:
        """Single source of truth for slot1 encoding."""
        if self.args is None:
            return b""
        if isinstance(self.args, bytes):
            return self.args
        if isinstance(self.args, (dict, list, int, float, str, bool)):
            return json.dumps(self.args, separators=(",", ":")).encode("utf-8")
        return str(self.args).encode("utf-8")

    def pack_slots(self) -> bytes:
        slot0 = self.verb.encode("utf-8") if self.verb else b""
        pre_encoded = self.__dict__.get("_args_json")
        if pre_encoded is None:
            pre_encoded = self._encode_args()
            # Stash so a second pass (sign_frame -> pack, unpack -> repack)
            # never re-runs json.dumps on the same args. `args` mutation
            # invalidates the stash via __setattr__. Bypass the hook so a
            # parsed-wire frame keeps its raw_payload cache intact.
            object.__setattr__(self, "_args_json", pre_encoded)
        slot1 = pre_encoded

        slot2 = (self.constraints or ToolConstraints()).pack()
        slot3 = (self.envelope or CryptoEnvelope()).pack()

        lens = struct.pack(">IIII", len(slot0), len(slot1), len(slot2), len(slot3))
        return lens + slot0 + slot1 + slot2 + slot3

    def pack(self) -> bytes:
        payload = self.raw_payload if self.raw_payload is not None else self.pack_slots()
        header = HEADER_STRUCT.pack(
            self.magic,
            self.version,
            int(self.msg_type),
            int(self.opcode),
            int(self.flags),
            self.caller_pin,
            self.target_pin,
            self.transaction_id,
            self.capabilities_mask,
            int(self.status),
            len(payload),
        )
        return header + payload

    @classmethod
    def unpack(cls, raw: bytes, max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE) -> EmcpFrame:
        if len(raw) < HEADER_SIZE:
            raise ValueError(f"Frame truncated: {len(raw)} < {HEADER_SIZE}")

        magic, ver, msg_type_raw, opcode, flags_raw, caller_pin, target_pin, tx_id, cap_mask, status_raw, payload_len = HEADER_STRUCT.unpack(
            raw[:HEADER_SIZE]
        )

        if magic != EMCP_MAGIC:
            raise ValueError(f"Invalid magic: {magic}")

        if payload_len > max_payload_size:
            raise ValueError(f"Payload size {payload_len} exceeds max {max_payload_size}")

        payload = raw[HEADER_SIZE : HEADER_SIZE + payload_len]
        if len(payload) < payload_len:
            raise ValueError(f"Payload truncated: need {payload_len}, got {len(payload)}")

        verb, args, constraints, envelope = cls.unpack_slots(payload)

        return cls(
            magic=magic,
            version=ver,
            msg_type=MsgType(msg_type_raw),
            opcode=opcode,
            flags=FrameFlags(flags_raw),
            caller_pin=caller_pin,
            target_pin=target_pin,
            transaction_id=tx_id,
            capabilities_mask=cap_mask,
            status=status_raw,
            verb=verb,
            args=args,
            constraints=constraints,
            envelope=envelope,
            raw_payload=payload,
        )

    @classmethod
    def unpack_slots(cls, payload: bytes) -> Tuple[str, Any, ToolConstraints, CryptoEnvelope]:
        if len(payload) < 16:
            return ("", None, ToolConstraints(), CryptoEnvelope())

        l0, l1, l2, l3 = struct.unpack(">IIII", payload[:16])
        offset = 16
        total = l0 + l1 + l2 + l3
        if 16 + total > len(payload):
            raise ValueError(
                f"Slot lengths exceed payload: declared {total}, "
                f"available {len(payload) - 16}"
            )

        slot0_bytes = payload[offset : offset + l0]
        offset += l0
        # Strict decode (EMCP spec): malformed verb bytes are a protocol
        # error, never silently tolerated.
        verb = slot0_bytes.decode("utf-8")

        slot1_bytes = payload[offset : offset + l1]
        offset += l1
        args = None
        if slot1_bytes:
            try:
                args = json.loads(slot1_bytes.decode("utf-8"))
            except Exception:
                args = slot1_bytes

        slot2_bytes = payload[offset : offset + l2]
        offset += l2
        constraints = ToolConstraints.unpack(slot2_bytes)

        slot3_bytes = payload[offset : offset + l3]
        envelope = CryptoEnvelope.unpack(slot3_bytes)

        return (verb, args, constraints, envelope)

    def create_reply(
        self,
        status: int = EmcpError.EMCP_SUCCESS,
        result_data: Any = None,
        remaining_budget: int = 0,
    ) -> EmcpFrame:
        reply_constraints = ToolConstraints(
            token_budget=remaining_budget,
            timeout_ms=self.constraints.timeout_ms,
            max_depth_hops=max(0, self.constraints.max_depth_hops - 1),
        )
        return EmcpFrame(
            magic=self.magic,
            version=self.version,
            msg_type=MsgType.MSG_REPLY,
            opcode=self.opcode,
            flags=FrameFlags.FLAG_NONE,
            caller_pin=RELAY_PIN,
            target_pin=self.caller_pin,
            transaction_id=self.transaction_id,
            capabilities_mask=self.capabilities_mask,
            status=status,
            verb="tools/reply",
            args=result_data,
            constraints=reply_constraints,
        )
