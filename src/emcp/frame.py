"""
EMCP 48-byte binary frame and 4-slot payload serializer.
"""

from __future__ import annotations
import json
import struct
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple

# Optional fast JSON (orjson). Falls back to stdlib json when orjson is not
# installed — the wire format is identical, so no code path changes.
try:
    import orjson as _orjson

    def _dumps(obj: Any) -> bytes:
        return _orjson.dumps(obj)

    def _loads(raw: bytes) -> Any:
        return _orjson.loads(raw)

    _HAVE_ORJSON = True
except ImportError:
    _HAVE_ORJSON = False

    def _dumps(obj: Any) -> bytes:
        return json.dumps(obj, separators=(",", ":")).encode("utf-8")

    def _loads(raw: bytes) -> Any:
        return json.loads(raw)

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
        """Mutation invalidates caches: raw_payload (parsed wire),
        _args_json (server single-encode stash) and the envelope's
        _signed_bytes (signed wire bytes), so a changed field is
        re-encoded / re-derived and never used stale.

        The signed-bytes invalidation is guarded by the presence of
        ``_signed_bytes_ref`` — the reference to the exact objects that
        were signed, set by ``ToolIdentity.sign_frame``. The common
        (unsigned) path pays one dict lookup; the envelope is only
        consulted when a signature is actually cached.
        """
        d = self.__dict__
        if name == "args" and "_args_json" in d:
            object.__setattr__(self, "_args_json", None)
        if name != "raw_payload" and d.get("raw_payload") is not None:
            object.__setattr__(self, "raw_payload", None)
        # A changed field must invalidate the signed-bytes cache too:
        # verify_frame must re-derive the bytes from the CURRENT fields,
        # not from the pre-mutation wire (tamper detection stays
        # fail-closed even for frames that arrived signed).
        if name != "envelope" and d.get("_signed_bytes_ref") is not None:
            # The frame holds a reference to the exact objects that were
            # signed (see ToolIdentity.sign_frame). If a signed field is
            # replaced, the reference no longer matches and the cached
            # signed bytes must be dropped so verify re-derives them.
            env = d.get("envelope")
            if env is not None and "_signed_bytes" in env.__dict__:
                object.__setattr__(env, "_signed_bytes", None)
            object.__setattr__(self, "_signed_bytes_ref", None)
        object.__setattr__(self, name, value)

    def _encode_args(self) -> bytes:
        """Single source of truth for slot1 encoding."""
        if self.args is None:
            return b""
        if isinstance(self.args, bytes):
            return self.args
        if isinstance(self.args, (dict, list, int, float, str, bool)):
            return _dumps(self.args)
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
        # b''.join() is measurably faster than chained + for a 5-way
        # concat (6.5 vs 16.1us on a 64KB payload): it computes the final
        # size once and copies each part exactly once.
        return b"".join((lens, slot0, slot1, slot2, slot3))

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

        # Fast-path construction: the dataclass __setattr__ override runs a
        # cache-invalidation check on *every* attribute write (12 dict lookups
        # per unpack). During unpack the fields are set once, in order, so the
        # invalidation logic is pure overhead. Build the object and assign each
        # field with object.__setattr__ to skip it entirely.
        obj = cls.__new__(cls)
        object.__setattr__(obj, "magic", magic)
        object.__setattr__(obj, "version", ver)
        object.__setattr__(obj, "msg_type", MsgType(msg_type_raw))
        object.__setattr__(obj, "opcode", opcode)
        object.__setattr__(obj, "flags", FrameFlags(flags_raw))
        object.__setattr__(obj, "caller_pin", caller_pin)
        object.__setattr__(obj, "target_pin", target_pin)
        object.__setattr__(obj, "transaction_id", tx_id)
        object.__setattr__(obj, "capabilities_mask", cap_mask)
        object.__setattr__(obj, "status", status_raw)
        object.__setattr__(obj, "verb", verb)
        object.__setattr__(obj, "args", args)
        object.__setattr__(obj, "constraints", constraints)
        object.__setattr__(obj, "envelope", envelope)
        object.__setattr__(obj, "raw_payload", payload)
        return obj

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
                # Feed the raw bytes straight to the JSON decoder. orjson's
                # native bytes path skips the separate utf-8 decode (measured
                # ~15us on a 64KB payload) and is in fact *faster* than the
                # str path (367 vs 403us/op); stdlib json.loads also accepts
                # bytes natively, so the no-orjson fallback path is unchanged.
                args = _loads(slot1_bytes)
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
