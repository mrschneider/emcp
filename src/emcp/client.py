"""
EMCP Client for invoking tools over local or network transports with capability claims.
"""

from __future__ import annotations
import itertools
from typing import Any, Dict, Optional

from .constants import Capability, EmcpError, FrameFlags, MsgType, OpCode
from .frame import CryptoEnvelope, EmcpFrame, ToolConstraints
from .security import ToolIdentity
from .server import EmcpServer


class EmcpClient:
    """Client for calling EMCP tool servers.

    `sign_frames` is opt-in: Ed25519 signing costs ~40µs/frame in-process
    (and is proportional to payload on the wire), so it stays off by
    default. Enable it for untrusted / network transports, paired with a
    server constructed with `verify_signatures=True` and a registered
    caller identity.
    """

    def __init__(
        self,
        identity: Optional[ToolIdentity] = None,
        allowed_capabilities: Capability = Capability.NONE,
        sign_frames: bool = False,
    ):
        self.identity = identity or ToolIdentity.generate()
        self.allowed_capabilities = allowed_capabilities
        self.sign_frames = sign_frames
        self._tx_counter = itertools.count(1)

    @property
    def pin(self) -> int:
        return self.identity.pin

    @property
    def pin_hex(self) -> str:
        return self.identity.pin_hex

    async def call_tool(
        self,
        server: EmcpServer,
        tool_name: str,
        args: Optional[Dict[str, Any]] = None,
        token_budget: int = 4000,
        timeout_ms: int = 5000,
    ) -> EmcpFrame:
        """Invokes a tool on an EmcpServer synchronously."""
        tx_id = next(self._tx_counter)

        # Inline construction (same pattern as EmcpFrame.unpack):
        # skips the __setattr__ cache-invalidation hook on every field
        # write.  A brand-new frame has no caches to invalidate.
        frame = EmcpFrame.__new__(EmcpFrame)
        object.__setattr__(frame, "magic", EmcpFrame.magic)
        object.__setattr__(frame, "version", EmcpFrame.version)
        object.__setattr__(frame, "msg_type", MsgType.MSG_SEND)
        object.__setattr__(frame, "opcode", OpCode.OP_TOOLS_CALL)
        object.__setattr__(frame, "flags", FrameFlags.FLAG_SIGNED if self.sign_frames else FrameFlags.FLAG_NONE)
        object.__setattr__(frame, "caller_pin", self.identity.pin)
        object.__setattr__(frame, "target_pin", server.pin)
        object.__setattr__(frame, "transaction_id", tx_id)
        object.__setattr__(frame, "capabilities_mask", int(self.allowed_capabilities))
        object.__setattr__(frame, "status", EmcpError.EMCP_SUCCESS)
        object.__setattr__(frame, "verb", tool_name)
        object.__setattr__(frame, "args", args or {})
        object.__setattr__(frame, "constraints", ToolConstraints(
            token_budget=token_budget,
            timeout_ms=timeout_ms,
            max_depth_hops=10,
        ))
        object.__setattr__(frame, "envelope", CryptoEnvelope())
        object.__setattr__(frame, "raw_payload", None)
        if self.sign_frames:
            self.identity.sign_frame(frame)

        reply = await server.handle_frame(frame)
        return reply

    async def list_tools(self, server: EmcpServer) -> Dict[str, Any]:
        """Queries the server's registered tools."""
        tx_id = next(self._tx_counter)
        frame = EmcpFrame.__new__(EmcpFrame)
        object.__setattr__(frame, "magic", EmcpFrame.magic)
        object.__setattr__(frame, "version", EmcpFrame.version)
        object.__setattr__(frame, "msg_type", MsgType.MSG_SEND)
        object.__setattr__(frame, "opcode", OpCode.OP_TOOLS_LIST)
        object.__setattr__(frame, "flags", FrameFlags.FLAG_NONE)
        object.__setattr__(frame, "caller_pin", self.identity.pin)
        object.__setattr__(frame, "target_pin", server.pin)
        object.__setattr__(frame, "transaction_id", tx_id)
        object.__setattr__(frame, "capabilities_mask", int(self.allowed_capabilities))
        object.__setattr__(frame, "status", EmcpError.EMCP_SUCCESS)
        object.__setattr__(frame, "verb", "tools/list")
        object.__setattr__(frame, "args", None)
        object.__setattr__(frame, "constraints", ToolConstraints())
        object.__setattr__(frame, "envelope", CryptoEnvelope())
        object.__setattr__(frame, "raw_payload", None)
        reply = await server.handle_frame(frame)
        return reply.args or {}
