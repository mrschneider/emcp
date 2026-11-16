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

    def _build_request_frame(
        self,
        server: EmcpServer,
        opcode: int,
        verb: str,
        args: Any,
        constraints: ToolConstraints,
        flags: FrameFlags,
    ) -> EmcpFrame:
        """Shared inline construction for outgoing request frames.

        Skips the __setattr__ cache-invalidation hook on every field write
        (same pattern as EmcpFrame.unpack): a brand-new frame has no caches
        to invalidate, so the hook would be pure overhead.  A single
        __dict__.update() is ~3x faster than 15 individual
        object.__setattr__ calls.
        """
        frame = EmcpFrame.__new__(EmcpFrame)
        frame.__dict__.update({
            "magic": EmcpFrame.magic,
            "version": EmcpFrame.version,
            "msg_type": MsgType.MSG_SEND,
            "opcode": opcode,
            "flags": flags,
            "caller_pin": self.identity.pin,
            "target_pin": server.pin,
            "transaction_id": self._tx_counter.__next__(),
            "capabilities_mask": int(self.allowed_capabilities),
            "status": EmcpError.EMCP_SUCCESS,
            "verb": verb,
            "args": args,
            "constraints": constraints,
            "envelope": CryptoEnvelope(),
            "raw_payload": None,
        })
        return frame

    async def call_tool(
        self,
        server: EmcpServer,
        tool_name: str,
        args: Optional[Dict[str, Any]] = None,
        token_budget: int = 4000,
        timeout_ms: int = 5000,
    ) -> EmcpFrame:
        """Invokes a tool on an EmcpServer synchronously."""
        frame = self._build_request_frame(
            server,
            OpCode.OP_TOOLS_CALL,
            tool_name,
            args or {},
            ToolConstraints(
                token_budget=token_budget,
                timeout_ms=timeout_ms,
                max_depth_hops=10,
            ),
            FrameFlags.FLAG_SIGNED if self.sign_frames else FrameFlags.FLAG_NONE,
        )
        if self.sign_frames:
            self.identity.sign_frame(frame)

        reply = await server.handle_frame(frame)
        return reply

    async def list_tools(self, server: EmcpServer) -> Dict[str, Any]:
        """Queries the server's registered tools."""
        frame = self._build_request_frame(
            server,
            OpCode.OP_TOOLS_LIST,
            "tools/list",
            None,
            ToolConstraints(),
            FrameFlags.FLAG_NONE,
        )
        reply = await server.handle_frame(frame)
        return reply.args or {}
