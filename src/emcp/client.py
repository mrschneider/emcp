"""
EMCP Client for invoking tools over local or network transports with capability claims.
"""

from __future__ import annotations
import itertools
from typing import Any, Dict, Optional

from .constants import Capability, EmcpError, FrameFlags, MsgType, OpCode
from .frame import EmcpFrame, ToolConstraints
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

        frame = EmcpFrame(
            msg_type=MsgType.MSG_SEND,
            opcode=OpCode.OP_TOOLS_CALL,
            caller_pin=self.identity.pin,
            target_pin=server.pin,
            transaction_id=tx_id,
            capabilities_mask=int(self.allowed_capabilities),
            flags=FrameFlags.FLAG_SIGNED if self.sign_frames else FrameFlags.FLAG_NONE,
            verb=tool_name,
            args=args or {},
            constraints=ToolConstraints(
                token_budget=token_budget,
                timeout_ms=timeout_ms,
                max_depth_hops=10,
            ),
        )
        if self.sign_frames:
            self.identity.sign_frame(frame)

        reply = await server.handle_frame(frame)
        return reply

    async def list_tools(self, server: EmcpServer) -> Dict[str, Any]:
        """Queries the server's registered tools."""
        tx_id = next(self._tx_counter)
        frame = EmcpFrame(
            msg_type=MsgType.MSG_SEND,
            opcode=OpCode.OP_TOOLS_LIST,
            caller_pin=self.identity.pin,
            target_pin=server.pin,
            transaction_id=tx_id,
            capabilities_mask=int(self.allowed_capabilities),
            verb="tools/list",
        )
        reply = await server.handle_frame(frame)
        return reply.args or {}
