"""
EMCP Tool Server implementation with PlatSec enforcement and Token Budget Escrow.
"""

from __future__ import annotations
import asyncio
import inspect
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

import math

from .budget import TokenBudgetLedger
from .constants import Capability, EmcpError, OpCode
from .frame import EmcpFrame, _dumps, _HAVE_ORJSON
from .security import PlatSecGate, ToolIdentity


def _has_non_finite(obj: Any) -> bool:
    """Iteratively check if *obj* contains any non-finite float (inf/nan).

    orjson silently serialises non-finite floats as ``null``; stdlib json
    preserves them as ``Infinity`` / ``NaN``.  This detector is used to
    decide whether a stdlib re-encode is needed.  It walks the structure
    iteratively (no recursion-limit risk) and short-circuits on the first
    non-finite value found.
    """
    stack = [obj]
    while stack:
        v = stack.pop()
        if isinstance(v, float):
            if not math.isfinite(v):
                return True
        elif isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
    return False


@dataclass
class ToolDefinition:
    name: str
    description: str
    handler: Callable[..., Any]
    required_caps: Capability = Capability.NONE
    input_schema: Dict[str, Any] = field(default_factory=dict)
    default_max_tokens: int = 4000
    # Cached once at registration: inspect.iscoroutinefunction costs
    # ~1µs and used to run on every single frame.
    is_async: bool = False


class EmcpServer:
    """
    Enhanced Model Context Protocol (EMCP) Server.
    Hosts tools with strict capability gating and token budgeting.
    """

    def __init__(
        self,
        name: str = "emcp-server",
        identity: Optional[ToolIdentity] = None,
        allowed_capabilities: Capability = Capability.NONE,
        token_ledger_capacity: int = 1_000_000,
        verify_signatures: bool = False,
    ):
        self.name = name
        self.identity = identity or ToolIdentity.generate()
        self.allowed_capabilities = allowed_capabilities
        self.gate = PlatSecGate(allowed_capabilities=allowed_capabilities, strict_mode=True)
        self.ledger = TokenBudgetLedger(capacity=token_ledger_capacity)
        self.tools: Dict[str, ToolDefinition] = {}
        # Opt-in Ed25519 verification. Off by default: the in-process
        # transport is trusted and signing costs ~40µs/frame. For network
        # transports, enable and register each caller with register_identity.
        self.verify_signatures = verify_signatures
        self._caller_identities: Dict[int, ToolIdentity] = {}
        # Cached tools/list catalogue. list_tools() rebuilt the full
        # schema dict on every request — the hottest read path in a mesh
        # (every caller lists tools on connect and on reconnect).
        self._tool_catalog: Optional[Dict[str, Any]] = None

    def register_identity(self, identity: ToolIdentity) -> None:
        """Registers a caller identity so verify_signatures can check it."""
        self._caller_identities[identity.pin] = identity

    @property
    def pin(self) -> int:
        return self.identity.pin

    @property
    def pin_hex(self) -> str:
        return self.identity.pin_hex

    def tool(
        self,
        name: Optional[str] = None,
        description: str = "",
        required_caps: Capability = Capability.NONE,
        input_schema: Optional[Dict[str, Any]] = None,
        default_max_tokens: int = 4000,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator to register a tool with PlatSec capability gates."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or func.__name__
            doc = description or (func.__doc__ or "").strip()
            schema = input_schema or self._generate_simple_schema(func)

            self.tools[tool_name] = ToolDefinition(
                name=tool_name,
                description=doc,
                handler=func,
                required_caps=required_caps,
                input_schema=schema,
                default_max_tokens=default_max_tokens,
                is_async=inspect.iscoroutinefunction(func),
            )
            self._tool_catalog = None  # invalidate: registration changed the catalogue
            return func

        return decorator

    def _generate_simple_schema(self, func: Callable[..., Any]) -> Dict[str, Any]:
        sig = inspect.signature(func)
        properties: Dict[str, Any] = {}
        required: list[str] = []

        for p_name, param in sig.parameters.items():
            properties[p_name] = {"type": "string"}
            if param.default is inspect.Parameter.empty:
                required.append(p_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    def list_tools(self) -> Dict[str, Any]:
        """Returns standard MCP-compatible tool schema catalogue (cached)."""
        if self._tool_catalog is None:
            self._tool_catalog = {
                "tools": [
                    {
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                        "requiredCapabilities": int(t.required_caps),
                    }
                    for t in self.tools.values()
                ]
            }
        return self._tool_catalog

    def __setattr__(self, name: str, value: Any) -> None:
        # External mutation of the tools dict (del server.tools[x],
        # server.tools[x] = ...) must invalidate the list_tools cache.
        if name == "tools":
            self.__dict__["_tool_catalog"] = None
        super().__setattr__(name, value)

    async def handle_frame(self, frame: EmcpFrame) -> EmcpFrame:
        """
        Processes incoming EMCP frame synchronously with PlatSec checks and budget escrow.
        """
        # 1. Handle tool listing
        if frame.opcode == OpCode.OP_TOOLS_LIST or frame.verb == "tools/list":
            return frame.create_reply(
                status=EmcpError.EMCP_SUCCESS,
                result_data=self.list_tools(),
            )

        # 2. Tool invocation
        tool_name = frame.verb
        if tool_name.startswith("tools/"):
            tool_name = tool_name[6:]

        tool = self.tools.get(tool_name)
        if not tool:
            return frame.create_reply(
                status=EmcpError.EMCP_ERR_TOOL_NOT_FOUND,
                result_data={"error": f"Tool '{tool_name}' not found on server"},
            )

        # 2.5 Signature verification (opt-in; untrusted transports)
        if self.verify_signatures:
            caller = self._caller_identities.get(frame.caller_pin)
            if caller is None:
                return frame.create_reply(
                    status=EmcpError.EMCP_ERR_UNKNOWN_PIN,
                    result_data={"error": f"Caller PIN 0x{frame.caller_pin:016X} not registered"},
                )
            if not caller.verify_frame(frame):
                return frame.create_reply(
                    status=EmcpError.EMCP_ERR_SIGNATURE_INVALID,
                    result_data={"error": "Frame signature verification failed"},
                )

        # 3. PlatSec Capability Verification (Fail-closed)
        if not self.gate.verify(frame.capabilities_mask, tool.required_caps):
            return frame.create_reply(
                status=EmcpError.EMCP_ERR_CAPABILITY_DENIED,
                result_data={
                    "error": "PlatSec access denied: frame lacks required capability",
                    "required": int(tool.required_caps),
                    "granted": frame.capabilities_mask,
                },
            )

        # 4. Token Budget Escrow
        budget_limit = frame.constraints.token_budget or tool.default_max_tokens
        tx_id = frame.transaction_id
        if not self.ledger.escrow(tx_id, budget_limit):
            return frame.create_reply(
                status=EmcpError.EMCP_ERR_TOKEN_OVERFLOW,
                result_data={"error": "Token budget ledger capacity exceeded on server"},
            )

        # 5. Tool Execution
        # Sync handlers run in a worker thread: a blocking handler must not
        # stall the event loop (measured: 2x300ms calls ran serially inline,
        # concurrently via to_thread). Async handlers are awaited directly.
        try:
            kwargs = frame.args if isinstance(frame.args, dict) else {}
            if tool.is_async:
                result = await tool.handler(**kwargs)
            else:
                result = await asyncio.to_thread(tool.handler, **kwargs)

            # Single JSON pass for the wire path: encode the result ONCE,
            # meter on those bytes (~4 chars/token) and stash them on the
            # reply so pack_slots reuses them instead of dumps() again.
            # orjson normalizes non-finite floats (inf/nan) to null and
            # rejects values outside its domain (big ints, non-str keys);
            # the stdlib re-encode preserves all of them.
            #
            # The `b"null" in result_json` byte scan is a fast C-level
            # filter (~85 µs on 120 KB) that catches both inf/nan and
            # legitimate None values.  When it fires, _has_non_finite()
            # walks the original Python object to distinguish the two:
            # only a genuine non-finite float triggers the stdlib
            # re-encode.  This eliminates the old false-positive where
            # any None value forced a full stdlib re-serialization.
            try:
                result_json = _dumps(result)
                if _HAVE_ORJSON and b"null" in result_json and _has_non_finite(result):
                    result_json = json.dumps(result, separators=(",", ":")).encode("utf-8")
            except (TypeError, OverflowError):
                result_json = json.dumps(result, separators=(",", ":")).encode("utf-8")
            tokens_spent = max(1, len(result_json) // 4)

            if budget_limit > 0 and not self.ledger.spend(tx_id, tokens_spent):
                self.ledger.refund(tx_id)
                return frame.create_reply(
                    status=EmcpError.EMCP_ERR_TOKEN_OVERFLOW,
                    result_data={
                        "error": f"Tool output generated {tokens_spent} tokens exceeding envelope of {budget_limit}",
                    },
                )

            remaining = self.ledger.commit(tx_id) or 0
            reply = frame.create_reply(
                status=EmcpError.EMCP_SUCCESS,
                result_data=result,
                remaining_budget=remaining,
            )
            reply._args_json = result_json
            return reply

        except asyncio.CancelledError:
            self.ledger.refund(tx_id)
            raise
        except Exception as e:
            self.ledger.refund(tx_id)
            return frame.create_reply(
                status=EmcpError.EMCP_ERR_TOOL_EXECUTION_FAILED,
                result_data={"error": f"Execution failed: {str(e)}"},
            )
