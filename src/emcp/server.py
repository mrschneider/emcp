"""
EMCP Tool Server implementation with PlatSec enforcement and Token Budget Escrow.
"""

from __future__ import annotations
import inspect
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from .budget import TokenBudgetLedger
from .constants import Capability, EmcpError, OpCode
from .frame import EmcpFrame
from .security import PlatSecGate, ToolIdentity


@dataclass
class ToolDefinition:
    name: str
    description: str
    handler: Callable[..., Any]
    required_caps: Capability = Capability.NONE
    input_schema: Dict[str, Any] = field(default_factory=dict)
    default_max_tokens: int = 4000


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
    ):
        self.name = name
        self.identity = identity or ToolIdentity.generate()
        self.allowed_capabilities = allowed_capabilities
        self.gate = PlatSecGate(allowed_capabilities=allowed_capabilities, strict_mode=True)
        self.ledger = TokenBudgetLedger(capacity=token_ledger_capacity)
        self.tools: Dict[str, ToolDefinition] = {}

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
            )
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
        """Returns standard MCP-compatible tool schema catalogue."""
        tool_list = []
        for t in self.tools.values():
            tool_list.append({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
                "requiredCapabilities": int(t.required_caps),
            })
        return {"tools": tool_list}

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
        try:
            kwargs = frame.args if isinstance(frame.args, dict) else {}
            if inspect.iscoroutinefunction(tool.handler):
                result = await tool.handler(**kwargs)
            else:
                result = tool.handler(**kwargs)

            # Single JSON pass for the wire path: encode the result ONCE,
            # meter on those bytes (~4 chars/token) and stash them on the
            # reply so pack_slots reuses them instead of dumps() again.
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

        except Exception as e:
            self.ledger.refund(tx_id)
            return frame.create_reply(
                status=EmcpError.EMCP_ERR_TOOL_EXECUTION_FAILED,
                result_data={"error": f"Execution failed: {str(e)}"},
            )
