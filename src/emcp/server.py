"""
EMCP Tool Server implementation with PlatSec enforcement and Token Budget Escrow.
"""

from __future__ import annotations
import asyncio
import inspect
import json
import time
from collections import deque
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


def _noop_for_threshold():
    """Callable passed to asyncio.to_thread() during threshold measurement."""
    return None


def _median_to_thread_cost_us() -> float:
    """Median cost (us) of one asyncio.to_thread() no-op offload, run inline.

    Timing happens inside a worker thread so the measurement reflects the
    offload itself rather than the main loop's own scheduling overhead.
    """
    ts = []
    for _ in range(20):
        s0 = time.perf_counter()
        asyncio.to_thread(_noop_for_threshold)
        ts.append((time.perf_counter() - s0) * 1e6)
    ts.sort()
    return ts[len(ts) // 2]


async def _measure_inline_threshold() -> float:
    """Median asyncio.to_thread() offload cost, measured on a running loop.

    Used to decide whether a *sync* tool handler runs inline (in-process) or
    is offloaded to a worker thread: a fast handler offloaded to a worker
    thread pays ~79us of asyncio.to_thread() overhead on top of its own cost,
    which for quick handlers is the dominant term. The measurement is cached
    on the first sync hit so steady-state calls pay nothing but a dict lookup.
    """
    ts = []
    for _ in range(20):
        await asyncio.to_thread(_noop_for_threshold)
    for _ in range(20):
        s0 = time.perf_counter()
        await asyncio.to_thread(_noop_for_threshold)
        ts.append((time.perf_counter() - s0) * 1e6)
    ts.sort()
    return ts[len(ts) // 2]


def _sync_inline_threshold() -> float:
    """Median asyncio.to_thread() offload cost, measured on an idle loop.

    Only valid to call while the loop is idle (``run_until_complete`` inside);
    when the loop is already running the handler uses the async path above.
    """
    loop = asyncio.get_event_loop()
    for _ in range(20):
        loop.run_until_complete(asyncio.to_thread(_noop_for_threshold))
    ts = []
    for _ in range(20):
        s0 = time.perf_counter()
        loop.run_until_complete(asyncio.to_thread(_noop_for_threshold))
        ts.append((time.perf_counter() - s0) * 1e6)
    ts.sort()
    return ts[len(ts) // 2]


# First-call probe cutoff for sync handlers. The first invocation of a sync
# handler runs inline and is timed ONCE; a handler that finishes below this
# cutoff is permanently classified FAST (inline) and above it SLOW
# (to_thread). A single 100µs probe costs nothing for the fast case and
# avoids the old scheme's double execution of slow handlers (the old code
# ran the handler inline, saw it exceed the ~79µs to_thread cost, and then
# ran it a SECOND time in a worker thread — doubling the latency of every
# slow handler's first call).
_SYNC_PROBE_THRESHOLD_US = 100.0
_EXEC_PROBE = 0  # first call: run inline, time it, classify
_EXEC_FAST = 1   # learned: inline
_EXEC_SLOW = 2   # learned: offload to worker thread


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
    # Sync execution mode: _EXEC_PROBE (first call times the handler) ->
    # _EXEC_FAST (inline) or _EXEC_SLOW (worker thread). See
    # _SYNC_PROBE_THRESHOLD_US.
    exec_mode: int = _EXEC_PROBE


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
        replay_cache_size: int = 10000,
    ):
        self.name = name
        self.identity = identity or ToolIdentity.generate()
        self.allowed_capabilities = allowed_capabilities
        self.gate = PlatSecGate(allowed_capabilities=allowed_capabilities, strict_mode=True)
        self.ledger = TokenBudgetLedger(capacity=token_ledger_capacity)
        self.tools: Dict[str, ToolDefinition] = {}
        # Offload-cost reference for sync handlers (see
        # _SYNC_PROBE_THRESHOLD_US). asyncio.to_thread() offloads the call
        # to a worker thread (a full context-switch + thread-pool task)
        # which costs ~79us/op — 80% of the round-trip for a trivial
        # handler. The measurement is a server-level property of the host
        # (thread-pool scheduling latency), so one measurement is cached
        # and reused for every sync handler.
        self._sync_inline_threshold_us: Optional[float] = None
        # Opt-in Ed25519 verification. Off by default: the in-process
        # transport is trusted and signing costs ~40µs/frame. For network
        # transports, enable and register each caller with register_identity.
        self.verify_signatures = verify_signatures
        self._caller_identities: Dict[int, ToolIdentity] = {}
        # Replay / duplicate-transaction guard. A frame whose
        # transaction_id was already processed is rejected before any
        # handler runs, so a captured/re-sent frame (in-process or over a
        # network transport) cannot re-execute a tool, double-count tokens,
        # or double-apply a side effect. Bounded ring: _seen_ids is the
        # membership set and _seen_order the FIFO eviction order — the same
        # O(1) pattern used by the DTN custody store. Without the cap a
        # long-running server would grow _seen_ids forever.
        self._seen_tx_ids: set[int] = set()
        self._seen_tx_order: deque[int] = deque()
        self._replay_cache_size = replay_cache_size
        # Cached tools/list catalogue. list_tools() rebuilt the full
        # schema dict on every request — the hottest read path in a mesh
        # (every caller lists tools on connect and on reconnect).
        self._tool_catalog: Optional[Dict[str, Any]] = None

    def register_identity(self, identity: ToolIdentity) -> None:
        """Registers a caller identity so verify_signatures can check it."""
        self._caller_identities[identity.pin] = identity

    def _mark_tx_seen(self, tx_id: int) -> None:
        """Record a transaction_id as processed, evicting the oldest.

        O(1): add to the membership set and the FIFO order deque; when the
        set exceeds the cap, pop the oldest id from both views. The cap
        bounds memory for a long-running server while still covering the
        worst-case retransmit window.
        """
        self._seen_tx_ids.add(tx_id)
        self._seen_tx_order.append(tx_id)
        if len(self._seen_tx_ids) > self._replay_cache_size:
            oldest = self._seen_tx_order.popleft()
            self._seen_tx_ids.discard(oldest)

    def _is_replay(self, tx_id: int) -> bool:
        """Return True if tx_id was already processed in the window."""
        if tx_id in self._seen_tx_ids:
            return True
        self._mark_tx_seen(tx_id)
        return False

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

        # 4. Replay / duplicate-transaction guard (fail-closed).
        # Reject a frame whose transaction_id was already processed BEFORE
        # the handler runs, so a captured or re-sent frame cannot
        # re-execute a tool, double-apply a side effect, or double-count
        # tokens. The escrow step below already refuses a duplicate tx_id,
        # but only *after* the handler has run — this check short-circuits
        # before that, which is the whole point for mutating tools. tx_id
        # is caller-controlled (the client sets it), so a malicious client
        # can always reuse an id; this bounds the damage to the replay
        # window (bounded ring).
        tx_id = frame.transaction_id
        if self._is_replay(tx_id):
            return frame.create_reply(
                status=EmcpError.EMCP_ERR_REPLAY_DETECTED,
                result_data={
                    "error": f"Duplicate transaction_id 0x{tx_id:016X} rejected",
                    "transaction_id": tx_id,
                },
            )

        # 4. Token Budget Escrow
        budget_limit = frame.constraints.token_budget or tool.default_max_tokens
        if not self.ledger.escrow(tx_id, budget_limit):
            return frame.create_reply(
                status=EmcpError.EMCP_ERR_TOKEN_OVERFLOW,
                result_data={"error": "Token budget ledger capacity exceeded on server"},
            )

        # 5. Tool Execution
        # Async handlers are awaited directly. Sync handlers use a
        # one-shot probe (see _SYNC_PROBE_THRESHOLD_US): the first call
        # runs inline and is timed once; the measured cost is then
        # compared against the server's measured asyncio.to_thread()
        # offload cost and the handler is permanently classified. Fast
        # handlers stay inline (a to_thread offload of a quick handler
        # costs ~79us — 80% of the round-trip); slow handlers are
        # offloaded so they do not stall the event loop. The old
        # scheme re-ran slow handlers a second time in a worker thread
        # after the inline attempt, doubling their first-call latency.
        try:
            kwargs = frame.args if isinstance(frame.args, dict) else {}
            if tool.is_async:
                result = await tool.handler(**kwargs)
            else:
                mode = tool.exec_mode
                if mode == _EXEC_SLOW:
                    result = await asyncio.to_thread(tool.handler, **kwargs)
                else:
                    s0 = time.perf_counter()
                    result = tool.handler(**kwargs)
                    inline_us = (time.perf_counter() - s0) * 1e6
                    if mode == _EXEC_PROBE:
                        if inline_us < _SYNC_PROBE_THRESHOLD_US:
                            # Fast enough that the to_thread offload
                            # overhead (measured once per server, cached)
                            # is never worth paying: classify inline.
                            tool.exec_mode = _EXEC_FAST
                        else:
                            # Slow handler: future calls offload to a
                            # worker thread. The offload-cost measurement
                            # is only needed for logging/telemetry from
                            # here on, so take it lazily.
                            tool.exec_mode = _EXEC_SLOW
                            threshold = self._sync_inline_threshold_us
                            if threshold is None:
                                if asyncio.get_event_loop().is_running():
                                    threshold = await _measure_inline_threshold()
                                else:
                                    threshold = _sync_inline_threshold()
                                self._sync_inline_threshold_us = threshold
                    elif inline_us >= _SYNC_PROBE_THRESHOLD_US:
                        # A previously-fast handler has degraded (GIL
                        # pressure, growing data): re-classify slow.
                        tool.exec_mode = _EXEC_SLOW

            # Single JSON pass for the wire path: encode the result ONCE,
            # meter on those bytes (~4 chars/token) and stash them on the
            # reply so pack_slots reuses them instead of dumps() again.
            #
            # orjson normalizes non-finite floats (inf/-inf/nan) to null and
            # rejects values outside its domain (big ints, non-str keys);
            # the stdlib re-encode preserves all of them.  A lone orjson
            # dumps() therefore loses the NaN/Infinity round-trip contract.
            #
            # To keep that contract without paying the full-object walk on
            # every reply, use a two-stage fast path: the `b"null" in
            # result_json` byte scan is a fast C-level filter (~52 us on 120
            # KB) that catches both inf/nan and legitimate None values.  When
            # it fires, _has_non_finite() walks the original Python object to
            # distinguish the two — only a genuine non-finite float triggers
            # the stdlib re-encode.  This eliminates the old false-positive
            # where any None value forced a full stdlib re-serialization.
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
