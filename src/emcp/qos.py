"""
EMCP Quality of Service (QoS) & Tool Ownership Arbitration Module.
Implements military C4I / OMG DDS (Data Distribution Service) QoS contract semantics
and failover arbitration for distributed agent tool meshes.
"""

from dataclasses import dataclass, field
from enum import IntEnum
import time
from typing import Dict, List, Optional, Tuple


class ReliabilityKind(IntEnum):
    BEST_EFFORT = 0  # Fire-and-forget; tool output frames may drop during network congestion
    RELIABLE = 1     # Guaranteed tool delivery; requires transport/rendezvous acknowledgement


class DurabilityKind(IntEnum):
    VOLATILE = 0         # Tool results not retained after initial delivery
    TRANSIENT_LOCAL = 1  # In-memory history maintained for reconnecting clients
    PERSISTENT = 2       # Chained to append-only persistent storage across restarts


class OwnershipKind(IntEnum):
    SHARED = 0     # Multiple tool instances can concurrently execute/serve the tool name
    EXCLUSIVE = 1  # Exactly one primary tool instance holds execution lease at any given time


class LivelinessKind(IntEnum):
    AUTOMATIC = 0              # Keepalive inferred from transport/rendezvous frames
    MANUAL_BY_PARTICIPANT = 1  # Explicit pulse heartbeats required within lease window


@dataclass(frozen=True)
class QosProfile:
    """
    Contractual QoS specification governing communication between callers and tools.
    Follows DDS Requested vs. Offered (RxO) contract model.
    """
    reliability: ReliabilityKind = ReliabilityKind.RELIABLE
    durability: DurabilityKind = DurabilityKind.VOLATILE
    ownership: OwnershipKind = OwnershipKind.SHARED
    ownership_strength: int = 0          # 0..1000; higher strength preempts lower in EXCLUSIVE mode
    deadline_ms: int = 0                 # Max tolerated turnaround latency (0 = unlimited)
    latency_budget_ms: int = 0           # Hint to transport layer for batching vs immediate flush
    liveliness_lease_ms: int = 30000     # Lease period for liveliness checks before failover


@dataclass
class QosViolation:
    violation_type: str  # 'RXO_INCOMPATIBLE', 'DEADLINE_MISSED', 'LIVELINESS_LOST'
    entity_pin: int
    target_tool: str
    details: str
    timestamp: float = field(default_factory=time.time)


class QosContractEvaluator:
    """
    Evaluates DDS Requested vs. Offered (RxO) contract compatibility.
    A caller requesting a contract can only bind to a tool provider offering
    an equal or strictly stronger guarantee.
    """

    @staticmethod
    def check_rxo_compatibility(
        offered: QosProfile,
        requested: QosProfile,
    ) -> Tuple[bool, Optional[str]]:
        # 1. Reliability: Offered must be >= Requested
        if requested.reliability > offered.reliability:
            return (
                False,
                f"Incompatible Reliability: requested {requested.reliability.name} "
                f"but offered {offered.reliability.name}",
            )

        # 2. Durability: Offered must be >= Requested
        if requested.durability > offered.durability:
            return (
                False,
                f"Incompatible Durability: requested {requested.durability.name} "
                f"but offered {offered.durability.name}",
            )

        # 3. Ownership: Ownership kinds must match
        if requested.ownership != offered.ownership:
            return (
                False,
                f"Incompatible Ownership kind: requested {requested.ownership.name} "
                f"vs offered {offered.ownership.name}",
            )

        # 4. Deadline: Offered deadline must be <= Requested deadline (if requested > 0)
        if requested.deadline_ms > 0:
            if offered.deadline_ms == 0 or offered.deadline_ms > requested.deadline_ms:
                return (
                    False,
                    f"Incompatible Deadline: requested {requested.deadline_ms}ms "
                    f"cannot be satisfied by offered {offered.deadline_ms}ms",
                )

        # 5. Latency Budget: Offered must be <= Requested (if requested > 0)
        if requested.latency_budget_ms > 0:
            if offered.latency_budget_ms > requested.latency_budget_ms:
                return (
                    False,
                    f"Incompatible Latency Budget: requested {requested.latency_budget_ms}ms "
                    f"exceeded by offered {offered.latency_budget_ms}ms",
                )

        return True, None


@dataclass
class ToolCandidateRegistration:
    tool_pin: int
    strength: int
    lease_ms: int
    last_heartbeat: float


class ToolOwnershipArbitrator:
    """
    DDS Exclusive Ownership Arbitrator for redundant tool instances.
    Tracks candidate tool providers by ownership strength. If the active
    primary tool misses its liveliness lease, execution fails over automatically
    to the next-highest live replica tool instance.
    """

    def __init__(self) -> None:
        # tool_name -> {tool_pin -> ToolCandidateRegistration}
        self._tools: Dict[str, Dict[int, ToolCandidateRegistration]] = {}
        # tool_name -> current_owner_pin
        self._active_owners: Dict[str, Optional[int]] = {}
        # Reverse index tool_pin -> set of tool names, so heartbeat() is
        # O(1) instead of scanning every tool's candidate table on every
        # pulse (heartbeats are the hottest path in a mesh: one per
        # candidate per lease window).
        self._pin_to_tools: Dict[int, set] = {}

    def register_candidate(
        self,
        tool_name: str,
        tool_pin: int,
        strength: int = 100,
        lease_ms: int = 30000,
        now: Optional[float] = None,
    ) -> None:
        t = now if now is not None else time.time()
        if tool_name not in self._tools:
            self._tools[tool_name] = {}
        self._tools[tool_name][tool_pin] = ToolCandidateRegistration(
            tool_pin=tool_pin,
            strength=strength,
            lease_ms=lease_ms,
            last_heartbeat=t,
        )
        self._pin_to_tools.setdefault(tool_pin, set()).add(tool_name)
        self.evaluate_tool(tool_name, now=t)

    def unregister_candidate(self, tool_name: str, tool_pin: int, now: Optional[float] = None) -> None:
        t = now if now is not None else time.time()
        if tool_name in self._tools and tool_pin in self._tools[tool_name]:
            del self._tools[tool_name][tool_pin]
            if not self._tools[tool_name]:
                del self._tools[tool_name]
            pins = self._pin_to_tools.get(tool_pin)
            if pins is not None:
                pins.discard(tool_name)
                if not pins:
                    del self._pin_to_tools[tool_pin]
            if self._active_owners.get(tool_name) == tool_pin:
                self._active_owners[tool_name] = None
            self.evaluate_tool(tool_name, now=t)

    def heartbeat(self, tool_pin: int, now: Optional[float] = None) -> None:
        t = now if now is not None else time.time()
        # O(1) reverse-index lookup; the old version scanned every
        # tool's candidate table on every pulse.
        for tool_name in self._pin_to_tools.get(tool_pin, ()):
            candidates = self._tools.get(tool_name)
            if candidates and tool_pin in candidates:
                candidates[tool_pin].last_heartbeat = t

    def evaluate_tool(self, tool_name: str, now: Optional[float] = None) -> Optional[int]:
        t = now if now is not None else time.time()
        candidates = self._tools.get(tool_name, {})
        if not candidates:
            self._active_owners[tool_name] = None
            return None

        # Filter live candidates
        live_candidates: List[ToolCandidateRegistration] = []
        for c in candidates.values():
            elapsed_ms = (t - c.last_heartbeat) * 1000.0
            if elapsed_ms <= c.lease_ms:
                live_candidates.append(c)

        if not live_candidates:
            self._active_owners[tool_name] = None
            return None

        # Sort by strength desc, break ties by higher tool_pin
        live_candidates.sort(key=lambda c: (c.strength, c.tool_pin), reverse=True)
        winner = live_candidates[0].tool_pin
        self._active_owners[tool_name] = winner
        return winner

    def get_owner(self, tool_name: str, now: Optional[float] = None) -> Optional[int]:
        return self.evaluate_tool(tool_name, now=now)


@dataclass
class _PendingDeadline:
    tx_id: int
    caller_pin: int
    tool_name: str
    deadline_ms: int
    start_time: float


class ToolDeadlineMonitor:
    """
    Monitors tool execution turnaround against agreed contractual deadlines.
    """

    def __init__(self) -> None:
        self._pending: Dict[int, _PendingDeadline] = {}

    def start_deadline(
        self,
        tx_id: int,
        caller_pin: int,
        tool_name: str,
        deadline_ms: int,
        now: Optional[float] = None,
    ) -> None:
        if deadline_ms <= 0:
            return
        t = now if now is not None else time.time()
        self._pending[tx_id] = _PendingDeadline(
            tx_id=tx_id,
            caller_pin=caller_pin,
            tool_name=tool_name,
            deadline_ms=deadline_ms,
            start_time=t,
        )

    def acknowledge(self, tx_id: int) -> bool:
        return self._pending.pop(tx_id, None) is not None

    def check_violations(self, now: Optional[float] = None) -> List[QosViolation]:
        t = now if now is not None else time.time()
        violations: List[QosViolation] = []
        expired_tx_ids: List[int] = []

        for tx_id, item in self._pending.items():
            elapsed_ms = (t - item.start_time) * 1000.0
            if elapsed_ms > item.deadline_ms:
                violations.append(
                    QosViolation(
                        violation_type="DEADLINE_MISSED",
                        entity_pin=item.caller_pin,
                        target_tool=item.tool_name,
                        details=(
                            f"Tool execution {item.tool_name} (tx {tx_id}) elapsed {elapsed_ms:.1f}ms "
                            f"exceeded deadline of {item.deadline_ms}ms"
                        ),
                        timestamp=t,
                    )
                )
                expired_tx_ids.append(tx_id)

        for tx_id in expired_tx_ids:
            del self._pending[tx_id]

        return violations
