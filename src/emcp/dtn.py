"""
EMCP Disruption-Tolerant Networking (DTN) Module.
Implements RFC 9171 / DARPA Bundle Protocol custody transfer and store-and-forward
resilience for agent tools operating on remote, lossy, or intermittent edge links.
"""

from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
import heapq
import time
from typing import Dict, List, Optional, Set, Tuple


class CustodySignal(IntEnum):
    CUSTODY_ACCEPTED = 1   # Custodian node successfully stored tool invocation/result
    CUSTODY_REFUSED = 2    # Custodian node rejected bundle (buffer full, expired, etc.)
    CUSTODY_RELEASED = 3   # Previous custodian node released responsibility after handover
    DELIVERY_RECEIPT = 4   # Tool or agent successfully received and processed bundle


class CustodyRefusalReason(IntEnum):
    NONE = 0
    BUFFER_EXHAUSTED = 1
    LIFETIME_EXPIRED = 2
    UNTRUSTED_CUSTODIAN = 3
    DUPLICATE_BUNDLE = 4
    HOP_COUNT_EXCEEDED = 5


@dataclass
class ToolBundle:
    """
    DTN Bundle Protocol envelope wrapping an EMCP frame for remote tool invocation/reply.
    """
    bundle_id: int
    caller_pin: int
    target_tool_pin: int
    custodian_pin: int
    creation_time_s: float
    lifetime_s: float = 3600.0
    custody_transfer_requested: bool = True
    payload: bytes = b""
    hops: int = 0
    max_hops: int = 16

    def is_expired(self, now: Optional[float] = None) -> bool:
        t = now if now is not None else time.time()
        return (t - self.creation_time_s) > self.lifetime_s

    def size_bytes(self) -> int:
        return 64 + len(self.payload)


@dataclass(frozen=True)
class CustodyReport:
    bundle_id: int
    signal: CustodySignal
    reporter_pin: int
    reason: CustodyRefusalReason = CustodyRefusalReason.NONE
    timestamp: float = field(default_factory=time.time)


class ToolCustodyStore:
    """
    Store-and-forward DTN custody manager for remote tool execution.
    Retains invocation and result frames until downstream confirms custody acceptance.
    """

    def __init__(
        self,
        local_pin: int,
        max_bundles: int = 1000,
        max_storage_bytes: int = 64 * 1024 * 1024,  # 64 MB
        seen_cache_size: int = 5000,
    ) -> None:
        self.local_pin = local_pin
        self.max_bundles = max_bundles
        self.max_storage_bytes = max_storage_bytes
        self.seen_cache_size = seen_cache_size

        self._bundles: Dict[int, ToolBundle] = {}
        self._storage_used: int = 0
        self._seen_ids: Set[int] = set()
        self._seen_order: deque = deque()
        # (expiry, bundle_id) min-heap for O(1) "anything expired?" checks.
        # Entries are lazily deleted: release_custody leaves the heap alone
        # and prune_expired skips entries whose bundle is already gone.
        self._expiry_heap: List[Tuple[float, int]] = []

    @property
    def bundle_count(self) -> int:
        return len(self._bundles)

    @property
    def storage_used(self) -> int:
        return self._storage_used

    def _mark_seen(self, bundle_id: int) -> None:
        if bundle_id not in self._seen_ids:
            self._seen_ids.add(bundle_id)
            self._seen_order.append(bundle_id)
            if len(self._seen_order) > self.seen_cache_size:
                # popleft: O(1) ring eviction (list.pop(0) shifted the
                # whole ring on every bundle past capacity)
                oldest = self._seen_order.popleft()
                self._seen_ids.discard(oldest)

    def _reap_expired(self, now: float) -> bool:
        """Pops the expiry heap and releases bundles that are gone.

        Returns True if at least one bundle was released (capacity freed).
        Heap entries are lazily deleted: entries for bundles released
        out-of-band (custody reports, forward_bundle) are skipped here.
        """
        freed = False
        while self._expiry_heap:
            expiry, bundle_id = self._expiry_heap[0]
            if expiry > now:
                break
            heapq.heappop(self._expiry_heap)
            bundle = self._bundles.get(bundle_id)
            if bundle is not None and bundle.is_expired(now=now):
                self.release_custody(bundle_id)
                freed = True
        return freed

    def admit_bundle(
        self,
        bundle: ToolBundle,
        now: Optional[float] = None,
    ) -> Tuple[bool, CustodyReport]:
        t = now if now is not None else time.time()

        if bundle.is_expired(now=t):
            return False, CustodyReport(
                bundle_id=bundle.bundle_id,
                signal=CustodySignal.CUSTODY_REFUSED,
                reporter_pin=self.local_pin,
                reason=CustodyRefusalReason.LIFETIME_EXPIRED,
                timestamp=t,
            )

        if bundle.hops >= bundle.max_hops:
            return False, CustodyReport(
                bundle_id=bundle.bundle_id,
                signal=CustodySignal.CUSTODY_REFUSED,
                reporter_pin=self.local_pin,
                reason=CustodyRefusalReason.HOP_COUNT_EXCEEDED,
                timestamp=t,
            )

        if bundle.bundle_id in self._seen_ids or bundle.bundle_id in self._bundles:
            return False, CustodyReport(
                bundle_id=bundle.bundle_id,
                signal=CustodySignal.CUSTODY_REFUSED,
                reporter_pin=self.local_pin,
                reason=CustodyRefusalReason.DUPLICATE_BUNDLE,
                timestamp=t,
            )

        bundle_size = bundle.size_bytes()
        if (
            len(self._bundles) >= self.max_bundles
            or (self._storage_used + bundle_size) > self.max_storage_bytes
        ):
            # Reclaim expired bundles before refusing: a full store that
            # has aged bundles should accept new traffic, not bounce it.
            if not self._reap_expired(t):
                return False, CustodyReport(
                    bundle_id=bundle.bundle_id,
                    signal=CustodySignal.CUSTODY_REFUSED,
                    reporter_pin=self.local_pin,
                    reason=CustodyRefusalReason.BUFFER_EXHAUSTED,
                    timestamp=t,
                )
            if (
                len(self._bundles) >= self.max_bundles
                or (self._storage_used + bundle_size) > self.max_storage_bytes
            ):
                return False, CustodyReport(
                    bundle_id=bundle.bundle_id,
                    signal=CustodySignal.CUSTODY_REFUSED,
                    reporter_pin=self.local_pin,
                    reason=CustodyRefusalReason.BUFFER_EXHAUSTED,
                    timestamp=t,
                )

        self._mark_seen(bundle.bundle_id)
        if bundle.custody_transfer_requested:
            bundle.custodian_pin = self.local_pin

        self._bundles[bundle.bundle_id] = bundle
        self._storage_used += bundle_size
        heapq.heappush(
            self._expiry_heap,
            (bundle.creation_time_s + bundle.lifetime_s, bundle.bundle_id),
        )

        signal = (
            CustodySignal.CUSTODY_ACCEPTED
            if bundle.custody_transfer_requested
            else CustodySignal.DELIVERY_RECEIPT
        )

        return True, CustodyReport(
            bundle_id=bundle.bundle_id,
            signal=signal,
            reporter_pin=self.local_pin,
            reason=CustodyRefusalReason.NONE,
            timestamp=t,
        )

    def forward_bundle(
        self,
        bundle_id: int,
        next_hop_pin: int,
        now: Optional[float] = None,
    ) -> Tuple[Optional[ToolBundle], Optional[CustodyReport]]:
        t = now if now is not None else time.time()
        bundle = self._bundles.get(bundle_id)
        if not bundle:
            return None, None

        if bundle.is_expired(now=t):
            self.release_custody(bundle_id)
            return None, CustodyReport(
                bundle_id=bundle_id,
                signal=CustodySignal.CUSTODY_REFUSED,
                reporter_pin=self.local_pin,
                reason=CustodyRefusalReason.LIFETIME_EXPIRED,
                timestamp=t,
            )

        bundle.hops += 1
        if bundle.hops > bundle.max_hops:
            self.release_custody(bundle_id)
            return None, CustodyReport(
                bundle_id=bundle_id,
                signal=CustodySignal.CUSTODY_REFUSED,
                reporter_pin=self.local_pin,
                reason=CustodyRefusalReason.HOP_COUNT_EXCEEDED,
                timestamp=t,
            )

        return bundle, None

    def process_custody_report(self, report: CustodyReport) -> bool:
        if report.signal in (CustodySignal.CUSTODY_ACCEPTED, CustodySignal.DELIVERY_RECEIPT):
            return self.release_custody(report.bundle_id)
        return False

    def release_custody(self, bundle_id: int) -> bool:
        bundle = self._bundles.pop(bundle_id, None)
        if bundle is not None:
            self._storage_used = max(0, self._storage_used - bundle.size_bytes())
            return True
        return False

    def prune_expired(self, now: Optional[float] = None) -> List[int]:
        t = now if now is not None else time.time()
        # Heap fast path: O(k log n) for k expired bundles (often k=0 ->
        # O(1)) instead of scanning the whole table on every call.
        expired: List[int] = []
        while self._expiry_heap:
            expiry, bundle_id = self._expiry_heap[0]
            if expiry > t:
                break
            heapq.heappop(self._expiry_heap)
            bundle = self._bundles.get(bundle_id)
            if bundle is not None and bundle.is_expired(now=t):
                expired.append(bundle_id)
                self.release_custody(bundle_id)
        return expired
