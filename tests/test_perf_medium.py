"""
Regression suite for the medium-impact performance findings (2026-10-27):

#5  ToolOwnershipArbitrator.heartbeat() is O(1) via a reverse index
    (was a full scan of every tool's candidate table per pulse).
#6  ToolCustodyStore.prune_expired() is O(k log n) via an expiry heap
    (was a full table scan per call) and admit_bundle() reclaims expired
    bundles before refusing a full store.
#7  EmcpServer.list_tools() is cached and invalidated on registration
    (was rebuilt on every tools/list request — the hottest read path).

The Rust-side fixes (escrow dropped on commit; dead deps removed) are
covered by `cargo test -p emcp-core` and `cargo build`.
"""

import time
import unittest

from emcp.dtn import CustodyRefusalReason, ToolBundle, ToolCustodyStore
from emcp.qos import ToolOwnershipArbitrator
from emcp.server import EmcpServer


class TestHeartbeatReverseIndex(unittest.TestCase):
    """#5: heartbeat() must update every tool a pin is registered under."""

    def test_heartbeat_updates_all_tools_for_pin(self):
        arb = ToolOwnershipArbitrator()
        t0 = 1000.0
        arb.register_candidate("tool-a", 7, strength=100, lease_ms=5000, now=t0)
        arb.register_candidate("tool-b", 7, strength=100, lease_ms=5000, now=t0)

        # Pulse once at t0+2s; both tools must see the fresh heartbeat.
        arb.heartbeat(7, now=t0 + 2.0)
        for tool in ("tool-a", "tool-b"):
            reg = arb._tools[tool][7]
            self.assertEqual(reg.last_heartbeat, t0 + 2.0)

    def test_heartbeat_keeps_both_live_preempts_on_strength(self):
        arb = ToolOwnershipArbitrator()
        t0 = 0.0
        arb.register_candidate("t", 1, strength=100, lease_ms=5000, now=t0)
        arb.register_candidate("t", 2, strength=200, lease_ms=5000, now=t0)
        # Both heartbeat; higher-strength pin stays owner.
        arb.heartbeat(1, now=t0 + 1.0)
        arb.heartbeat(2, now=t0 + 1.0)
        self.assertEqual(arb.get_owner("t", now=t0 + 1.0), 2)

    def test_unregister_clears_reverse_index(self):
        arb = ToolOwnershipArbitrator()
        t0 = 0.0
        arb.register_candidate("t", 5, strength=100, lease_ms=5000, now=t0)
        arb.unregister_candidate("t", 5, now=t0)
        # Reverse index must be empty; a stray heartbeat is a no-op.
        self.assertNotIn(5, arb._pin_to_tools)
        arb.heartbeat(5, now=t0 + 100.0)  # must not raise or resurrect
        self.assertIsNone(arb.get_owner("t", now=t0 + 100.0))

    def test_failover_still_works_with_reverse_index(self):
        # Mirrors the tactical suite's failover scenario, exercising the
        # new reverse-index heartbeat path end to end.
        arb = ToolOwnershipArbitrator()
        t0 = 0.0
        arb.register_candidate("t", 10, strength=200, lease_ms=5000, now=t0)
        arb.register_candidate("t", 20, strength=100, lease_ms=5000, now=t0)
        self.assertEqual(arb.get_owner("t", now=t0), 10)
        arb.heartbeat(10, now=t0 + 2.0)   # primary last pulse
        arb.heartbeat(20, now=t0 + 6.0)   # backup keeps pulsing
        # Primary: 8s since pulse > 5s lease -> dead; backup: 2s -> live.
        self.assertEqual(arb.get_owner("t", now=t0 + 8.0), 20)

    def test_heartbeat_is_sublinear_in_tool_count(self):
        # 5000 tools, one pin registered to all of them. A heartbeat must
        # not degrade to a full scan. Loose bound: the O(1) reverse-index
        # path scales with the pin's tool set, not the global table.
        arb = ToolOwnershipArbitrator()
        t0 = 0.0
        for name in range(5000):
            arb.register_candidate(f"tool-{name}", 1, strength=1, lease_ms=10_000, now=t0)
        t1 = time.perf_counter()
        for _ in range(200):
            arb.heartbeat(1, now=t0 + 1.0)
        elapsed = time.perf_counter() - t1
        # 200 heartbeats over 5000 tools should be well under a second.
        self.assertLess(elapsed, 1.0)


def _bundle(bid: int, created: float, lifetime: float = 60.0, payload: bytes = b"x" * 16) -> ToolBundle:
    return ToolBundle(
        bundle_id=bid,
        caller_pin=1,
        target_tool_pin=2,
        custodian_pin=0,
        creation_time_s=created,
        lifetime_s=lifetime,
        payload=payload,
    )


class TestDtnPrune(unittest.TestCase):
    """#6: heap-based prune + reclaim-before-refuse in admit_bundle()."""

    def test_prune_removes_only_expired(self):
        store = ToolCustodyStore(local_pin=1)
        now = 1000.0
        ok, _ = store.admit_bundle(_bundle(1, now, lifetime=10.0), now=now)
        ok2, _ = store.admit_bundle(_bundle(2, now, lifetime=10_000.0), now=now)
        self.assertTrue(ok and ok2)
        # At now+20, bundle 1 (lifetime 10s) is expired, bundle 2 is not.
        expired = store.prune_expired(now=now + 20.0)
        self.assertEqual(expired, [1])
        self.assertEqual(store.bundle_count, 1)

    def test_prune_is_noop_when_nothing_expired(self):
        store = ToolCustodyStore(local_pin=1)
        now = 1000.0
        for i in range(50):
            store.admit_bundle(_bundle(i, now, lifetime=10_000.0), now=now)
        # Nothing expired -> empty result, nothing released.
        self.assertEqual(store.prune_expired(now=now + 1.0), [])
        self.assertEqual(store.bundle_count, 50)

    def test_prune_skips_lazily_released_heap_entries(self):
        store = ToolCustodyStore(local_pin=1)
        now = 1000.0
        store.admit_bundle(_bundle(1, now, lifetime=10.0), now=now)
        # Release out-of-band (custody report path) — leaves a stale heap
        # entry that prune must skip, not double-release.
        self.assertTrue(store.release_custody(1))
        self.assertEqual(store.prune_expired(now=now + 20.0), [])
        self.assertEqual(store.bundle_count, 0)

    def test_admit_reclaims_expired_before_refusing_full_store(self):
        # A store at its bundle cap that has aged bundles must accept new
        # traffic after reclaiming, not bounce it with BUFFER_EXHAUSTED.
        store = ToolCustodyStore(local_pin=1, max_bundles=3)
        now = 1000.0
        for i in range(3):
            store.admit_bundle(_bundle(i, now, lifetime=10.0), now=now)
        # Full: a fresh long-lived bundle is refused while nothing has aged.
        ok, rep = store.admit_bundle(_bundle(99, now, lifetime=10_000.0), now=now)
        self.assertFalse(ok)
        self.assertEqual(rep.reason, CustodyRefusalReason.BUFFER_EXHAUSTED)
        # After the old bundles age out, the same admission succeeds.
        ok, rep = store.admit_bundle(_bundle(99, now + 11.0, lifetime=10_000.0), now=now + 11.0)
        self.assertTrue(ok, f"expected accept after reclaim, got {rep.reason}")
        self.assertEqual(store.bundle_count, 1)

    def test_prune_scales_sublinearly(self):
        # 20000 bundles, none expired: prune must return fast (k=0 -> O(1)
        # heap peek) rather than scanning the whole table.
        store = ToolCustodyStore(local_pin=1, max_bundles=100_000, max_storage_bytes=1 << 30)
        now = 1000.0
        for i in range(20_000):
            store.admit_bundle(_bundle(i, now, lifetime=10_000.0), now=now)
        t1 = time.perf_counter()
        self.assertEqual(store.prune_expired(now=now + 1.0), [])
        self.assertLess(time.perf_counter() - t1, 0.5)


class TestListToolsCache(unittest.TestCase):
    """#7: list_tools() is cached and invalidated on registration."""

    def _server(self) -> EmcpServer:
        s = EmcpServer(name="cache-test")

        @s.tool(name="a", description="tool a")
        def a(x: str):
            return x

        @s.tool(name="b", description="tool b")
        def b(x: str):
            return x

        return s

    def test_list_tools_is_cached(self):
        s = self._server()
        first = s.list_tools()
        second = s.list_tools()
        self.assertIs(first, second, "list_tools should return the cached catalogue")
        self.assertEqual({t["name"] for t in first["tools"]}, {"a", "b"})

    def test_registration_invalidates_cache(self):
        s = self._server()
        before = s.list_tools()
        cached = s.list_tools()
        self.assertIs(before, cached)

        @s.tool(name="c", description="tool c")
        def c(x: str):
            return x

        after = s.list_tools()
        self.assertIsNot(before, after, "registration must invalidate the cache")
        self.assertEqual({t["name"] for t in after["tools"]}, {"a", "b", "c"})

    def test_external_tools_mutation_invalidates(self):
        s = self._server()
        cached = s.list_tools()
        # External mutation of the dict must clear the cache.
        s.tools = dict(s.tools)
        self.assertIsNone(s._tool_catalog)
        fresh = s.list_tools()
        self.assertIsNot(cached, fresh)


if __name__ == "__main__":
    unittest.main()
