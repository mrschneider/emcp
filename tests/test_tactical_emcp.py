"""
Tactical Resiliency Test Suite for EMCP:
1. DDS C4I Tool QoS contracts (Requested vs Offered)
2. Redundant Tool Ownership Arbitration & automatic heartbeat failover
3. Tool Execution Deadline Monitoring
4. RFC 9171 / DARPA DTN Custody Transfer for remote edge tools
"""

import unittest

from emcp.qos import (
    DurabilityKind,
    OwnershipKind,
    QosContractEvaluator,
    QosProfile,
    ReliabilityKind,
    ToolDeadlineMonitor,
    ToolOwnershipArbitrator,
)
from emcp.dtn import (
    CustodyRefusalReason,
    CustodySignal,
    ToolBundle,
    ToolCustodyStore,
)


class TestEmcpTacticalResiliency(unittest.TestCase):
    def test_qos_tool_rxo_compatibility(self):
        """RxO contract compatibility checks between agent caller and tool provider."""
        tool_offered = QosProfile(
            reliability=ReliabilityKind.RELIABLE,
            durability=DurabilityKind.TRANSIENT_LOCAL,
            ownership=OwnershipKind.EXCLUSIVE,
            deadline_ms=100,
            latency_budget_ms=20,
        )

        # Compatible caller request
        caller_req = QosProfile(
            reliability=ReliabilityKind.RELIABLE,
            durability=DurabilityKind.TRANSIENT_LOCAL,
            ownership=OwnershipKind.EXCLUSIVE,
            deadline_ms=200,  # Caller tolerates 200ms, tool promises 100ms (OK)
            latency_budget_ms=50,
        )
        ok, err = QosContractEvaluator.check_rxo_compatibility(tool_offered, caller_req)
        self.assertTrue(ok)
        self.assertIsNone(err)

        # Incompatible reliability: caller demands RELIABLE, tool only offers BEST_EFFORT
        unreliable_tool = QosProfile(reliability=ReliabilityKind.BEST_EFFORT)
        ok, err = QosContractEvaluator.check_rxo_compatibility(unreliable_tool, caller_req)
        self.assertFalse(ok)
        self.assertIn("Incompatible Reliability", str(err))

        # Incompatible deadline: caller requires 50ms turnaround, tool offers 100ms
        strict_caller = QosProfile(ownership=OwnershipKind.EXCLUSIVE, deadline_ms=50)
        ok, err = QosContractEvaluator.check_rxo_compatibility(tool_offered, strict_caller)
        self.assertFalse(ok)
        self.assertIn("Incompatible Deadline", str(err))

    def test_qos_redundant_tool_failover(self):
        """Redundant tool instance failover upon missed liveliness lease."""
        arbitrator = ToolOwnershipArbitrator()
        tool_name = "query_database"
        t0 = 1000.0

        tool_primary_pin = 0x7070_1111_2222_3333  # Running on .70
        tool_backup_pin = 0x1818_4444_5555_6666   # Running on .18

        # Register primary (strength 200, lease 5s) and backup (strength 100, lease 5s)
        arbitrator.register_candidate(tool_name, tool_primary_pin, strength=200, lease_ms=5000, now=t0)
        arbitrator.register_candidate(tool_name, tool_backup_pin, strength=100, lease_ms=5000, now=t0)

        # Primary has higher strength -> owns execution
        self.assertEqual(arbitrator.get_owner(tool_name, now=t0), tool_primary_pin)

        # Primary heartbeats at t0 + 2s
        arbitrator.heartbeat(tool_primary_pin, now=t0 + 2.0)
        arbitrator.heartbeat(tool_backup_pin, now=t0 + 6.0)

        # At t0 + 8s:
        # Primary last heartbeat was t0 + 2s (6s elapsed > 5s lease -> DEAD!)
        # Backup last heartbeat was t0 + 6s (2s elapsed <= 5s lease -> ALIVE)
        # Automatic failover occurs! Tool queries now route to backup!
        self.assertEqual(arbitrator.get_owner(tool_name, now=t0 + 8.0), tool_backup_pin)

    def test_qos_tool_deadline_monitor(self):
        """Monitors slow tool turnaround against agreed SLA deadline."""
        monitor = ToolDeadlineMonitor()
        t0 = 1000.0
        caller = 0x1234

        monitor.start_deadline(tx_id=1, caller_pin=caller, tool_name="quick_read", deadline_ms=50, now=t0)
        monitor.start_deadline(tx_id=2, caller_pin=caller, tool_name="slow_search", deadline_ms=200, now=t0)

        # Complete quick_read within 30ms
        self.assertTrue(monitor.acknowledge(tx_id=1))

        # At t0 + 250ms -> slow_search exceeded 200ms
        violations = monitor.check_violations(now=t0 + 0.250)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].violation_type, "DEADLINE_MISSED")
        self.assertEqual(violations[0].target_tool, "slow_search")

    def test_dtn_tool_custody_transfer(self):
        """Store-and-forward custody transfer across edge nodes for tool execution."""
        caller_pin = 0xAAAA
        relay_pin = 0xBBBB
        remote_tool_pin = 0xCCCC

        store_caller = ToolCustodyStore(local_pin=caller_pin)
        store_relay = ToolCustodyStore(local_pin=relay_pin)
        t0 = 1000.0

        bundle = ToolBundle(
            bundle_id=301,
            caller_pin=caller_pin,
            target_tool_pin=remote_tool_pin,
            custodian_pin=caller_pin,
            creation_time_s=t0,
            lifetime_s=600.0,
            custody_transfer_requested=True,
            payload=b'{"sql": "COMPUTE HEAVY TELEMETRY"}',
        )

        # Caller assumes custody in local store
        ok, _ = store_caller.admit_bundle(bundle, now=t0)
        self.assertTrue(ok)
        self.assertEqual(store_caller.bundle_count, 1)

        # Network link temporarily unavailable, then opens: forward to relay
        fwd, _ = store_caller.forward_bundle(301, next_hop_pin=relay_pin, now=t0 + 10.0)
        self.assertIsNotNone(fwd)
        assert fwd is not None
        self.assertEqual(fwd.hops, 1)

        # Relay accepts custody
        accepted, report = store_relay.admit_bundle(fwd, now=t0 + 10.0)
        self.assertTrue(accepted)
        self.assertEqual(report.signal, CustodySignal.CUSTODY_ACCEPTED)

        # Caller receives report and safely releases local custody
        released = store_caller.process_custody_report(report)
        self.assertTrue(released)
        self.assertEqual(store_caller.bundle_count, 0)
        self.assertEqual(store_relay.bundle_count, 1)


if __name__ == "__main__":
    unittest.main()
