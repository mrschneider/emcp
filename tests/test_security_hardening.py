"""Regression tests for capability policy and escrow accounting."""
import unittest

from emcp.budget import TokenBudgetLedger
from emcp.adapter_mcp import McpLegacyAdapter
from emcp.constants import Capability


class HardeningTests(unittest.TestCase):
    def test_commit_releases_full_reservation(self):
        ledger = TokenBudgetLedger(capacity=100)
        for tx in range(10):
            self.assertTrue(ledger.escrow(tx, 80))
            self.assertTrue(ledger.spend(tx, 30))
            self.assertEqual(ledger.commit(tx), 50)
            self.assertEqual(ledger.allocated, 0)

    def test_duplicate_transaction_refused(self):
        ledger = TokenBudgetLedger(capacity=100)
        self.assertTrue(ledger.escrow(1, 30))
        self.assertFalse(ledger.escrow(1, 20))
        self.assertEqual(ledger.allocated, 30)
        self.assertTrue(ledger.refund(1))
        self.assertEqual(ledger.allocated, 0)

    def test_unmapped_mcp_tool_fails_closed(self):
        def dispatcher(request):
            return {"result": {"tools": [{"name": "dangerous"}]}}
        with self.assertRaises(RuntimeError):
            McpLegacyAdapter("legacy", dispatcher)

    def test_explicit_public_mcp_tool_allowed(self):
        def dispatcher(request):
            return {"result": {"tools": [{"name": "public"}]}}
        adapter = McpLegacyAdapter(
            "legacy", dispatcher,
            tool_capabilities={"public": Capability.NONE},
        )
        self.assertIn("public", adapter.tools)


if __name__ == "__main__":
    unittest.main()
