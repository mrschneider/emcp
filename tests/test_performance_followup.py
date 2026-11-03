"""Behavioral and resource regressions for the performance follow-up."""
import asyncio
import concurrent.futures
import json
import os
import sys
import threading
import tracemalloc
import unittest
from unittest.mock import patch

from emcp import EmcpClient, EmcpServer, EmcpError, EmcpFrame, McpStdioProcessAdapter
from emcp.dtn import ToolBundle, ToolCustodyStore
from emcp.qos import ToolOwnershipArbitrator

MOCK = os.path.join(os.path.dirname(__file__), "mock_mcp_server.py")


def bundle(bid, lifetime):
    return ToolBundle(bid, 1, 2, 0, 0, lifetime_s=lifetime)


class ExpiryTests(unittest.TestCase):
    def test_mixed_lifetimes_and_exact_boundary(self):
        store = ToolCustodyStore(1)
        for bid, lifetime in [(1, 100), (2, 1), (3, 10)]:
            self.assertTrue(store.admit_bundle(bundle(bid, lifetime), now=0)[0])
        self.assertEqual(store.prune_expired(now=1), [])
        self.assertEqual(store.prune_expired(now=2), [2])
        self.assertEqual(store.prune_expired(now=11), [3])
        self.assertEqual(store.bundle_count, 1)
        self.assertEqual(store.storage_used, 64)

    def test_reclaims_later_expired_bundle_at_capacity(self):
        store = ToolCustodyStore(1, max_bundles=2)
        store.admit_bundle(bundle(1, 100), now=0)
        store.admit_bundle(bundle(2, 1), now=0)
        self.assertTrue(store.admit_bundle(bundle(3, 100), now=2)[0])
        self.assertEqual(store.bundle_count, 2)

    def test_release_churn_bounds_heap_with_live_anchor(self):
        store = ToolCustodyStore(1, seen_cache_size=1)
        store.admit_bundle(bundle(0, 1000), now=0)
        for bid in range(1, 10000):
            store.admit_bundle(bundle(bid, 100), now=0)
            store.release_custody(bid)
        self.assertLessEqual(len(store._expiry_heap), 2 * store.bundle_count + 64)
        self.assertEqual(store.prune_expired(now=101), [])
        self.assertEqual(store.prune_expired(now=1001), [0])

    def test_no_expiry_does_not_allocate_full_index_copy(self):
        store = ToolCustodyStore(1, max_bundles=20001)
        for bid in range(20000):
            store.admit_bundle(bundle(bid, 100), now=0)
        tracemalloc.start()
        try:
            self.assertEqual(store.prune_expired(now=1), [])
            self.assertLess(tracemalloc.get_traced_memory()[1], 16384)
        finally:
            tracemalloc.stop()


class OwnershipTests(unittest.TestCase):
    def test_ties_failover_and_no_live_candidates(self):
        arb = ToolOwnershipArbitrator()
        arb.register_candidate('t', 1, 100, lease_ms=1000, now=0)
        arb.register_candidate('t', 2, 100, lease_ms=2000, now=0)
        arb.register_candidate('t', 3, 200, lease_ms=1000, now=0)
        self.assertEqual(arb.get_owner('t', now=1), 3)
        self.assertEqual(arb.get_owner('t', now=1.1), 2)
        self.assertIsNone(arb.get_owner('t', now=3))


class SerializationTests(unittest.IsolatedAsyncioTestCase):
    async def reply(self, result, budget=10000):
        server = EmcpServer()
        @server.tool(name='value')
        async def value():
            return result
        return await EmcpClient().call_tool(server, 'value', token_budget=budget)

    async def test_utf8_wire_bytes_are_metered_once(self):
        value = {'text': 'é漢字' * 20, 'small': 1e-7, 'negative': -0.0}
        reply = await self.reply(value)
        self.assertEqual(reply.status, EmcpError.EMCP_SUCCESS)
        raw = reply._args_json
        self.assertIn('漢'.encode(), raw)
        self.assertEqual(reply.constraints.token_budget, 10000 - max(1, len(raw) // 4))
        with patch('emcp.frame._dumps', side_effect=AssertionError('re-encoded')):
            self.assertEqual(EmcpFrame.unpack(reply.pack()).args, value)

    async def test_legacy_json_values_still_supported(self):
        for value in ({'n': 2**100}, {1: 'one'}, {'n': float('nan')}, {'n': float('inf')}):
            reply = await self.reply(value)
            self.assertEqual(reply.status, EmcpError.EMCP_SUCCESS)
            self.assertEqual(reply._args_json, json.dumps(value, separators=(',', ':')).encode())

    async def test_over_budget_output_refused(self):
        reply = await self.reply({'text': 'x' * 100}, budget=2)
        self.assertEqual(reply.status, EmcpError.EMCP_ERR_TOKEN_OVERFLOW)


class DrainTests(unittest.TestCase):
    def test_stderr_is_read_in_bounded_chunks(self):
        class Stderr:
            count = 0
            def read(self, size):
                self.assert_size = size
                self.count += 1
                return b'x' * size if self.count < 100 else b''
        adapter = McpStdioProcessAdapter.__new__(McpStdioProcessAdapter)
        adapter.proc = type('Process', (), {'stderr': Stderr()})()
        tracemalloc.start()
        try:
            adapter._drain_stderr()
            self.assertEqual(adapter.proc.stderr.assert_size, 65536)
            self.assertLess(tracemalloc.get_traced_memory()[1], 150000)
        finally:
            tracemalloc.stop()


class AsyncAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter = McpStdioProcessAdapter('async-test', [sys.executable, MOCK])
        self.client = EmcpClient()

    async def asyncTearDown(self):
        self.adapter.close()

    async def test_calls_do_not_need_default_executor_workers(self):
        loop = asyncio.get_running_loop()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        loop.set_default_executor(executor)
        release = threading.Event()
        started = threading.Event()
        def occupy():
            started.set()
            release.wait(5)
        blocked = executor.submit(occupy)
        started.wait(1)
        try:
            replies = await asyncio.wait_for(asyncio.gather(*(
                self.client.call_tool(self.adapter, 'slow_tool', {'n': i}) for i in range(16)
            )), 2)
            self.assertTrue(all(r.status == EmcpError.EMCP_SUCCESS for r in replies))
            self.assertEqual([r.args['text'] for r in replies], [f'slow:{i}' for i in range(16)])
        finally:
            release.set()
            blocked.result(2)

    async def test_cancel_refunds_budget_and_ignores_late_reply(self):
        call = asyncio.create_task(self.client.call_tool(self.adapter, 'slow_tool', {'n': 1}))
        await asyncio.sleep(.01)
        call.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await call
        self.assertEqual(self.adapter._pending, {})
        self.assertEqual(self.adapter.ledger.allocated, 0)
        reply = await self.client.call_tool(self.adapter, 'slow_tool', {'n': 2})
        self.assertEqual(reply.args, {'text': 'slow:2'})

    async def test_timeout_cleans_pending_requests(self):
        self.adapter.timeout_s = .001
        with self.assertRaises(TimeoutError):
            await self.adapter._request_async('tools/call', {'name': 'slow_tool'})
        self.assertEqual(self.adapter._pending, {})

    async def test_limit_is_enforced_and_capacity_recovers(self):
        self.adapter.max_pending_requests = 1
        first = asyncio.create_task(self.adapter._request_async('tools/call', {'name': 'slow_tool'}))
        await asyncio.sleep(.01)
        with self.assertRaisesRegex(RuntimeError, 'limit'):
            await self.adapter._request_async('tools/list')
        await first
        self.assertIn('result', await self.adapter._request_async('tools/list'))

    async def test_pipe_backpressure_does_not_block_loop_or_timeout(self):
        entered, release = threading.Event(), threading.Event()
        original = self.adapter._write_line
        def blocked_write(req):
            entered.set()
            release.wait(2)
            original(req)
        self.adapter.timeout_s = .05
        with patch.object(self.adapter, '_write_line', blocked_write):
            try:
                with self.assertRaises(TimeoutError):
                    await asyncio.wait_for(self.adapter._request_async('tools/list'), .5)
                self.assertTrue(entered.is_set())
                self.assertEqual(self.adapter._pending, {})
            finally:
                release.set()
        self.adapter.timeout_s = 1
        self.assertIn('result', await self.adapter._request_async('tools/list'))

    async def test_write_failure_cleans_request_and_propagates(self):
        with patch.object(self.adapter, '_write_line', side_effect=BrokenPipeError('broken')):
            with self.assertRaises(BrokenPipeError):
                await self.adapter._request_async('tools/list')
        self.assertEqual(self.adapter._pending, {})
        self.assertIn('result', await self.adapter._request_async('tools/list'))

    async def test_eof_fails_waiters_and_rejects_new_requests(self):
        first = asyncio.create_task(self.adapter._request_async('tools/call', {'name': 'slow_tool'}))
        await asyncio.sleep(.01)
        self.adapter.proc.kill()
        with self.assertRaises(RuntimeError):
            await asyncio.wait_for(first, 1)
        self.assertEqual(self.adapter._pending, {})
        with self.assertRaises(RuntimeError):
            await self.adapter._request_async('tools/list')

    async def test_close_fails_waiters_and_stops_writer(self):
        first = asyncio.create_task(self.adapter._request_async('tools/call', {'name': 'slow_tool'}))
        await asyncio.sleep(.01)
        self.adapter.close()
        with self.assertRaises(RuntimeError):
            await first
        self.assertFalse(self.adapter._writer.is_alive())
        self.assertFalse(self.adapter._stderr_reader.is_alive())
        for stream in (self.adapter.proc.stdin, self.adapter.proc.stdout, self.adapter.proc.stderr):
            self.assertTrue(stream.closed)
