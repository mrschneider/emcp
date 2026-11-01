"""
Regression tests for the four critical performance/security fixes (v0.4.0):
1. Signature is opt-in; when enabled the server verifies (fail-closed)
2. pack_slots caches the single JSON pass (no duplicate dumps in sign->pack)
3. Sync handlers run off the event loop (to_thread) so calls run concurrently
4. McpStdioProcessAdapter pipelines JSON-RPC by id (concurrent calls, no lock)
"""

import asyncio
import os
import sys
import time
import unittest

from emcp import (
    EmcpClient,
    EmcpError,
    EmcpFrame,
    EmcpServer,
    McpStdioProcessAdapter,
    ToolConstraints,
)
from emcp.constants import Capability, FrameFlags, MsgType, OpCode
from emcp.security import ToolIdentity

SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "mock_mcp_server.py")


class TestSignatureOptIn(unittest.IsolatedAsyncioTestCase):
    """#1: signing is off by default; verify_signatures enforces it fail-closed."""

    def _server(self, **kw) -> EmcpServer:
        server = EmcpServer(name="sig-server", **kw)

        @server.tool(name="echo")
        def echo(a: str = ""):
            return {"echo": a}

        return server

    async def test_unsigned_call_succeeds_by_default(self):
        server = self._server()
        client = EmcpClient()
        self.assertFalse(client.sign_frames)
        reply = await client.call_tool(server, "echo", {"a": "x"})
        self.assertEqual(reply.status, EmcpError.EMCP_SUCCESS)
        self.assertEqual(reply.args, {"echo": "x"})

    async def test_signed_call_verifies_on_strict_server(self):
        server = self._server(verify_signatures=True)
        client = EmcpClient(sign_frames=True)
        server.register_identity(client.identity)
        reply = await client.call_tool(server, "echo", {"a": "y"})
        self.assertEqual(reply.status, EmcpError.EMCP_SUCCESS)

    async def test_unregistered_caller_rejected(self):
        server = self._server(verify_signatures=True)
        client = EmcpClient(sign_frames=True)  # not registered
        reply = await client.call_tool(server, "echo", {})
        self.assertEqual(reply.status, EmcpError.EMCP_ERR_UNKNOWN_PIN)

    async def test_tampered_payload_rejected(self):
        server = self._server(verify_signatures=True)
        client = EmcpClient(sign_frames=True)
        server.register_identity(client.identity)

        frame = EmcpFrame(
            msg_type=MsgType.MSG_SEND,
            opcode=OpCode.OP_TOOLS_CALL,
            caller_pin=client.identity.pin,
            target_pin=server.pin,
            transaction_id=1,
            capabilities_mask=0,
            flags=FrameFlags.FLAG_SIGNED,
            verb="echo",
            args={"a": "clean"},
            constraints=ToolConstraints(token_budget=4000, max_depth_hops=10),
        )
        client.identity.sign_frame(frame)
        # Mutate args AFTER signing, bypassing cache invalidation (wire tamper)
        object.__setattr__(frame, "args", {"a": "tampered"})
        reply = await server.handle_frame(frame)
        self.assertEqual(reply.status, EmcpError.EMCP_ERR_SIGNATURE_INVALID)

    def test_verify_frame_roundtrip(self):
        ident = ToolIdentity.generate()
        frame = EmcpFrame(
            msg_type=MsgType.MSG_SEND,
            opcode=OpCode.OP_TOOLS_CALL,
            caller_pin=ident.pin,
            target_pin=2,
            transaction_id=1,
            verb="echo",
            args={"a": "x"},
            constraints=ToolConstraints(token_budget=4000, max_depth_hops=10),
        )
        ident.sign_frame(frame)
        self.assertTrue(ident.verify_frame(frame))
        self.assertFalse(ToolIdentity.generate().verify_frame(frame))


class TestSlotCache(unittest.IsolatedAsyncioTestCase):
    """#2: pack_slots reuses one JSON pass; mutation invalidates the stash."""

    def test_pack_twice_no_reencode(self):
        big = {"rows": [{"id": i, "name": "x" * 40} for i in range(2000)]}
        frame = EmcpFrame(
            verb="tools/call",
            args=big,
            constraints=ToolConstraints(token_budget=4000),
        )
        ident = ToolIdentity.generate()
        ident.sign_frame(frame)  # first pack_slots (slot3 empty at sign time)
        wire = frame.pack()      # must reuse the stashed JSON, not re-dump
        unpacked = EmcpFrame.unpack(wire)
        self.assertEqual(unpacked.args, big)
        self.assertEqual(len(unpacked.envelope.signature), 64)
        # The signature covers the slots as packed at sign time (empty slot3)
        self.assertTrue(ident.verify_frame(unpacked))

    def test_args_mutation_invalidates_stash(self):
        frame = EmcpFrame(verb="v", args={"a": 1})
        frame.pack_slots()
        self.assertIsNotNone(frame.__dict__.get("_args_json"))
        frame.args = {"a": 2}
        self.assertIsNone(frame.__dict__.get("_args_json"))
        self.assertEqual(EmcpFrame.unpack(frame.pack()).args, {"a": 2})


class TestSyncHandlerOffLoop(unittest.IsolatedAsyncioTestCase):
    """#3: sync handlers run in a worker thread; concurrent calls don't serialize."""

    async def test_concurrent_sync_handlers_overlap(self):
        server = EmcpServer(name="concurrent")

        @server.tool(name="slow")
        def slow():
            time.sleep(0.2)
            return {"ok": True}

        client = EmcpClient()
        # Calibrate the serial bound in this environment (shared CI runners
        # are noisy — an absolute constant flaked by 0.9ms on macOS).
        t0 = time.perf_counter()
        await client.call_tool(server, "slow", {})
        serial_unit = time.perf_counter() - t0
        t0 = time.perf_counter()
        replies = await asyncio.gather(
            client.call_tool(server, "slow", {}),
            client.call_tool(server, "slow", {}),
        )
        elapsed = time.perf_counter() - t0
        self.assertTrue(all(r.status == EmcpError.EMCP_SUCCESS for r in replies))
        # Two 200ms calls overlap: <90% of the serialized 2x bound. Broken
        # overlap lands at ~100%; healthy overlap at ~50% even when loaded.
        self.assertLess(elapsed, serial_unit * 2 * 0.9)

    async def test_async_handler_still_awaited(self):
        server = EmcpServer(name="async")

        @server.tool(name="aio")
        async def aio(x: int = 0):
            await asyncio.sleep(0)
            return {"x": x}

        client = EmcpClient()
        reply = await client.call_tool(server, "aio", {"x": 7})
        self.assertEqual(reply.status, EmcpError.EMCP_SUCCESS)
        self.assertEqual(reply.args, {"x": 7})


class TestStdioAdapterPipelining(unittest.IsolatedAsyncioTestCase):
    """#4: JSON-RPC responses are matched by id; concurrent calls pipeline."""

    async def asyncSetUp(self):
        self.adapter = McpStdioProcessAdapter(
            name="pipe-mcp",
            command=[sys.executable, SERVER_SCRIPT],
        )
        self.client = EmcpClient()

    async def asyncTearDown(self):
        self.adapter.close()

    async def test_concurrent_calls_pipeline(self):
        # Calibrate the serial bound IN THIS ENVIRONMENT: shared CI runners
        # (macOS esp.) are noisy, so an absolute 0.25s constant flakes. The
        # invariant under test is relative: 8 pipelined 50ms calls must take
        # a small fraction of the serial (8x single-call) time.
        t0 = time.perf_counter()
        one = await self.client.call_tool(self.adapter, "slow_tool", {"n": 99})
        serial_unit = time.perf_counter() - t0
        self.assertEqual(one.status, EmcpError.EMCP_SUCCESS)

        t0 = time.perf_counter()
        replies = await asyncio.gather(
            *[
                self.client.call_tool(self.adapter, "slow_tool", {"n": i})
                for i in range(8)
            ]
        )
        elapsed = time.perf_counter() - t0
        self.assertTrue(all(r.status == EmcpError.EMCP_SUCCESS for r in replies))
        for i, r in enumerate(replies):
            self.assertEqual(r.args["text"], f"slow:{i}")
        # Pipelined bound: 75% of the serial time for the same 8 calls.
        # Broken pipelining lands at ~100% of serial; healthy pipelining
        # lands well under half even on a loaded runner.
        self.assertLess(elapsed, serial_unit * 8 * 0.75)

    async def test_mixed_fast_slow_out_of_order(self):
        replies = await asyncio.gather(
            *[
                self.client.call_tool(self.adapter, "slow_tool", {"n": i})
                for i in range(4)
            ],
            *[
                self.client.call_tool(self.adapter, "query_database", {"sql": f"SELECT {i}"})
                for i in range(4)
            ],
        )
        self.assertTrue(all(r.status == EmcpError.EMCP_SUCCESS for r in replies))


if __name__ == "__main__":
    unittest.main()
