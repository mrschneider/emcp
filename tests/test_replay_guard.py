"""Regression tests for the server-side replay / duplicate-transaction guard.

A frame whose transaction_id was already processed must be rejected with
EMCP_ERR_REPLAY_DETECTED BEFORE the tool handler runs, so a captured or
re-sent frame cannot re-execute a mutating tool, double-count tokens, or
double-apply a side effect.

These tests lock the fail-closed contract:

- the same (tool_name, transaction_id) runs the handler once and is then
  rejected on replay;
- a distinct transaction_id is processed normally;
- the guard rejects before the handler runs (handler call count stays 1);
- the replay window is bounded: ids older than the ring are evicted and
  can be processed again;
- list_tools / resources opcodes are unaffected (they carry no
  transaction_id to dedup).
"""

import unittest

from emcp import Capability, EmcpClient, EmcpError, EmcpServer


class ReplayGuardTests(unittest.IsolatedAsyncioTestCase):
    def _server(self) -> EmcpServer:
        return EmcpServer(
            name="guard-server",
            allowed_capabilities=Capability.NONE,
        )

    async def _call(self, server, tx_id, token_budget=4000):
        client = EmcpClient(allowed_capabilities=Capability.NONE)
        # Build a frame with an explicit transaction_id and dispatch it
        # directly (bypassing the client's auto-increment counter).
        from emcp.frame import EmcpFrame, ToolConstraints
        from emcp.constants import MsgType, OpCode, FrameFlags, EmcpError as E
        frame = EmcpFrame.__new__(EmcpFrame)
        frame.__dict__.update({
            "magic": EmcpFrame.magic,
            "version": EmcpFrame.version,
            "msg_type": MsgType.MSG_SEND,
            "opcode": OpCode.OP_TOOLS_CALL,
            "flags": FrameFlags.FLAG_NONE,
            "caller_pin": 0xDEADBEEFCAFEBABE,
            "target_pin": server.pin,
            "transaction_id": tx_id,
            "capabilities_mask": int(Capability.NONE),
            "status": E.EMCP_SUCCESS,
            "verb": "mutate",
            "args": {},
            "constraints": ToolConstraints(token_budget=token_budget),
            "envelope": __import__("emcp.frame", fromlist=["CryptoEnvelope"]).CryptoEnvelope(),
            "raw_payload": None,
        })
        return await server.handle_frame(frame)

    async def test_replay_rejected_before_handler_runs(self):
        server = self._server()
        calls = []

        @server.tool(name="mutate", required_caps=Capability.NONE)
        def mutate(**kwargs):
            calls.append(1)
            return {"ok": True}

        first = await self._call(server, 42)
        self.assertEqual(first.status, EmcpError.EMCP_SUCCESS)
        self.assertEqual(len(calls), 1)

        # Replay: same tx_id, must be rejected and handler NOT re-run.
        second = await self._call(server, 42)
        self.assertEqual(second.status, EmcpError.EMCP_ERR_REPLAY_DETECTED)
        self.assertEqual(len(calls), 1)

        # A third replay is also rejected.
        third = await self._call(server, 42)
        self.assertEqual(third.status, EmcpError.EMCP_ERR_REPLAY_DETECTED)
        self.assertEqual(len(calls), 1)

    async def test_distinct_transactions_processed(self):
        server = self._server()
        calls = []

        @server.tool(name="mutate", required_caps=Capability.NONE)
        def mutate(**kwargs):
            calls.append(1)
            return {"ok": True}

        for tx in (1, 2, 3, 4, 5):
            reply = await self._call(server, tx)
            self.assertEqual(reply.status, EmcpError.EMCP_SUCCESS)
        self.assertEqual(len(calls), 5)

    async def test_replay_window_is_bounded(self):
        server = EmcpServer(
            name="bounded-server",
            allowed_capabilities=Capability.NONE,
            replay_cache_size=3,
        )
        calls = []

        @server.tool(name="mutate", required_caps=Capability.NONE)
        def mutate(**kwargs):
            calls.append(1)
            return {"ok": True}

        # Process tx 1..4 with a ring of size 3: tx 1 is evicted once tx 4
        # is processed, so a replay of tx 1 must succeed again.
        for tx in (1, 2, 3):
            reply = await self._call(server, tx)
            self.assertEqual(reply.status, EmcpError.EMCP_SUCCESS)

        # tx 1 is still in the ring -> rejected.
        replay1 = await self._call(server, 1)
        self.assertEqual(replay1.status, EmcpError.EMCP_ERR_REPLAY_DETECTED)

        # Push tx 4 in, evicting tx 1 from the ring.
        reply4 = await self._call(server, 4)
        self.assertEqual(reply4.status, EmcpError.EMCP_SUCCESS)

        # tx 1 is now outside the window -> processed again.
        replay1_again = await self._call(server, 1)
        self.assertEqual(replay1_again.status, EmcpError.EMCP_SUCCESS)

    async def test_list_tools_unaffected(self):
        server = self._server()

        @server.tool(name="mutate", required_caps=Capability.NONE)
        def mutate(**kwargs):
            return {"ok": True}

        from emcp.frame import EmcpFrame, ToolConstraints
        from emcp.constants import MsgType, OpCode, FrameFlags, EmcpError as E
        frame = EmcpFrame.__new__(EmcpFrame)
        frame.__dict__.update({
            "magic": EmcpFrame.magic,
            "version": EmcpFrame.version,
            "msg_type": MsgType.MSG_SEND,
            "opcode": OpCode.OP_TOOLS_LIST,
            "flags": FrameFlags.FLAG_NONE,
            "caller_pin": 0x1,
            "target_pin": server.pin,
            "transaction_id": 999,
            "capabilities_mask": int(Capability.NONE),
            "status": E.EMCP_SUCCESS,
            "verb": "tools/list",
            "args": None,
            "constraints": ToolConstraints(),
            "envelope": __import__("emcp.frame", fromlist=["CryptoEnvelope"]).CryptoEnvelope(),
            "raw_payload": None,
        })
        reply = await server.handle_frame(frame)
        self.assertEqual(reply.status, EmcpError.EMCP_SUCCESS)


if __name__ == "__main__":
    unittest.main()
