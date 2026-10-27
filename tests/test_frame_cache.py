"""Locks the EMCP performance-hardening contracts:
- post-unpack mutation must be visible in the next pack (cache invalidation)
- out-of-bounds declared slot lengths are rejected (no silent slice absorb)
- malformed UTF-8 verb bytes are a protocol error (strict decode)
- server reply keeps an object in-process while the wire reuses ONE JSON pass
"""
import struct
import unittest

from emcp.client import EmcpClient
from emcp.constants import Capability, EmcpError
from emcp.frame import HEADER_SIZE, EmcpFrame
from emcp.server import EmcpServer


class TestFrameCacheInvalidation(unittest.TestCase):
    def test_mutation_invalidates_raw_cache(self):
        f = EmcpFrame(verb="tools/read", args={"path": "/a"})
        g = EmcpFrame.unpack(f.pack())
        self.assertEqual(g.args, {"path": "/a"})
        g.args = {"path": "/b"}  # top-level mutation after unpack
        wire = g.pack()
        self.assertEqual(EmcpFrame.unpack(wire).args, {"path": "/b"})

    def test_unpack_rejects_out_of_bounds_slots(self):
        f = EmcpFrame(verb="x", args={})
        raw = f.pack()
        head, payload = raw[:HEADER_SIZE], raw[HEADER_SIZE:]
        l0 = struct.unpack(">I", payload[:4])[0]
        bad = head + struct.pack(">I", l0 + 4096) + payload[4:]
        with self.assertRaises(ValueError):
            EmcpFrame.unpack(bad)

    def test_unpack_rejects_malformed_utf8_verb(self):
        f = EmcpFrame(verb="ok", args={})
        raw = f.pack()
        head = raw[: HEADER_SIZE - 4] + struct.pack(">I", 18)
        payload = struct.pack(">IIII", 2, 0, 0, 0) + b"\xff\xfe"
        with self.assertRaises(ValueError):
            EmcpFrame.unpack(head + payload)


class TestReplySingleEncode(unittest.IsolatedAsyncioTestCase):
    async def test_reply_object_in_process_and_on_wire(self):
        server = EmcpServer(name="s", allowed_capabilities=Capability.NONE)

        @server.tool(name="echo", description="echo back")
        def echo(text: str = "hi"):
            return {"echo": text}

        client = EmcpClient()
        reply = await client.call_tool(server, "echo", {"text": "abc"})
        self.assertEqual(reply.status, EmcpError.EMCP_SUCCESS)
        # in-process consumers keep reading a dict...
        self.assertEqual(reply.args, {"echo": "abc"})
        # ...and the wire (reusing the stashed single JSON pass) decodes to it
        wire = EmcpFrame.unpack(reply.pack())
        self.assertEqual(wire.args, {"echo": "abc"})