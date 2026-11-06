"""Regression tests for the signed-bytes cache and tamper detection.

The cache of signed bytes is a performance optimisation: it lets
``verify_frame`` skip re-packing the payload. It is also a security
surface — a stale cache would let a mutated frame verify successfully.

These tests lock the fail-closed contract:

- a frame that is signed and then mutated must NOT verify;
- the mutation must be detected no matter how it was made (normal
  attribute assignment, or ``object.__setattr__`` which bypasses
  ``EmcpFrame.__setattr__``);
- a frame that was never mutated must still verify on the fast path;
- a frame that arrived over the wire must verify on the wire path;
- a tampered wire payload must be rejected.
"""

import unittest

from emcp.frame import EmcpFrame, ToolConstraints
from emcp.security import ToolIdentity

# Large enough to cross the signed-bytes cache threshold.
_BIG_ARGS = {"rows": [{"id": i, "name": "x" * 40} for i in range(2000)]}
_SMALL_ARGS = {"a": "x", "n": 1}


def _big_frame() -> EmcpFrame:
    return EmcpFrame(
        verb="tools/call",
        args=_BIG_ARGS,
        constraints=ToolConstraints(token_budget=4000),
    )


class SignedBytesCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = ToolIdentity()

    def test_signed_frame_verifies(self):
        frame = _big_frame()
        self.identity.sign_frame(frame)
        self.assertTrue(self.identity.verify_frame(frame))

    def test_mutation_after_signing_is_rejected(self):
        frame = _big_frame()
        self.identity.sign_frame(frame)
        frame.args = {"rows": [{"id": i, "name": "EVIL" * 40} for i in range(2000)]}
        self.assertFalse(self.identity.verify_frame(frame))

    def test_verb_mutation_after_signing_is_rejected(self):
        frame = _big_frame()
        self.identity.sign_frame(frame)
        frame.verb = "tools/exfiltrate"
        self.assertFalse(self.identity.verify_frame(frame))

    def test_object_setattr_bypass_is_rejected(self):
        """``object.__setattr__`` skips ``EmcpFrame.__setattr__``.

        The cache must not survive that: a signed frame could otherwise be
        altered and still verify.
        """
        frame = _big_frame()
        self.identity.sign_frame(frame)
        object.__setattr__(frame, "args", {"evil": True})
        self.assertFalse(self.identity.verify_frame(frame))

    def test_small_frame_mutation_is_rejected(self):
        """Frames below the cache threshold take the re-pack path."""
        frame = EmcpFrame(
            verb="echo",
            args=_SMALL_ARGS,
            constraints=ToolConstraints(token_budget=4000),
        )
        self.identity.sign_frame(frame)
        self.assertTrue(self.identity.verify_frame(frame))
        frame.args = {"a": "EVIL", "n": 999}
        self.assertFalse(self.identity.verify_frame(frame))

    def test_wire_roundtrip_verifies(self):
        """The cross-process path verifies from the parsed wire payload."""
        frame = _big_frame()
        self.identity.sign_frame(frame)
        parsed = EmcpFrame.unpack(frame.pack())
        self.assertTrue(self.identity.verify_frame(parsed))

    def test_tampered_wire_payload_is_rejected(self):
        frame = _big_frame()
        self.identity.sign_frame(frame)
        wire = bytearray(frame.pack())
        wire[-1] ^= 0xFF
        try:
            parsed = EmcpFrame.unpack(bytes(wire))
        except Exception:
            return  # rejected at parse time — also fail-closed
        self.assertFalse(self.identity.verify_frame(parsed))

    def test_unsigned_frame_is_rejected(self):
        frame = EmcpFrame(
            verb="echo",
            args=_SMALL_ARGS,
            constraints=ToolConstraints(token_budget=4000),
        )
        self.assertFalse(self.identity.verify_frame(frame))


if __name__ == "__main__":
    unittest.main()
