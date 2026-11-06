"""
EMCP Security, Tool-PIN derivation, Ed25519 signatures, and PlatSec capability gate.
"""

from __future__ import annotations
import hashlib
import struct
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .constants import Capability, EmcpError
from .frame import CryptoEnvelope, EmcpFrame

# 4 slot-length words + the 4-byte session_handle prefix of slot3: the
# minimum packed-slots layout a signature can cover.
_SLOTS_PREFIX_LEN = 16 + 4

# Frames at or above this size cache their signed bytes on the envelope:
# re-encoding the payload on every verify (pack_slots does a full JSON
# re-serialisation of slot1) costs more than storing the buffer. Below
# the threshold the cache is skipped and tiny frames pay nothing extra.
_SIGNED_BYTES_THRESHOLD = 16 * 1024


def _signed_refs_match(frame: EmcpFrame) -> bool:
    """True while the frame still carries the exact objects that were signed.

    ``sign_frame`` stores a reference to the signed args and constraints
    objects on the frame itself. Comparing identity is O(1) and needs no
    serialisation: hashing a repr() of the args costs more than the
    Ed25519 check the cache exists to save (measured: SHA-256 over
    repr(args) made sign/verify ~3x slower).

    Holding the reference also keeps the comparison sound: the signed
    object cannot be freed (and its id reused) while the frame holds it.

    Limitation, unchanged from the upstream cache: mutating the args
    *in place* (``frame.args["k"] = v``) keeps the same object identity,
    so it is not detected here. It is out of scope for the frame-level
    mutation protocol; the wire path
    (``_signed_slots_from_raw_payload``) is unaffected and stays
    fail-closed.
    """
    ref = frame.__dict__.get("_signed_bytes_ref")
    if ref is None:
        return False
    signed_args, signed_constraints, signed_verb = ref
    return (
        frame.args is signed_args
        and frame.constraints is signed_constraints
        and frame.verb == signed_verb
    )


def _signed_slots_from_raw_payload(raw_payload: Optional[bytes]) -> Optional[bytes]:
    """Rebuilds the exact signed bytes (slots with an empty-signature
    envelope) from the parsed wire payload without re-serialising anything.

    The wire layout is [l0 l1 l2 l3][slot0][slot1][slot2][slot3] and
    sign_frame() signs the same layout when slot3 carries only the
    4-byte session handle (l3 == 4). On the wire, slot3 also carries the
    signature, so l3 == 4 + len(sig) and the l3 length word differs from
    the one that was signed. The signed bytes are therefore: the 4 length
    words with l3 rewritten to 4, then slot0 + slot1 + slot2 unchanged,
    then the 4-byte session-handle prefix of the wire slot3.

    Any payload that is shorter than the layout, longer than the declared
    lengths, or that carries no session-handle prefix is rejected (None) —
    verify then falls through to the re-pack path, which fails closed on a
    tampered signature.
    """
    if raw_payload is None:
        return None
    n = len(raw_payload)
    if n < _SLOTS_PREFIX_LEN:
        return None
    l0, l1, l2, l3 = struct.unpack(">IIII", raw_payload[:16])
    total = l0 + l1 + l2 + l3
    if 16 + total != n:
        return None
    slots_end = 16 + l0 + l1 + l2
    return struct.pack(">IIII", l0, l1, l2, 4) + raw_payload[16:slots_end + 4]


def compute_pin(public_bytes: bytes) -> int:
    """Derives deterministic 64-bit unsigned Tool-PIN from Ed25519 public key."""
    digest = hashlib.sha256(public_bytes).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=False)


def format_pin(pin: int) -> str:
    """Formats 64-bit integer PIN into hexadecimal representation."""
    h = f"{pin:016X}"
    return f"0x{h[0:4]}_{h[4:8]}_{h[8:12]}_{h[12:16]}"


class ToolIdentity:
    """Cryptographic identity of an EMCP tool provider or calling agent."""

    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None):
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._public_bytes = self._public_key.public_bytes_raw()
        self.pin = compute_pin(self._public_bytes)

    @classmethod
    def generate(cls) -> ToolIdentity:
        return cls()

    @property
    def public_bytes(self) -> bytes:
        return self._public_bytes

    @property
    def pin_hex(self) -> str:
        return format_pin(self.pin)

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, message)
            return True
        except Exception:
            return False

    def sign_frame(self, frame: EmcpFrame) -> None:
        """Signs the frame payload and attaches signature to envelope.

        The signature covers the packed slots with an empty-signature
        envelope. For frames at or above ``_SIGNED_BYTES_THRESHOLD`` the
        exact signed bytes are cached on the envelope so an in-process
        ``verify_frame`` is a pure Ed25519 check (no re-pack / JSON
        re-serialisation). The cache is captured at sign time together
        with a reference to the exact objects that were signed, so any
        later replacement of those objects invalidates the cache — even
        when the replacement is made through ``object.__setattr__``,
        which bypasses ``EmcpFrame.__setattr__``. Post-sign tamper is
        therefore detected fail-closed: verify re-derives the bytes from
        the current fields and the signature no longer matches.
        """
        payload_to_sign = frame.pack_slots()
        sig = self.sign(payload_to_sign)
        frame.envelope.signature = sig
        if len(payload_to_sign) >= _SIGNED_BYTES_THRESHOLD:
            object.__setattr__(frame.envelope, "_signed_bytes", payload_to_sign)
            # Remember the exact objects that were signed so a later
            # replacement of any of them (including one made through
            # ``object.__setattr__``, which bypasses the frame's
            # ``__setattr__``) invalidates the cached bytes.
            object.__setattr__(
                frame,
                "_signed_bytes_ref",
                (frame.args, frame.constraints, frame.verb),
            )

    def verify_frame(self, frame: EmcpFrame) -> bool:
        """Verifies the envelope signature over the packed slots.

        The signature covers the slots as packed at sign time, when slot3
        (envelope) was still empty. Verification resolves the covered
        bytes in three tiers, cheapest first:

        1. The signer's in-process cache (``_signed_bytes``, large
           frames only) -> pure Ed25519 check, no re-serialisation.
        2. The parsed wire payload (``raw_payload``) -> the exact bytes
           the sender put on the wire, sliced with zero re-encoding
           (this is the cross-process server path).
        3. A fresh re-pack of the current fields (tiny frames, or a
           frame that was never on the wire).

        Every path is fail-closed: a missing signature, an unresolvable
        payload, or a tampered signature rejects the frame.
        """
        sig = frame.envelope.signature
        if not sig:
            return False
        cached = getattr(frame.envelope, "_signed_bytes", None)
        if cached is not None:
            # The cache is only trustworthy while the frame's fields still
            # match the bytes that were signed. A mutation made through
            # ``object.__setattr__`` bypasses ``EmcpFrame.__setattr__`` and
            # would otherwise leave a stale (still-valid) cache in place --
            # a signed frame could be altered and still verify. The
            # fingerprint re-derives the current field state, so any
            # mutation invalidates the cache regardless of how it was made.
            if _signed_refs_match(frame):
                return self.verify(cached, sig)
        unsigned_bytes = _signed_slots_from_raw_payload(frame.raw_payload)
        if unsigned_bytes is None:
            unsigned = EmcpFrame(
                magic=frame.magic,
                version=frame.version,
                msg_type=frame.msg_type,
                opcode=frame.opcode,
                flags=frame.flags,
                caller_pin=frame.caller_pin,
                target_pin=frame.target_pin,
                transaction_id=frame.transaction_id,
                capabilities_mask=frame.capabilities_mask,
                status=frame.status,
                verb=frame.verb,
                args=frame.args,
                constraints=frame.constraints,
                envelope=CryptoEnvelope(
                    session_handle=frame.envelope.session_handle, signature=b""
                ),
            )
            unsigned_bytes = unsigned.pack_slots()
        return self.verify(unsigned_bytes, sig)


class PlatSecGate:
    """
    Platform Security (PlatSec) capability verification gate.
    Enforces the invariant: (granted & required) == required.
    """

    def __init__(self, allowed_capabilities: Capability = Capability.NONE, strict_mode: bool = True):
        self.allowed_capabilities = allowed_capabilities
        self.strict_mode = strict_mode

    def verify(self, granted_mask: int, required_caps: Capability) -> bool:
        if required_caps == Capability.NONE:
            return True

        req = int(required_caps)
        # Granted mask cannot exceed what the manifest allows
        effective = granted_mask & int(self.allowed_capabilities)

        return (effective & req) == req
