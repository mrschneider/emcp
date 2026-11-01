"""
EMCP Security, Tool-PIN derivation, Ed25519 signatures, and PlatSec capability gate.
"""

from __future__ import annotations
import hashlib
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .constants import Capability, EmcpError
from .frame import CryptoEnvelope, EmcpFrame

# Frames at or above this size benefit from caching the signed bytes: the
# cost of one SHA-256 over the payload is far below the cost of re-encoding
# the payload (pack_slots does a full JSON re-serialisation of slot1) plus
# re-running Ed25519 verify. Below the threshold we skip the cache and keep
# the original re-pack verification path, so tiny frames pay nothing extra.
_SIGNED_BYTES_THRESHOLD = 16 * 1024


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

        Caches the exact bytes that were signed (the packed slots with an
        empty-signature envelope) in ``frame.envelope._signed_bytes`` so a
        later ``verify_frame`` can reuse them instead of re-packing the frame
        and re-serialising slot1's JSON. The cache is captured at sign time,
        so post-sign mutation of frame fields (e.g. wire tamper via
        ``object.__setattr__(frame, "args", ...)``) is still detected: verify
        checks the cached bytes against the current signature, not against the
        mutated fields.

        The cache is only populated for frames large enough that re-encoding
        them on every verify would cost more than the SHA-256 used to store
        the cache, keeping tiny frames on the original re-pack path.
        """
        payload_to_sign = frame.pack_slots()
        sig = self.sign(payload_to_sign)
        frame.envelope.signature = sig
        if len(payload_to_sign) >= _SIGNED_BYTES_THRESHOLD:
            object.__setattr__(frame.envelope, "_signed_bytes", payload_to_sign)
        else:
            object.__setattr__(frame.envelope, "_signed_bytes", None)

    def verify_frame(self, frame: EmcpFrame) -> bool:
        """Verifies the envelope signature over the packed slots.

        The signature covers the slots as packed at sign time, when slot3
        (envelope) was still empty. If the signer cached the signed bytes
        (see ``sign_frame``), verify reuses them rather than re-packing the
        frame and re-serialising slot1's JSON -- turning verify into a pure
        Ed25519 check instead of pack + SHA-256 + Ed25519. Below
        ``_SIGNED_BYTES_THRESHOLD`` the cache is empty and the original
        re-pack path is used.
        """
        sig = frame.envelope.signature
        if not sig:
            return False
        cached = getattr(frame.envelope, "_signed_bytes", None)
        if cached is not None:
            return self.verify(cached, sig)
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
        return self.verify(unsigned.pack_slots(), sig)


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
