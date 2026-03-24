"""
ECDH-TOTP: Elliptic Curve Diffie-Hellman Time-Based One-Time Passwords.

Implements the key derivation, shared secret computation, and OTP
generation/verification described in rfc-ecdh-totp.txt.
"""

import hashlib
import hmac
import struct
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

P256_ORDER = (
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
)


class MasterKey:
    """Server-side ECDH-TOTP master key.

    Holds a P-256 master private scalar derived from a seed via HKDF and
    exposes child-key derivation, shared-secret computation, and OTP
    generation/verification.
    """

    def __init__(self, secret: bytes, *, period: int = 30) -> None:
        self._secret = secret
        self._period = period

        raw = self._derive_material(b"humancheck:master-private")
        self._scalar = int.from_bytes(raw, "big") % (P256_ORDER - 1) + 1
        self._private_key = ec.derive_private_key(self._scalar, ec.SECP256R1())

        uncompressed = self._private_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        self._public_raw = uncompressed[1:]  # raw X||Y (64 bytes)

    # -- properties ----------------------------------------------------------

    @property
    def public_raw(self) -> bytes:
        """Master public key as raw X||Y (64 bytes)."""
        return self._public_raw

    @property
    def period(self) -> int:
        return self._period

    # -- time ----------------------------------------------------------------

    def current_counter(self) -> int:
        return int(time.time()) // self._period

    # -- child key derivation ------------------------------------------------

    def tweak_scalar(self, counter: int) -> int:
        counter_bytes = struct.pack(">Q", counter)
        digest = hmac.new(
            self._public_raw, counter_bytes, hashlib.sha256
        ).digest()
        return int.from_bytes(digest, "big") % P256_ORDER

    def child_private_for_counter(
        self, counter: int
    ) -> ec.EllipticCurvePrivateKey:
        d = (self._scalar + self.tweak_scalar(counter)) % P256_ORDER
        if d == 0:
            d = 1
        return ec.derive_private_key(d, ec.SECP256R1())

    def child_pubkey_hex(self, counter: int) -> str:
        return (
            self.child_private_for_counter(counter)
            .public_key()
            .public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            .hex()
        )

    # -- shared secret & OTP -------------------------------------------------

    @staticmethod
    def compute_shared_secret(
        server_private: ec.EllipticCurvePrivateKey,
        user_pubkey_hex: str,
    ) -> bytes:
        user_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(user_pubkey_hex)
        )
        raw_shared = server_private.exchange(ec.ECDH(), user_pub)
        return X963KDF(
            algorithm=hashes.SHA256(),
            length=32,
            sharedinfo=b"",
        ).derive(raw_shared)

    @staticmethod
    def compute_totp(shared_secret: bytes, counter: int) -> str:
        counter_bytes = struct.pack(">Q", counter)
        h = hmac.new(shared_secret, counter_bytes, hashlib.sha256).digest()
        offset = h[-1] & 0x0F
        truncated = (
            struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
        )
        otp = truncated % 1_000_000
        return f"{otp:06d}"

    def verify_otp(
        self,
        user_pubkey_hex: str,
        otp: str,
        *,
        skew: int = 1,
        last_counter: int = -1,
    ) -> tuple[bool, int]:
        """Verify an OTP against the current time window.

        Returns (valid, matched_counter).  If invalid, matched_counter is -1.
        """
        counter = self.current_counter()
        candidates = [counter + i for i in range(-skew, skew + 1)]
        for c in candidates:
            if c <= last_counter:
                continue
            sk = self.child_private_for_counter(c)
            shared = self.compute_shared_secret(sk, user_pubkey_hex)
            expected = self.compute_totp(shared, c)
            if hmac.compare_digest(expected, otp):
                return True, c
        return False, -1

    # -- internal ------------------------------------------------------------

    def _derive_material(self, label: bytes, length: int = 32) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=b"humancheck-offline-v1",
            info=label,
        ).derive(self._secret)
