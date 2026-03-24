"""
Apple App Attest verification.

Verifies CBOR-encoded attestation objects produced by DCAppAttestService,
including x5c certificate chain validation back to Apple's App Attestation
Root CA.
"""

import base64
import hashlib
import hmac
import time
from typing import Optional

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ObjectIdentifier

APPLE_ATTEST_NONCE_OID = ObjectIdentifier("1.2.840.113635.100.8.2")

APPLE_APP_ATTESTATION_ROOT_CA_PEM = b"""\
-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----"""

APPLE_ROOT_CA = x509.load_pem_x509_certificate(
    APPLE_APP_ATTESTATION_ROOT_CA_PEM
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def b64_decode(value: str) -> bytes:
    normalized = value.strip().replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized, validate=True)
    except Exception:
        return base64.b64decode(normalized + "==")


def _decode_text_or_b64(value: str) -> bytes:
    try:
        return b64_decode(value)
    except Exception:
        return value.encode()


def _cbor_map_get(payload: dict, key: str):
    if key in payload:
        return payload[key]
    key_bytes = key.encode()
    if key_bytes in payload:
        return payload[key_bytes]
    return None


def _as_bytes(value) -> Optional[bytes]:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return None


def _extract_authenticator_key_id(auth_data: bytes) -> Optional[bytes]:
    # RP ID hash(32) + flags(1) + sign_count(4) + AAGUID(16) + credIdLen(2) + credId
    if len(auth_data) < 55:
        return None
    cred_id_len = int.from_bytes(auth_data[53:55], "big")
    start = 55
    end = start + cred_id_len
    if end > len(auth_data) or cred_id_len == 0:
        return None
    return auth_data[start:end]


def _extract_asn1_octet_bytes(value: bytes) -> bytes:
    if not value or value[0] != 0x04:
        return value
    if len(value) < 2:
        return b""
    pos = 1
    length = value[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(value[pos : pos + n], "big")
        pos += n
    if pos + length > len(value):
        return b""
    return value[pos : pos + length]


def _extract_nonce_from_extension(ext_value: bytes) -> bytes:
    if not ext_value:
        return b""
    if len(ext_value) == 32:
        return ext_value
    if ext_value and ext_value[0] == 0x04:
        candidate = _extract_asn1_octet_bytes(ext_value)
        if len(candidate) == 32:
            return candidate
    if len(ext_value) > 6:
        candidate = ext_value[6:]
        if len(candidate) == 32:
            return candidate
    return b""


def _verify_app_id_hash(
    auth_data: bytes,
    allowed_app_ids: Optional[list[str]] = None,
) -> tuple[bool, str, Optional[bytes]]:
    if len(auth_data) < 32:
        return False, "authData too short for rpIdHash", None

    if allowed_app_ids is None:
        return True, "", None

    if not allowed_app_ids:
        return False, "allowed_app_ids is empty", None

    actual = auth_data[:32]
    for app_id in allowed_app_ids:
        expected = hashlib.sha256(app_id.encode("utf-8")).digest()
        if hmac.compare_digest(actual, expected):
            return True, "", expected
    return False, "app id hash does not match any allowed bundle id", None


def _verify_x5c_chain(x5c_certs: list) -> tuple[bool, str, list[dict]]:
    """Verify the x5c certificate chain back to Apple's Root CA.

    Returns (ok, reason, chain_info).
    """
    from .android_attest import serialize_cert_chain, _verify_cert_signature

    chain_info = serialize_cert_chain(x5c_certs, root_label="Apple App Attestation Root CA")
    if not x5c_certs:
        return False, "empty x5c chain", chain_info

    # Check intermediate links (already computed in serialize_cert_chain)
    for entry in chain_info[:-1]:
        if not entry["signature_valid"]:
            return False, f"x5c chain verification failed at cert[{entry['index']}]", chain_info

    # Verify last cert against Apple root
    last_cert = x5c_certs[-1]
    root_verified = _verify_cert_signature(last_cert, APPLE_ROOT_CA.public_key())
    if chain_info:
        chain_info[-1]["signature_valid"] = root_verified

    if not root_verified:
        return False, "x5c chain not rooted to Apple App Attestation Root CA", chain_info

    return True, "", chain_info


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def verify_app_attest(
    attestation_b64: str,
    attest_key_id_b64: str,
    expected_client_data_hash: bytes,
    user_public_key: str,
    session_challenge_b64: str,
    allowed_app_ids: Optional[list[str]] = None,
) -> tuple[bool, str, dict]:
    """Verify an Apple App Attest attestation object.

    Returns (ok, reason, details).
    """

    def _safe_cert_name(value) -> str:
        try:
            if value is None:
                return "n/a"
            return ", ".join(
                f"{attr.oid._name}={attr.value}" for attr in value
            )
        except Exception:
            return "unable-to-parse"

    def _fail(reason: str, d: dict) -> tuple[bool, str, dict]:
        d["failure_reason"] = reason
        return False, reason, d

    details: dict = {}

    try:
        attestation_data = b64_decode(attestation_b64)
        session_challenge = b64_decode(session_challenge_b64)
        attest_key_id = _decode_text_or_b64(attest_key_id_b64)
    except Exception:
        return _fail("invalid base64 in app attest fields", details)

    try:
        public_key_bytes = bytes.fromhex(user_public_key)
    except ValueError:
        return _fail("invalid public key encoding", details)

    expected_hash = hashlib.sha256(
        session_challenge + public_key_bytes
    ).digest()
    if not hmac.compare_digest(expected_hash, expected_client_data_hash):
        return _fail("attest challenge binding failed", details)

    try:
        attestation = cbor2.loads(attestation_data)
    except Exception as exc:
        return _fail(f"invalid attestation object: {exc}", details)

    if not isinstance(attestation, dict):
        return _fail("attestation object must be a map", details)

    fmt = _cbor_map_get(attestation, "fmt")
    if fmt is None:
        return _fail("attestation missing fmt", details)
    if isinstance(fmt, bytes):
        fmt = fmt.decode("utf-8", errors="ignore")
    if fmt not in ("apple-appattest", "apple"):
        return _fail(f"unsupported attestation format: {fmt}", details)
    details["fmt"] = fmt

    auth_data = _as_bytes(_cbor_map_get(attestation, "authData"))
    if auth_data is None:
        return _fail("attestation missing authData", details)
    details["auth_data_len"] = len(auth_data)
    details["auth_data_rp_id_hash"] = auth_data[:32].hex()

    details["app_id_hash_configured"] = allowed_app_ids is not None
    details["app_id_hash_actual"] = auth_data[:32].hex()
    app_id_ok, app_id_reason, matched_hash = _verify_app_id_hash(auth_data, allowed_app_ids)
    details["app_id_hash_expected"] = matched_hash.hex() if matched_hash else None
    if not app_id_ok:
        details["app_id_hash_verified"] = False
        return _fail(app_id_reason, details)
    details["app_id_hash_verified"] = True

    att_stmt = _cbor_map_get(attestation, "attStmt")
    if not isinstance(att_stmt, dict):
        return _fail("attestation missing attStmt", details)

    key_id = _extract_authenticator_key_id(auth_data)
    if key_id is None or not hmac.compare_digest(key_id, attest_key_id):
        details["key_id_len"] = len(key_id) if key_id is not None else 0
        return _fail("app attest key id mismatch", details)
    details["key_id_len"] = len(key_id)
    details["key_id_match"] = True

    x5c = _cbor_map_get(att_stmt, "x5c")
    if not isinstance(x5c, list) or not x5c:
        details["x5c_count"] = 0
        return _fail("attestation missing x5c certificate chain", details)
    details["x5c_count"] = len(x5c)

    try:
        x5c_certs = []
        for i, raw in enumerate(x5c):
            raw_bytes = _as_bytes(raw)
            if raw_bytes is None:
                return _fail(
                    f"invalid x5c certificate at index {i}", details
                )
            x5c_certs.append(x509.load_der_x509_certificate(raw_bytes))
        cert = x5c_certs[0]
    except Exception as exc:
        return _fail(f"invalid x5c certificate: {exc}", details)

    chain_ok, chain_reason, chain_info = _verify_x5c_chain(x5c_certs)
    details["x5c_chain_verified"] = chain_ok
    details["cert_chain"] = chain_info
    if not chain_ok:
        return _fail(chain_reason, details)

    nonce = hashlib.sha256(auth_data + expected_client_data_hash).digest()
    try:
        nonce_ext = cert.extensions.get_extension_for_oid(
            APPLE_ATTEST_NONCE_OID
        )
        ext_payload = getattr(nonce_ext.value, "value", None)
        if ext_payload is None:
            ext_payload = nonce_ext.value
        if not isinstance(ext_payload, bytes):
            ext_payload = bytes(ext_payload)
        ext_nonce = _extract_nonce_from_extension(ext_payload)
    except Exception:
        ext_nonce = b""
    details["attestation_nonce_expected_hex"] = nonce.hex()
    details["attestation_nonce_extension_hex"] = (
        ext_nonce.hex() if ext_nonce else ""
    )
    if not ext_nonce or not hmac.compare_digest(ext_nonce, nonce):
        details["attestation_nonce_verified"] = False
        return _fail("attestation nonce check failed", details)
    details["attestation_nonce_verified"] = True

    signature = _as_bytes(_cbor_map_get(att_stmt, "sig"))
    if signature is not None:
        try:
            cert.public_key().verify(
                signature,
                auth_data + expected_client_data_hash,
                ec.ECDSA(hashes.SHA256()),
            )
        except Exception as exc:
            details["attestation_signature_verified"] = False
            return _fail(f"attestation signature failed: {exc}", details)
    details["attestation_signature_verified"] = signature is not None

    details["valid"] = True
    details["verified_at"] = time.time()
    return True, "ok", details
