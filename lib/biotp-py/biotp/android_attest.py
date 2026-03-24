"""
Android Key Attestation verification.

Verifies that an Android KeyStore attestation certificate chain is rooted
to a Google hardware attestation root and that the key attestation extension
(OID 1.3.6.1.4.1.11129.2.1.17) contains the expected challenge.
"""

import base64
import hashlib
import hmac
import time
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ObjectIdentifier

# Google hardware attestation root certificates (there are two known roots).
# We accept either.
GOOGLE_ROOT_CERTS_PEM = [
    # Root 1 (RSA)
    b"""\
-----BEGIN CERTIFICATE-----
MIIFYDCCBEigAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY0NzY2OTMzMjgwNDQxNDEwHhcNMTIwNDI1MTE0MzI3WhcNMjIwNDIzMTE0
MzI3WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgS
TyF15Iq/e7hjAolP1kmjXpgXrVXM3/QMXR0Cf5tGJwUbKZ3ruA2MkpJKfPRi9Y4b
gKz4z/qzXAJEppJ1S+IZAmNuSHRUgJiw0K/gI9BjfDyDr3P0b2RYUUU4JJslxUHh
E2skEz0DlCEQgGHCIxFgVKgvFSWwPUHUbUg9K/wDKrQDIxdfrVIaenUvMSbG0SRN
5UxDGJJH5mT/bNzYOSg/x7YRNhQ0jlApNJ3U4Zhl0RUM8QT8JHPO/9L8MIyR9/0
CggAUAADAQABo4IBOjCCATYwHQYDVR0OBBYEFMit6XdMRcOjzw0WEOR5QzohWjDPM
B8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf
8wDgYDVR0PAQH/BAQDAgGGMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR
0cDovL28ucGtpLmdvb2cvZ3NyMjAyBgNVHR8EKzApMCegJaAjhiFodHRwOi8vby5w
a2kuZ29vZy9nc3IyL2dzcjIuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQBbSRnhSzNF
a/Y4lIwwSdb1dFqGOrxS2MXOgpRBnYezHCjG4GY07gMRDAFKsSFlq8u9o/t6QZMR
9+bOY33BoV5dnGey7c0F/YZ6O72EPmD8A/k+8l4Oyn2xwXAS11KEsr0z/Yf46SqN
tynGRZfWRCJRjE/GniLi9vx4g4w3GasJPRhsb4a/8aqExshEZG+1tBCjSCFKJFNF
qaBTzay1f8TBbQUG8lkN8cf/PjfAXmiJBpRz0bJHZBdDXzOPC4Io4lds/P5v7qEU
NbG/RvB7WUVAP31N/UJoFeZuf2kXOHX7d3FKF3nS1qkpGiQMHa1v47VPl2P3RSKU
RkKHa/YFYJpnxbZ0OGTM5PsZnZKl8AR3BclJvi3M1+mPNRWSXQN7167J8bPNR1YQ
IqjAoSiZHaKIajqp/rBmIqQLxKLhMJ4pKl9E2dJet1gN0VbJiOJiRUouRMDSIKNw
JpajxQJ1hFMN70mFnw5GhVi4gkRJ5cJSTbZnz6N1OVGzCKeOk0BO5Z8SfPshvVfc
MN3qN+GXRZRT+lHGH8MRsGEmVbITmGR2vp2GFLBPSAl2vWxn0jKNR3S6MgVk9DO0
cJHi1fA/IvNBjFqGVCFCCSsJnJBoEvdIDwDOh9DGBGyCkLnmJAE/EhteIJsBnVGm
Eah2JhsEbLfBGJpSiaKCh8kH/EU2Ug==
-----END CERTIFICATE-----""",
    # Root 2 (EC, more common on modern devices)
    b"""\
-----BEGIN CERTIFICATE-----
MIICMDCCAbagAwIBAgIKFMGhLgAAAAACDTAKBggqhkjOPQQDAjAbMRkwFwYDVQQF
ExBmOTIwMDllODUzYjZiMDQ1MB4XDTE5MTEyMjIwMzc1OFoXDTM0MTEyMjIwMzc1
OFowOzE5MDcGA1UEBRMwNjM2MDc2ODRiODNiMTkzNjM3NTA1MjUyNzI5OTAzNjBl
YWYxOTNkNTdlODQ4MDUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASeJFhLlGbP
QMIBkMGkse/aJMQ2PmRrtNkfnOMqW6s+GSqJJCmhkMVLo3IjG80arlPkQ5+sse1Q
DLjyQ/sMtlTmo4G6MIG3MB0GA1UdDgQWBBQ2YeEAfIgFKBRih5aXMvixtPewBjAfB
gNVHSMEGDAWgBTIrel3TEXDo88NFhDkeUM6IVowzzAPBgNVHRMBAf8EBTADAQH/MA
4GA1UdDwEB/wQEAwICBDBUBgNVHR8ETTBLMEmgR6BFhkNodHRwczovL2FuZHJvaWQ
uZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsLzA2MzYwNzY4NGI4M2IxOTM2
Mzc1MDUwKBgKKwYBBAHWeQIBFQQaMBgCARkKAQACAQMKAQEECGFiY2RlZmdoMAoG
CCqGSM49BAMCA0gAMEUCIDadx4jX0NQtw77N8jnPQOqiTnkCONBQwN6Y1ryP9n0P
AiEAl5mB+GCvKN7EqtLfqBMEkuaFd4053AEi7+QZDCEvm7c=
-----END CERTIFICATE-----""",
]

ANDROID_KEY_ATTESTATION_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")


def _load_google_roots():
    roots = []
    for pem in GOOGLE_ROOT_CERTS_PEM:
        try:
            roots.append(x509.load_pem_x509_certificate(pem))
        except Exception:
            pass
    return roots


GOOGLE_ROOTS = _load_google_roots()


def _safe_cert_name(name) -> str:
    try:
        if name is None:
            return "n/a"
        return ", ".join(f"{attr.oid._name}={attr.value}" for attr in name)
    except Exception:
        try:
            return name.rfc4514_string()
        except Exception:
            return "unable-to-parse"


def _verify_cert_signature(child, issuer_pub) -> bool:
    """Return True if child cert is signed by issuer_pub."""
    try:
        if isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            issuer_pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        elif isinstance(issuer_pub, rsa.RSAPublicKey):
            issuer_pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,
            )
        else:
            return False
        return True
    except Exception:
        return False


def serialize_cert_chain(certs: list, root_label: str = "Google Root") -> list[dict]:
    """Serialize a certificate chain with per-link verification status."""
    if not certs:
        return []

    result = []
    for i, cert in enumerate(certs):
        try:
            subject = _safe_cert_name(cert.subject)
            issuer = _safe_cert_name(cert.issuer)
            serial = str(cert.serial_number)
            not_before = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat()
            not_after = cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat()
        except Exception:
            subject = issuer = serial = not_before = not_after = "parse error"

        # Determine who signed this cert and whether it verifies
        if i < len(certs) - 1:
            signed_by = f"cert[{i+1}]"
            verified = _verify_cert_signature(cert, certs[i + 1].public_key())
        else:
            signed_by = root_label
            verified = False  # caller should set this for the root check

        entry = {
            "index": i,
            "role": "leaf" if i == 0 else ("root" if i == len(certs) - 1 else "intermediate"),
            "subject": subject,
            "issuer": issuer,
            "serial": serial,
            "not_before": not_before,
            "not_after": not_after,
            "signed_by": signed_by,
            "signature_valid": verified,
        }
        result.append(entry)

    return result


def _verify_chain(certs: list) -> tuple[bool, str, list[dict]]:
    """Verify each cert is signed by the next, and last is signed by a Google root.

    Returns (ok, reason, chain_info).
    """
    chain_info = serialize_cert_chain(certs, root_label="Google Hardware Attestation Root")
    if not certs:
        return False, "empty certificate chain", chain_info

    # Check intermediate links (already computed in serialize_cert_chain)
    for entry in chain_info[:-1]:
        if not entry["signature_valid"]:
            return False, f"chain verification failed at cert[{entry['index']}]", chain_info

    # Verify last cert against any known Google root (cryptographic check only)
    last_cert = certs[-1]
    root_verified = False
    for root in GOOGLE_ROOTS:
        if _verify_cert_signature(last_cert, root.public_key()):
            root_verified = True
            break

    if chain_info:
        chain_info[-1]["signature_valid"] = root_verified

    if not root_verified:
        return False, "chain not rooted to a known Google hardware attestation root", chain_info

    return True, "", chain_info


def verify_android_attestation(
    cert_chain_b64: list[str],
    expected_challenge: bytes,
    user_public_key_hex: str,
) -> tuple[bool, str, dict]:
    """Verify an Android KeyStore attestation certificate chain.

    Returns (ok, reason, details).
    """
    details: dict = {}

    if not cert_chain_b64:
        return False, "no attestation chain provided", details

    # Parse certs
    try:
        certs = []
        for i, b64 in enumerate(cert_chain_b64):
            der = base64.b64decode(b64)
            certs.append(x509.load_der_x509_certificate(der))
        details["chain_length"] = len(certs)
    except Exception as exc:
        return False, f"invalid certificate in chain: {exc}", details

    # Verify chain
    chain_ok, chain_reason, chain_info = _verify_chain(certs)
    details["chain_verified"] = chain_ok
    details["cert_chain"] = chain_info
    if not chain_ok:
        details["failure_reason"] = chain_reason
        return False, chain_reason, details

    # Extract key attestation extension from leaf
    leaf = certs[0]
    try:
        ext = leaf.extensions.get_extension_for_oid(ANDROID_KEY_ATTESTATION_OID)
        ext_data = ext.value.value if hasattr(ext.value, "value") else bytes(ext.value)
        details["attestation_extension_present"] = True
        details["attestation_extension_len"] = len(ext_data)
    except x509.ExtensionNotFound:
        details["attestation_extension_present"] = False
        return False, "no key attestation extension; key is not hardware-attested", details

    # Verify the leaf certificate public key matches the registered public key.
    # The leaf cert in an Android KeyStore attestation chain contains the attested key.
    try:
        leaf_pub = leaf.public_key()
        if isinstance(leaf_pub, ec.EllipticCurvePublicKey):
            leaf_nums = leaf_pub.public_numbers()
            leaf_x = leaf_nums.x.to_bytes(32, "big")
            leaf_y = leaf_nums.y.to_bytes(32, "big")
            leaf_raw_hex = (leaf_x + leaf_y).hex()
            details["leaf_public_key_hex"] = leaf_raw_hex[:20] + "..."
            if leaf_raw_hex != user_public_key_hex:
                return False, "leaf certificate public key does not match registered key", details
            details["public_key_binding"] = True
        else:
            return False, "leaf certificate does not contain an EC public key", details
    except Exception as exc:
        return False, f"failed to extract leaf public key: {exc}", details

    # Verify the challenge is present in the attestation extension.
    challenge_hash = hashlib.sha256(
        expected_challenge + bytes.fromhex(user_public_key_hex)
    ).digest()

    if expected_challenge in ext_data:
        details["challenge_binding"] = "raw_challenge_found"
    elif challenge_hash in ext_data:
        details["challenge_binding"] = "challenge_hash_found"
    else:
        return False, "challenge not found in attestation extension", details

    details["valid"] = True
    details["verified_at"] = time.time()
    return True, "ok", details
