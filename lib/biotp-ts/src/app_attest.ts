import * as crypto from "node:crypto";
import { decode } from "cbor-x";
import {
  findExtensionValue,
  verifyCertSignature,
  serializeCertChain,
  CertChainEntry,
} from "./x509";

const APPLE_ATTEST_NONCE_OID = "1.2.840.113635.100.8.2";

const APPLE_APP_ATTESTATION_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`;

const APPLE_ROOT_CA = new crypto.X509Certificate(
  APPLE_APP_ATTESTATION_ROOT_CA_PEM
);

// -- Helpers ------------------------------------------------------------

function b64Decode(value: string): Buffer {
  let normalized = value.trim().replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (normalized.length % 4)) % 4;
  normalized += "=".repeat(pad);
  return Buffer.from(normalized, "base64");
}

function decodeTextOrB64(value: string): Buffer {
  try {
    return b64Decode(value);
  } catch {
    return Buffer.from(value);
  }
}

function asBuffer(value: unknown): Buffer | null {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  return null;
}

function cborMapGet(
  payload: Record<string, unknown>,
  key: string
): unknown {
  if (key in payload) return payload[key];
  const keyBuf = Buffer.from(key);
  for (const k of Object.keys(payload)) {
    if (Buffer.isBuffer(k) && keyBuf.equals(k as unknown as Buffer))
      return payload[k];
  }
  return undefined;
}

function extractAuthenticatorKeyId(authData: Buffer): Buffer | null {
  // RP ID hash(32) + flags(1) + sign_count(4) + AAGUID(16) + credIdLen(2) + credId
  if (authData.length < 55) return null;
  const credIdLen = authData.readUInt16BE(53);
  const start = 55;
  const end = start + credIdLen;
  if (end > authData.length || credIdLen === 0) return null;
  return authData.subarray(start, end);
}

function extractAsn1OctetBytes(value: Buffer): Buffer {
  if (!value.length || value[0] !== 0x04) return value;
  if (value.length < 2) return Buffer.alloc(0);
  let pos = 1;
  let length = value[pos];
  pos += 1;
  if (length & 0x80) {
    const n = length & 0x7f;
    length = 0;
    for (let i = 0; i < n; i++) {
      length = length * 256 + value[pos + i];
    }
    pos += n;
  }
  if (pos + length > value.length) return Buffer.alloc(0);
  return value.subarray(pos, pos + length);
}

function extractNonceFromExtension(extValue: Buffer): Buffer {
  if (!extValue.length) return Buffer.alloc(0);
  if (extValue.length === 32) return extValue;
  if (extValue[0] === 0x04) {
    const candidate = extractAsn1OctetBytes(extValue);
    if (candidate.length === 32) return candidate;
  }
  if (extValue.length > 6) {
    const candidate = extValue.subarray(6);
    if (candidate.length === 32) return candidate;
  }
  return Buffer.alloc(0);
}

function verifyAppIdHash(
  authData: Buffer,
  allowedAppIds?: string[]
): [boolean, string, Buffer | null] {
  if (authData.length < 32) {
    return [false, "authData too short for rpIdHash", null];
  }

  if (allowedAppIds === undefined) {
    return [true, "", null];
  }

  if (allowedAppIds.length === 0) {
    return [false, "allowed_app_ids is empty", null];
  }

  const actual = authData.subarray(0, 32);
  for (const appId of allowedAppIds) {
    const expected = crypto
      .createHash("sha256")
      .update(appId, "utf-8")
      .digest();
    if (crypto.timingSafeEqual(actual, expected)) {
      return [true, "", expected];
    }
  }
  return [false, "app id hash does not match any allowed bundle id", null];
}

function verifyX5cChain(
  x5cCerts: crypto.X509Certificate[]
): [boolean, string, CertChainEntry[]] {
  const chainInfo = serializeCertChain(
    x5cCerts,
    "Apple App Attestation Root CA"
  );
  if (x5cCerts.length === 0) return [false, "empty x5c chain", chainInfo];

  // Check intermediate links
  for (const entry of chainInfo.slice(0, -1)) {
    if (!entry.signature_valid) {
      return [
        false,
        `x5c chain verification failed at cert[${entry.index}]`,
        chainInfo,
      ];
    }
  }

  // Verify last cert against Apple root
  const lastCert = x5cCerts[x5cCerts.length - 1];
  const rootVerified = verifyCertSignature(lastCert, APPLE_ROOT_CA.publicKey);
  if (chainInfo.length > 0) {
    chainInfo[chainInfo.length - 1].signature_valid = rootVerified;
  }

  if (!rootVerified) {
    return [
      false,
      "x5c chain not rooted to Apple App Attestation Root CA",
      chainInfo,
    ];
  }

  return [true, "", chainInfo];
}

// -- Public API ---------------------------------------------------------

export function verifyAppAttest(
  attestationB64: string,
  attestKeyIdB64: string,
  expectedClientDataHash: Buffer,
  userPublicKey: string,
  sessionChallengeB64: string,
  allowedAppIds?: string[]
): [boolean, string, Record<string, unknown>] {
  const details: Record<string, unknown> = {};

  function fail(
    reason: string
  ): [boolean, string, Record<string, unknown>] {
    details.failure_reason = reason;
    return [false, reason, details];
  }

  // Decode inputs
  let attestationData: Buffer;
  let sessionChallenge: Buffer;
  let attestKeyId: Buffer;
  try {
    attestationData = b64Decode(attestationB64);
    sessionChallenge = b64Decode(sessionChallengeB64);
    attestKeyId = decodeTextOrB64(attestKeyIdB64);
  } catch {
    return fail("invalid base64 in app attest fields");
  }

  let publicKeyBytes: Buffer;
  try {
    publicKeyBytes = Buffer.from(userPublicKey, "hex");
  } catch {
    return fail("invalid public key encoding");
  }

  const expectedHash = crypto
    .createHash("sha256")
    .update(sessionChallenge)
    .update(publicKeyBytes)
    .digest();
  if (
    expectedHash.length !== expectedClientDataHash.length ||
    !crypto.timingSafeEqual(expectedHash, expectedClientDataHash)
  ) {
    return fail("attest challenge binding failed");
  }

  // Decode CBOR attestation
  let attestation: Record<string, unknown>;
  try {
    attestation = decode(attestationData) as Record<string, unknown>;
  } catch (exc) {
    return fail(`invalid attestation object: ${exc}`);
  }

  if (typeof attestation !== "object" || attestation === null) {
    return fail("attestation object must be a map");
  }

  let fmt = cborMapGet(attestation, "fmt");
  if (fmt === undefined) return fail("attestation missing fmt");
  if (Buffer.isBuffer(fmt)) fmt = fmt.toString("utf-8");
  if (fmt !== "apple-appattest" && fmt !== "apple") {
    return fail(`unsupported attestation format: ${fmt}`);
  }
  details.fmt = fmt;

  const authData = asBuffer(cborMapGet(attestation, "authData"));
  if (authData === null) return fail("attestation missing authData");
  details.auth_data_len = authData.length;
  details.auth_data_rp_id_hash = authData.subarray(0, 32).toString("hex");

  // Verify app ID hash
  details.app_id_hash_configured = allowedAppIds !== undefined;
  details.app_id_hash_actual = authData.subarray(0, 32).toString("hex");
  const [appIdOk, appIdReason, matchedHash] = verifyAppIdHash(
    authData,
    allowedAppIds
  );
  details.app_id_hash_expected = matchedHash
    ? matchedHash.toString("hex")
    : null;
  if (!appIdOk) {
    details.app_id_hash_verified = false;
    return fail(appIdReason);
  }
  details.app_id_hash_verified = true;

  const attStmt = cborMapGet(attestation, "attStmt") as
    | Record<string, unknown>
    | undefined;
  if (!attStmt || typeof attStmt !== "object") {
    return fail("attestation missing attStmt");
  }

  // Verify key ID
  const keyId = extractAuthenticatorKeyId(authData);
  if (
    keyId === null ||
    keyId.length !== attestKeyId.length ||
    !crypto.timingSafeEqual(keyId, attestKeyId)
  ) {
    details.key_id_len = keyId ? keyId.length : 0;
    return fail("app attest key id mismatch");
  }
  details.key_id_len = keyId.length;
  details.key_id_match = true;

  // Verify x5c chain
  const x5c = cborMapGet(attStmt, "x5c");
  if (!Array.isArray(x5c) || x5c.length === 0) {
    details.x5c_count = 0;
    return fail("attestation missing x5c certificate chain");
  }
  details.x5c_count = x5c.length;

  let x5cCerts: crypto.X509Certificate[];
  let leafCert: crypto.X509Certificate;
  try {
    x5cCerts = [];
    for (let i = 0; i < x5c.length; i++) {
      const raw = asBuffer(x5c[i]);
      if (raw === null)
        return fail(`invalid x5c certificate at index ${i}`);
      x5cCerts.push(new crypto.X509Certificate(raw));
    }
    leafCert = x5cCerts[0];
  } catch (exc) {
    return fail(`invalid x5c certificate: ${exc}`);
  }

  const [chainOk, chainReason, chainInfo] = verifyX5cChain(x5cCerts);
  details.x5c_chain_verified = chainOk;
  details.cert_chain = chainInfo;
  if (!chainOk) return fail(chainReason);

  // Verify nonce
  const nonce = crypto
    .createHash("sha256")
    .update(authData)
    .update(expectedClientDataHash)
    .digest();

  let extNonce: Buffer = Buffer.alloc(0);
  const extPayload = findExtensionValue(Buffer.from(leafCert.raw), APPLE_ATTEST_NONCE_OID);
  if (extPayload) {
    extNonce = extractNonceFromExtension(extPayload);
  }
  details.attestation_nonce_expected_hex = nonce.toString("hex");
  details.attestation_nonce_extension_hex = extNonce.length
    ? extNonce.toString("hex")
    : "";
  if (
    !extNonce.length ||
    extNonce.length !== nonce.length ||
    !crypto.timingSafeEqual(extNonce, nonce)
  ) {
    details.attestation_nonce_verified = false;
    return fail("attestation nonce check failed");
  }
  details.attestation_nonce_verified = true;

  // Verify signature (optional field)
  const signature = asBuffer(cborMapGet(attStmt, "sig"));
  if (signature !== null) {
    try {
      const valid = crypto.verify(
        "sha256",
        Buffer.concat([authData, expectedClientDataHash]),
        leafCert.publicKey,
        signature
      );
      if (!valid) {
        details.attestation_signature_verified = false;
        return fail("attestation signature failed");
      }
    } catch (exc) {
      details.attestation_signature_verified = false;
      return fail(`attestation signature failed: ${exc}`);
    }
  }
  details.attestation_signature_verified = signature !== null;

  details.valid = true;
  details.verified_at = Date.now() / 1000;
  return [true, "ok", details];
}
