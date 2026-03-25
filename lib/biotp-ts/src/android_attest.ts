import * as crypto from "node:crypto";
import {
  findExtensionValue,
  verifyCertSignature,
  serializeCertChain,
  CertChainEntry,
} from "./x509";

const ANDROID_KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

const TAG_USER_AUTH_TYPE = 504;
const TAG_NO_AUTH_REQUIRED = 503;
const TAG_AUTH_TIMEOUT = 505;
const AUTH_TYPE_FINGERPRINT = 0x02;
const SECURITY_LEVEL_TEE = 1;
const SECURITY_LEVEL_STRONGBOX = 2;

// -- DER parser for KeyDescription -------------------------------------

function parseDerElement(
  data: Buffer,
  offset: number
): { tag: number; constructed: boolean; cls: number; value: Buffer; end: number } {
  const tagByte = data[offset++];
  const cls = (tagByte >> 6) & 0x03;
  const constructed = (tagByte & 0x20) !== 0;
  let tag = tagByte & 0x1f;

  if (tag === 0x1f) {
    tag = 0;
    while (true) {
      const b = data[offset++];
      tag = (tag << 7) | (b & 0x7f);
      if (!(b & 0x80)) break;
    }
  }

  const lenByte = data[offset++];
  let length: number;
  if (lenByte < 0x80) {
    length = lenByte;
  } else {
    const n = lenByte & 0x7f;
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + data[offset++];
  }

  const value = data.subarray(offset, offset + length);
  return { tag, constructed, cls, value, end: offset + length };
}

function parseDerSequence(
  data: Buffer
): Array<{ tag: number; constructed: boolean; cls: number; value: Buffer }> {
  const elements: Array<{ tag: number; constructed: boolean; cls: number; value: Buffer }> = [];
  let offset = 0;
  while (offset < data.length) {
    const el = parseDerElement(data, offset);
    elements.push({ tag: el.tag, constructed: el.constructed, cls: el.cls, value: el.value });
    offset = el.end;
  }
  return elements;
}

function parseDerInteger(data: Buffer): number {
  let val = data[0] & 0x80 ? -1 : 0;
  for (const b of data) val = (val << 8) | b;
  return val;
}

function parseAuthorizationList(seqData: Buffer): Record<number, unknown> {
  const result: Record<number, unknown> = {};
  for (const el of parseDerSequence(seqData)) {
    if (el.cls === 2 && el.constructed && el.value.length > 0) {
      const inner = parseDerElement(el.value, 0);
      if (inner.tag === 2) {
        result[el.tag] = parseDerInteger(inner.value);
      } else if (inner.tag === 5) {
        result[el.tag] = true;
      } else if (inner.tag === 17) {
        // SET OF INTEGER
        const items = parseDerSequence(inner.value);
        result[el.tag] = items.filter((i) => i.tag === 2).map((i) => parseDerInteger(i.value));
      } else {
        result[el.tag] = inner.value;
      }
    }
  }
  return result;
}

interface KeyDescription {
  attestationSecurityLevel: number;
  softwareEnforced: Record<number, unknown>;
  teeEnforced: Record<number, unknown>;
  error?: string;
}

function parseKeyDescription(extData: Buffer): KeyDescription {
  try {
    const outer = parseDerElement(extData, 0);
    if (outer.tag !== 16 || !outer.constructed)
      return { attestationSecurityLevel: 0, softwareEnforced: {}, teeEnforced: {}, error: "not a SEQUENCE" };

    const elements = parseDerSequence(outer.value);
    if (elements.length < 8)
      return { attestationSecurityLevel: 0, softwareEnforced: {}, teeEnforced: {}, error: `expected 8 elements, got ${elements.length}` };

    return {
      attestationSecurityLevel: parseDerInteger(elements[1].value),
      softwareEnforced: parseAuthorizationList(elements[6].value),
      teeEnforced: parseAuthorizationList(elements[7].value),
    };
  } catch (exc) {
    return { attestationSecurityLevel: 0, softwareEnforced: {}, teeEnforced: {}, error: String(exc) };
  }
}

const GOOGLE_ROOT_CERTS_PEM = [
  // Root 1 (RSA)
  `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`,
  // Root 2 (EC, more common on modern devices)
  `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`,
];

function loadGoogleRoots(): crypto.X509Certificate[] {
  const roots: crypto.X509Certificate[] = [];
  for (const pem of GOOGLE_ROOT_CERTS_PEM) {
    try {
      roots.push(new crypto.X509Certificate(pem));
    } catch {
      // skip invalid roots
    }
  }
  return roots;
}

const GOOGLE_ROOTS = loadGoogleRoots();

function verifyChain(
  certs: crypto.X509Certificate[]
): [boolean, string, CertChainEntry[]] {
  const chainInfo = serializeCertChain(
    certs,
    "Google Hardware Attestation Root"
  );
  if (certs.length === 0) return [false, "empty certificate chain", chainInfo];

  // Check intermediate links
  for (const entry of chainInfo.slice(0, -1)) {
    if (!entry.signature_valid) {
      return [
        false,
        `chain verification failed at cert[${entry.index}]`,
        chainInfo,
      ];
    }
  }

  // Verify last cert against known Google root (cryptographic check only)
  const lastCert = certs[certs.length - 1];
  let rootVerified = false;
  for (const root of GOOGLE_ROOTS) {
    if (verifyCertSignature(lastCert, root.publicKey)) {
      rootVerified = true;
      break;
    }
  }

  if (chainInfo.length > 0) {
    chainInfo[chainInfo.length - 1].signature_valid = rootVerified;
  }

  if (!rootVerified) {
    return [
      false,
      "chain not rooted to a known Google hardware attestation root",
      chainInfo,
    ];
  }

  return [true, "", chainInfo];
}

export function verifyAndroidAttestation(
  certChainB64: string[],
  expectedChallenge: Buffer,
  userPublicKeyHex: string,
  requireBiometric = true
): [boolean, string, Record<string, unknown>] {
  const details: Record<string, unknown> = {};

  if (!certChainB64.length) {
    return [false, "no attestation chain provided", details];
  }

  // Parse certs
  let certs: crypto.X509Certificate[];
  try {
    certs = certChainB64.map((b64) => {
      const der = Buffer.from(b64, "base64");
      return new crypto.X509Certificate(der);
    });
    details.chain_length = certs.length;
  } catch (exc) {
    return [false, `invalid certificate in chain: ${exc}`, details];
  }

  // Verify chain
  const [chainOk, chainReason, chainInfo] = verifyChain(certs);
  details.chain_verified = chainOk;
  details.cert_chain = chainInfo;
  if (!chainOk) {
    details.failure_reason = chainReason;
    return [false, chainReason, details];
  }

  // Extract key attestation extension from leaf
  const leaf = certs[0];
  const extData = findExtensionValue(
    leaf.raw,
    ANDROID_KEY_ATTESTATION_OID
  );
  if (extData === null) {
    details.attestation_extension_present = false;
    return [
      false,
      "no key attestation extension; key is not hardware-attested",
      details,
    ];
  }
  details.attestation_extension_present = true;
  details.attestation_extension_len = extData.length;

  // Verify leaf certificate public key matches the registered public key
  try {
    const leafPubJwk = leaf.publicKey.export({ format: "jwk" }) as {
      x?: string;
      y?: string;
      kty?: string;
      crv?: string;
    };
    if (leafPubJwk.kty !== "EC" || !leafPubJwk.x || !leafPubJwk.y) {
      return [
        false,
        "leaf certificate does not contain an EC public key",
        details,
      ];
    }
    const leafX = Buffer.from(leafPubJwk.x, "base64url");
    const leafY = Buffer.from(leafPubJwk.y, "base64url");
    const leafRawHex = Buffer.concat([leafX, leafY]).toString("hex");
    details.leaf_public_key_hex = leafRawHex.substring(0, 20) + "...";
    if (leafRawHex !== userPublicKeyHex) {
      return [
        false,
        "leaf certificate public key does not match registered key",
        details,
      ];
    }
    details.public_key_binding = true;
  } catch (exc) {
    return [false, `failed to extract leaf public key: ${exc}`, details];
  }

  // Verify challenge is present in attestation extension
  const challengeHash = crypto
    .createHash("sha256")
    .update(expectedChallenge)
    .update(Buffer.from(userPublicKeyHex, "hex"))
    .digest();

  if (extData.includes(expectedChallenge)) {
    details.challenge_binding = "raw_challenge_found";
  } else if (extData.includes(challengeHash)) {
    details.challenge_binding = "challenge_hash_found";
  } else {
    return [
      false,
      "challenge not found in attestation extension",
      details,
    ];
  }

  // Parse KeyDescription for authorization details
  const keyDesc = parseKeyDescription(extData);
  if (!keyDesc.error) {
    const tee = keyDesc.teeEnforced;
    const sw = keyDesc.softwareEnforced;
    const userAuthTypeTee = typeof tee[TAG_USER_AUTH_TYPE] === "number" ? tee[TAG_USER_AUTH_TYPE] as number : 0;
    const userAuthTypeSw = typeof sw[TAG_USER_AUTH_TYPE] === "number" ? sw[TAG_USER_AUTH_TYPE] as number : 0;
    const noAuth = tee[TAG_NO_AUTH_REQUIRED] || sw[TAG_NO_AUTH_REQUIRED];
    const authTimeout = typeof tee[TAG_AUTH_TIMEOUT] === "number" ? tee[TAG_AUTH_TIMEOUT] as number : undefined;

    const biometricInTee = (userAuthTypeTee & AUTH_TYPE_FINGERPRINT) !== 0;
    const biometricInSw = (userAuthTypeSw & AUTH_TYPE_FINGERPRINT) !== 0;

    const secLevel = keyDesc.attestationSecurityLevel;
    details.key_protection = {
      security_level:
        secLevel === SECURITY_LEVEL_STRONGBOX ? "StrongBox" :
        secLevel === SECURITY_LEVEL_TEE ? "TEE" : "Software",
      biometric_required_tee: biometricInTee,
      biometric_required_sw: biometricInSw,
      no_auth_required: Boolean(noAuth),
      auth_timeout: authTimeout,
    };

    if (requireBiometric && !biometricInTee) {
      return [false, "key is not biometrically protected in TEE", details];
    }
  } else {
    details.key_description_parse_error = keyDesc.error;
    if (requireBiometric) {
      return [false, `could not verify biometric protection: ${keyDesc.error}`, details];
    }
  }

  details.valid = true;
  details.verified_at = Date.now() / 1000;
  return [true, "ok", details];
}
