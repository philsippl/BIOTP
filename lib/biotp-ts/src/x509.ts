import * as crypto from "node:crypto";

// -- Minimal DER parser for extension extraction ------------------------

interface DerNode {
  tag: number;
  cls: number;
  constructed: boolean;
  value: Buffer;
  children?: DerNode[];
}

function parseDer(
  data: Buffer,
  offset = 0
): { node: DerNode; end: number } {
  const tag = data[offset++];
  const cls = (tag >> 6) & 0x03;
  const constructed = (tag & 0x20) !== 0;

  let length: number;
  const lenByte = data[offset++];
  if (lenByte < 0x80) {
    length = lenByte;
  } else {
    const numBytes = lenByte & 0x7f;
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = length * 256 + data[offset++];
    }
  }

  const value = data.subarray(offset, offset + length);
  const end = offset + length;
  const node: DerNode = { tag, cls, constructed, value };

  if (constructed) {
    node.children = [];
    let pos = 0;
    while (pos < value.length) {
      const result = parseDer(value, pos);
      node.children.push(result.node);
      pos = result.end;
    }
  }

  return { node, end };
}

function decodeOid(data: Buffer): string {
  if (data.length === 0) return "";
  const parts: number[] = [Math.floor(data[0] / 40), data[0] % 40];
  let value = 0;
  for (let i = 1; i < data.length; i++) {
    value = value * 128 + (data[i] & 0x7f);
    if ((data[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

export function findExtensionValue(
  certDer: Buffer,
  targetOid: string
): Buffer | null {
  const { node: cert } = parseDer(certDer);
  const tbs = cert.children?.[0];
  if (!tbs?.children) return null;

  for (const child of tbs.children) {
    // Extensions are tagged [3] EXPLICIT (context-specific, constructed)
    if (child.cls === 2 && (child.tag & 0x1f) === 3) {
      const extsSeq = child.children?.[0];
      if (!extsSeq?.children) return null;

      for (const ext of extsSeq.children) {
        if (!ext.children || ext.children.length < 2) continue;
        const oidStr = decodeOid(ext.children[0].value);
        if (oidStr === targetOid) {
          // Value is the last child (OCTET STRING), skip critical bool if present
          const valNode = ext.children[ext.children.length - 1];
          return Buffer.from(valNode.value);
        }
      }
    }
  }
  return null;
}

// -- Certificate chain utilities ----------------------------------------

export function verifyCertSignature(
  child: crypto.X509Certificate,
  issuerPub: crypto.KeyObject
): boolean {
  try {
    return child.verify(issuerPub);
  } catch {
    return false;
  }
}

function safeCertName(name: string | undefined): string {
  if (!name) return "n/a";
  try {
    return name.replace(/\n/g, ", ");
  } catch {
    return "unable-to-parse";
  }
}

export interface CertChainEntry {
  index: number;
  role: string;
  subject: string;
  issuer: string;
  serial: string;
  not_before: string;
  not_after: string;
  signed_by: string;
  signature_valid: boolean;
}

export function serializeCertChain(
  certs: crypto.X509Certificate[],
  rootLabel = "Google Root"
): CertChainEntry[] {
  if (certs.length === 0) return [];

  const result: CertChainEntry[] = [];
  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i];
    let subject: string,
      issuer: string,
      serial: string,
      notBefore: string,
      notAfter: string;
    try {
      subject = safeCertName(cert.subject);
      issuer = safeCertName(cert.issuer);
      serial = cert.serialNumber;
      notBefore = cert.validFrom;
      notAfter = cert.validTo;
    } catch {
      subject = issuer = serial = notBefore = notAfter = "parse error";
    }

    let signedBy: string;
    let verified: boolean;
    if (i < certs.length - 1) {
      signedBy = `cert[${i + 1}]`;
      verified = verifyCertSignature(cert, certs[i + 1].publicKey);
    } else {
      signedBy = rootLabel;
      verified = false; // caller should set this for root check
    }

    result.push({
      index: i,
      role:
        i === 0 ? "leaf" : i === certs.length - 1 ? "root" : "intermediate",
      subject,
      issuer,
      serial,
      not_before: notBefore,
      not_after: notAfter,
      signed_by: signedBy,
      signature_valid: verified,
    });
  }

  return result;
}
