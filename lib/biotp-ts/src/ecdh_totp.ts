import * as crypto from "node:crypto";

const P256_ORDER = BigInt(
  "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
);

function bigintToBuffer(n: bigint, length: number): Buffer {
  const hex = n.toString(16).padStart(length * 2, "0");
  return Buffer.from(hex, "hex");
}

function bufferToBigint(buf: Buffer): bigint {
  return BigInt("0x" + buf.toString("hex"));
}

function x963kdf(
  sharedSecret: Buffer,
  sharedInfo: Buffer,
  length: number
): Buffer {
  const blocks: Buffer[] = [];
  let total = 0;
  let counter = 1;
  while (total < length) {
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(counter);
    const hash = crypto
      .createHash("sha256")
      .update(sharedSecret)
      .update(counterBuf)
      .update(sharedInfo)
      .digest();
    blocks.push(hash);
    total += hash.length;
    counter++;
  }
  return Buffer.concat(blocks).subarray(0, length);
}

function ecKeyFromScalar(scalar: bigint): {
  privateKey: crypto.KeyObject;
  publicRaw: Buffer;
} {
  const dBuf = bigintToBuffer(scalar, 32);
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(dBuf);
  const pubUncompressed = Buffer.from(ecdh.getPublicKey()); // 04 || X || Y

  const x = pubUncompressed.subarray(1, 33);
  const y = pubUncompressed.subarray(33, 65);

  const privateKey = crypto.createPrivateKey({
    key: {
      kty: "EC",
      crv: "P-256",
      d: dBuf.toString("base64url"),
      x: x.toString("base64url"),
      y: y.toString("base64url"),
    },
    format: "jwk",
  });

  return { privateKey, publicRaw: pubUncompressed };
}

export class MasterKey {
  private _secret: Buffer;
  private _period: number;
  private _scalar: bigint;
  private _privateKey: crypto.KeyObject;
  private _publicRaw: Buffer; // raw X||Y (64 bytes, no 04 prefix)

  constructor(secret: Buffer, period = 30) {
    this._secret = secret;
    this._period = period;

    const raw = this._deriveMaterial(Buffer.from("humancheck:master-private"));
    this._scalar = (bufferToBigint(raw) % (P256_ORDER - 1n)) + 1n;

    const { privateKey, publicRaw } = ecKeyFromScalar(this._scalar);
    this._privateKey = privateKey;
    this._publicRaw = publicRaw.subarray(1); // strip 04 prefix -> X||Y
  }

  get publicRaw(): Buffer {
    return this._publicRaw;
  }

  get period(): number {
    return this._period;
  }

  currentCounter(): number {
    return Math.floor(Date.now() / 1000 / this._period);
  }

  tweakScalar(counter: number): bigint {
    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter));
    const digest = crypto
      .createHmac("sha256", this._publicRaw)
      .update(counterBuf)
      .digest();
    return bufferToBigint(digest) % P256_ORDER;
  }

  childPrivateForCounter(counter: number): crypto.KeyObject {
    let d = (this._scalar + this.tweakScalar(counter)) % P256_ORDER;
    if (d === 0n) d = 1n;
    return ecKeyFromScalar(d).privateKey;
  }

  childPubkeyHex(counter: number): string {
    let d = (this._scalar + this.tweakScalar(counter)) % P256_ORDER;
    if (d === 0n) d = 1n;
    const { publicRaw } = ecKeyFromScalar(d);
    return publicRaw.toString("hex"); // includes 04 prefix
  }

  static computeSharedSecret(
    serverPrivate: crypto.KeyObject,
    userPubkeyHex: string
  ): Buffer {
    const pubBytes = Buffer.from(userPubkeyHex, "hex");
    let x: Buffer, y: Buffer;
    if (pubBytes.length === 65 && pubBytes[0] === 0x04) {
      x = pubBytes.subarray(1, 33);
      y = pubBytes.subarray(33, 65);
    } else if (pubBytes.length === 64) {
      x = pubBytes.subarray(0, 32);
      y = pubBytes.subarray(32, 64);
    } else {
      throw new Error("invalid public key length");
    }

    const userPub = crypto.createPublicKey({
      key: {
        kty: "EC",
        crv: "P-256",
        x: x.toString("base64url"),
        y: y.toString("base64url"),
      },
      format: "jwk",
    });

    const rawShared = crypto.diffieHellman({
      privateKey: serverPrivate,
      publicKey: userPub,
    });

    return x963kdf(Buffer.from(rawShared), Buffer.alloc(0), 32);
  }

  static computeTotp(sharedSecret: Buffer, counter: number): string {
    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter));
    const h = crypto
      .createHmac("sha256", sharedSecret)
      .update(counterBuf)
      .digest();
    const offset = h[h.length - 1] & 0x0f;
    const truncated = h.readUInt32BE(offset) & 0x7fffffff;
    const otp = truncated % 1_000_000;
    return otp.toString().padStart(6, "0");
  }

  verifyOtp(
    userPubkeyHex: string,
    otp: string,
    { skew = 1, lastCounter = -1 }: { skew?: number; lastCounter?: number } = {}
  ): [boolean, number] {
    const counter = this.currentCounter();
    for (let i = -skew; i <= skew; i++) {
      const c = counter + i;
      if (c <= lastCounter) continue;
      const sk = this.childPrivateForCounter(c);
      const shared = MasterKey.computeSharedSecret(sk, userPubkeyHex);
      const expected = MasterKey.computeTotp(shared, c);
      if (
        expected.length === otp.length &&
        crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(otp))
      ) {
        return [true, c];
      }
    }
    return [false, -1];
  }

  private _deriveMaterial(label: Buffer, length = 32): Buffer {
    return Buffer.from(
      crypto.hkdfSync(
        "sha256",
        this._secret,
        Buffer.from("humancheck-offline-v1"),
        label,
        length
      )
    );
  }
}
