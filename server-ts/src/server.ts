import * as crypto from "node:crypto";
import * as os from "node:os";
import * as path from "node:path";
import express from "express";
import {
  MasterKey,
  verifyAppAttest,
  verifyAndroidAttestation,
} from "biotp";
import {
  initDb,
  getUser,
  userExists,
  insertUser,
  updateLastVerifiedCounter,
  listUsers,
  UserRow,
} from "./db";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PERIOD = 30;
const MASTER_SECRET = Buffer.from(
  process.env.MASTER_SECRET || crypto.randomBytes(32).toString("hex"),
  "hex"
);
const SESSION_TTL = 300;

const master = new MasterKey(MASTER_SECRET, PERIOD);

const rawAppIds = (process.env.ALLOWED_APP_IDS || "").trim();
const ALLOWED_APP_IDS: string[] | undefined = rawAppIds
  ? rawAppIds.split(",").map((s) => s.trim()).filter(Boolean)
  : undefined;

const ALLOW_SIMULATOR = ["1", "true", "yes"].includes(
  (process.env.ALLOW_SIMULATOR || "").trim().toLowerCase()
);

const ICON_COLOR_PALETTE = [
  "#6366f1",
  "#ec4899",
  "#14b8a6",
  "#f59e0b",
  "#8b5cf6",
  "#ef4444",
  "#06b6d4",
  "#22c55e",
];

// ---------------------------------------------------------------------------
// In-memory stores (sessions only — users are in Postgres)
// ---------------------------------------------------------------------------

interface RegistrationSession {
  status: string;
  rp_name: string;
  created_at: number;
  attest_challenge: string;
  user_id?: string;
}

const registrationSessions = new Map<string, RegistrationSession>();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function b64Decode(value: string): Buffer {
  let normalized = value.trim().replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (normalized.length % 4)) % 4;
  normalized += "=".repeat(pad);
  return Buffer.from(normalized, "base64");
}

function deriveRelyingPartyColorSeed(
  userId: string,
  record: UserRow
): string {
  const pk = record.public_key?.trim();
  if (pk) return pk;

  const rpName = record.rp_name?.trim();
  if (rpName) return rpName;

  if (!userId) return "HumanCheck";

  const lastDash = userId.lastIndexOf("-");
  if (lastDash !== -1) {
    const suffix = userId.substring(lastDash + 1);
    if (suffix.length === 4 && /^[a-zA-Z0-9]+$/.test(suffix)) {
      return userId.substring(0, lastDash);
    }
  }

  return userId;
}

function stableFnv1a64(value: string): bigint {
  const normalized = Buffer.from(value.trim().toLowerCase(), "utf-8");
  let hash = 1469598103934665603n;
  const prime = 1099511628211n;
  for (const byte of normalized) {
    hash ^= BigInt(byte);
    hash = (hash * prime) & 0xFFFFFFFFFFFFFFFFn;
  }
  return hash;
}

function deriveRelyingPartyColor(seed: string): string {
  if (!seed?.trim()) return ICON_COLOR_PALETTE[0];
  const index = Number(stableFnv1a64(seed) % BigInt(ICON_COLOR_PALETTE.length));
  return ICON_COLOR_PALETTE[index];
}

function cleanupExpiredSessions(): void {
  const now = Date.now() / 1000;
  for (const [sid, session] of registrationSessions) {
    if (now - session.created_at > SESSION_TTL) {
      registrationSessions.delete(sid);
    }
  }
}

function validatePublicKey(hex: string): string | null {
  try {
    const raw = Buffer.from(hex, "hex");
    let normalized: Buffer;
    if (raw.length === 64) {
      normalized = Buffer.concat([Buffer.from([0x04]), raw]);
    } else {
      normalized = raw;
    }
    // Validate by creating a key object
    const x = normalized.subarray(1, 33);
    const y = normalized.subarray(33, 65);
    crypto.createPublicKey({
      key: { kty: "EC", crv: "P-256", x: x.toString("base64url"), y: y.toString("base64url") },
      format: "jwk",
    });
    return normalized.toString("hex");
  } catch {
    return null;
  }
}

function getLanIp(): string {
  const interfaces = os.networkInterfaces();
  for (const iface of Object.values(interfaces)) {
    if (!iface) continue;
    for (const addr of iface) {
      if (addr.family === "IPv4" && !addr.internal) return addr.address;
    }
  }
  return "127.0.0.1";
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());

const staticDir = path.join(__dirname, "..", "static");
app.use(express.static(staticDir));

// ---------------------------------------------------------------------------
// Web UI
// ---------------------------------------------------------------------------

app.get("/", (_req, res) => {
  res.set("Cache-Control", "no-store");
  res.sendFile(path.join(staticDir, "index.html"));
});

app.get("/how-it-works", (_req, res) => {
  res.set("Cache-Control", "no-store");
  res.sendFile(path.join(staticDir, "how-it-works.html"));
});

// ---------------------------------------------------------------------------
// Key status (debug)
// ---------------------------------------------------------------------------

app.get("/key", (_req, res) => {
  const counter = master.currentCounter();
  const remaining = PERIOD - (Math.floor(Date.now() / 1000) % PERIOD);
  res.json({
    public_key: master.childPubkeyHex(counter),
    counter,
    expires_in: remaining,
    mode: "offline-derived",
  });
});

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

app.post("/register/start", (req, res) => {
  cleanupExpiredSessions();
  const data = req.body || {};
  const rpName: string = data.rp_name || "HumanCheck Demo";

  const sessionId = crypto.randomUUID();
  const publicBaseUrl = (process.env.PUBLIC_BASE_URL || "").trim().replace(/\/+$/, "");

  let serverUrl: string;
  if (publicBaseUrl) {
    serverUrl = publicBaseUrl;
  } else {
    serverUrl = `${req.protocol}://${req.get("host")}`;
  }
  if (
    !publicBaseUrl &&
    (serverUrl.includes("localhost") || serverUrl.includes("127.0.0.1"))
  ) {
    serverUrl = `http://${getLanIp()}:8787`;
  }

  registrationSessions.set(sessionId, {
    status: "pending",
    rp_name: rpName,
    created_at: Date.now() / 1000,
    attest_challenge: crypto.randomBytes(32).toString("base64"),
  });

  const session = registrationSessions.get(sessionId)!;

  res.json({
    session_id: sessionId,
    qr_data: {
      action: "register",
      callback_url: `${serverUrl}/register/complete`,
      rp_name: rpName,
      session_id: sessionId,
      master_public: master.publicRaw.toString("hex"),
      period: PERIOD,
      attest_challenge: session.attest_challenge,
    },
  });
});

app.get("/register/status/:sessionId", (req, res) => {
  const session = registrationSessions.get(req.params.sessionId);
  if (!session) {
    res.status(404).json({ error: "session not found" });
    return;
  }
  res.json({ status: session.status, user_id: session.user_id });
});

app.post("/register/complete", async (req, res) => {
  const data = req.body;
  const sessionId: string | undefined = data.session_id;
  const userId: string | undefined = data.user_id;
  const publicKey: string | undefined = data.public_key;
  const platform: string = data.platform || "ios";

  if (!sessionId || !userId || !publicKey) {
    res
      .status(400)
      .json({ error: "session_id, user_id, and public_key required" });
    return;
  }

  if (await userExists(userId)) {
    res.status(409).json({ error: "user_id already registered" });
    return;
  }

  const session = registrationSessions.get(sessionId);
  if (!session) {
    res.status(404).json({ error: "invalid session" });
    return;
  }
  if (session.status !== "pending") {
    res.status(400).json({ error: "session already completed" });
    return;
  }
  if (Date.now() / 1000 - session.created_at > SESSION_TTL) {
    registrationSessions.delete(sessionId);
    res.status(410).json({ error: "session expired" });
    return;
  }

  const normalizedHex = validatePublicKey(publicKey);
  if (!normalizedHex) {
    res.status(400).json({ error: "invalid public key" });
    return;
  }

  const sessionChallenge = session.attest_challenge;
  if (typeof sessionChallenge !== "string") {
    res.status(500).json({ error: "invalid session state" });
    return;
  }

  // Platform-specific attestation verification
  let ok = false;
  let reason = "";
  let attestationDetails: Record<string, unknown> = {};

  if (platform === "android") {
    const androidChain: string[] = data.android_attestation_chain || [];
    try {
      const challengeBytes = b64Decode(sessionChallenge);
      [ok, reason, attestationDetails] = verifyAndroidAttestation(
        androidChain,
        challengeBytes,
        publicKey,
        !ALLOW_SIMULATOR
      );
    } catch (exc) {
      if (!ALLOW_SIMULATOR) {
        res
          .status(500)
          .json({ error: `attestation parsing failed: ${exc}` });
        return;
      }
      ok = false;
      reason = String(exc);
      attestationDetails = { error: String(exc) };
    }
  } else {
    // iOS App Attest
    const attestChallenge: string | undefined = data.attest_challenge;
    const attestKeyId: string | undefined = data.attest_key_id;
    const attestClientDataHash: string | undefined =
      data.attest_client_data_hash;
    const attestationObject: string | undefined = data.attest_object;

    if (
      !attestChallenge ||
      !attestKeyId ||
      !attestClientDataHash ||
      !attestationObject
    ) {
      if (!ALLOW_SIMULATOR) {
        res
          .status(400)
          .json({ error: "app attest fields are required" });
        return;
      }
      ok = false;
      reason = "fields missing";
      attestationDetails = { error: "fields missing" };
    } else {
      try {
        const clientHash = b64Decode(attestClientDataHash);
        [ok, reason, attestationDetails] = verifyAppAttest(
          attestationObject,
          attestKeyId,
          clientHash,
          publicKey,
          sessionChallenge,
          ALLOWED_APP_IDS
        );
      } catch (exc) {
        if (!ALLOW_SIMULATOR) {
          res
            .status(500)
            .json({ error: `attestation parsing failed: ${exc}` });
          return;
        }
        ok = false;
        reason = String(exc);
        attestationDetails = { error: String(exc) };
      }
    }
  }

  if (!ok && ALLOW_SIMULATOR) {
    attestationDetails.skipped = true;
    attestationDetails.original_reason = reason;
    ok = true;
    reason = "skipped (attestation disabled)";
  }

  if (!ok) {
    res.status(401).json({ error: `attestation failed: ${reason}` });
    return;
  }

  await insertUser(userId, normalizedHex, session.rp_name, platform, {
    valid: ok,
    details: attestationDetails,
    verified_at: Date.now() / 1000,
  });
  session.status = "completed";
  session.user_id = userId;

  console.log(`[register] ${userId} -> ${publicKey.substring(0, 20)}...`);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

app.post("/verify", async (req, res) => {
  const data = req.body;
  const userId: string | undefined = data.user_id;
  const otp: string | undefined = data.otp;

  if (!userId || !otp) {
    res.status(400).json({ error: "user_id and otp required" });
    return;
  }

  const userRecord = await getUser(userId);
  if (!userRecord) {
    console.log("[verify] unknown user_id attempted");
    res.status(401).json({ valid: false });
    return;
  }

  const lastCounter = userRecord.last_verified_counter ?? -1;

  const [valid, matchedCounter] = master.verifyOtp(
    userRecord.public_key,
    otp,
    { skew: 1, lastCounter }
  );

  if (valid) {
    await updateLastVerifiedCounter(userId, matchedCounter);
    console.log(
      `[verify] ${userId} OTP valid (counter=${matchedCounter})`
    );
    res.json({ valid: true, counter: matchedCounter });
    return;
  }

  console.log(`[verify] ${userId} OTP rejected`);
  res.status(401).json({ valid: false });
});

// ---------------------------------------------------------------------------
// Users list
// ---------------------------------------------------------------------------

app.get("/users", async (_req, res) => {
  const rows = await listUsers();
  const result = rows.map((record) => {
    const colorSeed = deriveRelyingPartyColorSeed(record.user_id, record);
    const attest = record.attestation;
    const details = attest?.details as Record<string, unknown> | undefined;
    const keyProtection = details?.key_protection as Record<string, unknown> | undefined;
    return {
      user_id: record.user_id,
      relying_party: record.rp_name || record.user_id,
      platform: record.platform || "ios",
      color_seed: colorSeed,
      icon_color: deriveRelyingPartyColor(colorSeed),
      public_key: record.public_key.substring(0, 20) + "...",
      key_protection: keyProtection ?? null,
      attestation: attest
        ? {
            valid: Boolean(attest.valid),
            verified_at: attest.verified_at,
            details: attest.details,
          }
        : null,
    };
  });
  res.json({ users: result });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const PORT = 8787;

async function main() {
  if (process.env.DATABASE_URL) {
    await initDb();
    console.log("Database: connected (Postgres)");
  } else {
    console.log("Database: none (DATABASE_URL not set, users will not persist)");
  }

  console.log(`Master public (raw): ${master.publicRaw.toString("hex")}`);
  console.log(
    `Public base URL override: ${(process.env.PUBLIC_BASE_URL || "<none>").trim() || "<none>"}`
  );
  console.log(
    `Allowed app IDs: ${ALLOWED_APP_IDS ? ALLOWED_APP_IDS.join(", ") : "<any (not configured)>"}`
  );
  console.log(`Period: ${PERIOD}s`);
  console.log(`Serving on http://0.0.0.0:${PORT}`);
  console.log();

  app.listen(PORT, "0.0.0.0");
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
