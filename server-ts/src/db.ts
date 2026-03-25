import { Pool } from "pg";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

export async function initDb(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      user_id       TEXT PRIMARY KEY,
      public_key    TEXT NOT NULL,
      rp_name       TEXT,
      platform      TEXT NOT NULL DEFAULT 'ios',
      attestation   JSONB,
      last_verified_counter INTEGER DEFAULT -1,
      created_at    DOUBLE PRECISION NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())
    )
  `);
}

export interface UserRow {
  user_id: string;
  public_key: string;
  rp_name: string | null;
  platform: string;
  attestation: {
    valid: boolean;
    details: Record<string, unknown>;
    verified_at: number;
  } | null;
  last_verified_counter: number;
}

export async function getUser(userId: string): Promise<UserRow | null> {
  const { rows } = await pool.query<UserRow>(
    "SELECT * FROM users WHERE user_id = $1",
    [userId]
  );
  return rows[0] ?? null;
}

export async function userExists(userId: string): Promise<boolean> {
  const { rows } = await pool.query(
    "SELECT 1 FROM users WHERE user_id = $1",
    [userId]
  );
  return rows.length > 0;
}

export async function insertUser(
  userId: string,
  publicKey: string,
  rpName: string | undefined,
  platform: string,
  attestation: {
    valid: boolean;
    details: Record<string, unknown>;
    verified_at: number;
  }
): Promise<void> {
  await pool.query(
    `INSERT INTO users (user_id, public_key, rp_name, platform, attestation)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, publicKey, rpName ?? null, platform, JSON.stringify(attestation)]
  );
}

export async function updateLastVerifiedCounter(
  userId: string,
  counter: number
): Promise<void> {
  await pool.query(
    "UPDATE users SET last_verified_counter = $1 WHERE user_id = $2",
    [counter, userId]
  );
}

export async function listUsers(): Promise<UserRow[]> {
  const { rows } = await pool.query<UserRow>(
    "SELECT * FROM users ORDER BY created_at DESC"
  );
  return rows;
}
