import "dotenv/config";
import express from "express";
import https from "https";
import http from "http";
import fs from "fs";
import path from "path";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3-multiple-ciphers";
import crypto from "crypto";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import { ed25519 } from "@noble/curves/ed25519.js";

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", false);
const PORT = parseInt(process.env.PORT || "5000", 10);
if (!process.env.JWT_SECRET) {
  console.error("[SECURITY] JWT_SECRET is not set — refusing to start. Set a stable random secret in .env to preserve sessions across restarts.");
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

// ── M2: TOTP-at-rest encryption — dedicated secret, independent of JWT_SECRET ──
if (!process.env.TOTP_ENC_SECRET) {
  console.error("[SECURITY] TOTP_ENC_SECRET is not set — refusing to start. TOTP secrets would become unrecoverable if JWT_SECRET ever rotates. Set a dedicated TOTP_ENC_SECRET in .env.");
  process.exit(1);
}
const TOTP_ENC_KEY = crypto.createHmac("sha256", process.env.TOTP_ENC_SECRET).update("lvls-totp-enc-v1").digest();
function encryptTotp(secret: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", TOTP_ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}
function decryptTotp(stored: string): string {
  try {
    const buf = Buffer.from(stored, "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", TOTP_ENC_KEY, buf.subarray(0, 12));
    decipher.setAuthTag(buf.subarray(12, 28));
    return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString("utf8");
  } catch { return stored; } // graceful fallback for plaintext secrets already in DB
}

// ── Per-vault AES-256-GCM for cached machine secrets ─────────────────────────
// Key derived from LVLS_DB_KEY + vault_id — server can encrypt/decrypt, never exposed to clients.
function vaultCacheKey(vaultId: string): Buffer {
  return Buffer.from(crypto.hkdfSync("sha256",
    Buffer.from(process.env.LVLS_DB_KEY!),
    Buffer.from(vaultId),
    Buffer.from("lvls-vault-cache-v1"),
    32
  ));
}
function encryptCachedSecret(plaintext: string, vaultId: string): string {
  const key = vaultCacheKey(vaultId);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const packed = Buffer.concat([iv, tag, enc]).toString("base64");
  return JSON.stringify({ type: "aes-cached", ciphertext: packed });
}
function decryptCachedSecret(stored: string, vaultId: string): string {
  const parsed = JSON.parse(stored);
  if (parsed.type !== "aes-cached") throw new Error("stale_format");
  const key = vaultCacheKey(vaultId);
  const buf = Buffer.from(parsed.ciphertext, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString("utf8");
}

// ── Request logging ─────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    if (req.path.startsWith("/api/")) {
      console.log(`[lvls] ${req.method} ${req.path} → ${res.statusCode} (${Date.now() - start}ms) [${req.ip}]`);
    }
  });
  next();
});

// ── H4: HTTP Security Headers ────────────────────────────────────────────────
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' chrome-extension: moz-extension:;");
  next();
});

// ── Cache-Control: no-store on all API responses (L-05) ──────────────────────
app.use("/api", (_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

// ---------- CORS — strict origin allowlist ----------
const ALLOWED_EXTENSION_ID = process.env.EXTENSION_ID || null;
const CLUTCH_ORIGIN = process.env.CLUTCH_ORIGIN || null;
const HOST = process.env.HOST || "127.0.0.1";
const CORS_ALLOWLIST = new Set([
  `https://${HOST}:${PORT}`,
  `http://localhost:${PORT}`,
  `https://localhost:${PORT}`,
  `http://127.0.0.1:${PORT}`,
  `https://127.0.0.1:${PORT}`,
]);
if (CLUTCH_ORIGIN) CORS_ALLOWLIST.add(CLUTCH_ORIGIN);
if (ALLOWED_EXTENSION_ID) {
  CORS_ALLOWLIST.add(`chrome-extension://${ALLOWED_EXTENSION_ID}`);
  CORS_ALLOWLIST.add(`moz-extension://${ALLOWED_EXTENSION_ID}`);
}
app.use((req, res, next) => {
  const origin = req.headers.origin || "";
  if (CORS_ALLOWLIST.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ---------- Rate Limiter — Fix 2: DB-persisted, survives restarts ----------
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 5;

// Backup/restore endpoints need larger bodies — must be registered before the global 16kb parser
app.use("/api/vault/restore", express.json({ limit: "50mb" }));
app.use(express.json({ limit: "16kb" }));

// ---------- Database ----------
if (!process.env.LVLS_DB_KEY) {
  console.error("[SECURITY] LVLS_DB_KEY not set — refusing to start. Set it in .env");
  process.exit(1);
}
const db = new Database("lvls.db");
db.pragma(`key='${process.env.LVLS_DB_KEY!.replace(/'/g, "''")}'`);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    level INTEGER NOT NULL,
    secret_type TEXT DEFAULT 'custom',
    encrypted_value TEXT NOT NULL,
    iv TEXT,
    salt TEXT,
    tags TEXT,
    expiry TEXT,
    url TEXT,
    username TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS session_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    user_level INTEGER NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS auth_config (
    level INTEGER PRIMARY KEY,
    credential_hash TEXT NOT NULL,
    kem_public_key TEXT,
    method TEXT NOT NULL DEFAULT 'passphrase',
    totp_secret TEXT,
    totp_enabled INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ── M1: Token revocation table ───────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS revoked_tokens (
    session_id TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
  );
`);

// ── M3: TOTP replay prevention ────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS used_totps (
    code TEXT NOT NULL,
    level INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (code, level)
  );
`);

// ---------- Rate limits table (Fix 2) ----------
db.exec(`
  CREATE TABLE IF NOT EXISTS rate_limits (
    ip TEXT PRIMARY KEY,
    count INTEGER DEFAULT 0,
    reset_at INTEGER NOT NULL
  );
`);

// ---------- Machine Vaults ----------
db.exec(`
  CREATE TABLE IF NOT EXISTS machine_vaults (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    kem_public_key TEXT,
    totp_secret TEXT,
    totp_enabled INTEGER DEFAULT 0,
    ttl INTEGER DEFAULT 14400,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS machine_secrets (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    name TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vault_id) REFERENCES machine_vaults(id) ON DELETE CASCADE
  );
`);

// ---------- Lease-based secrets system ----------
db.exec(`
  CREATE TABLE IF NOT EXISTS vault_grants (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    granted_by TEXT NOT NULL DEFAULT 'admin',
    max_ttl_seconds INTEGER NOT NULL DEFAULT 3600,
    scoped_keys TEXT,
    active INTEGER DEFAULT 1,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    FOREIGN KEY (vault_id) REFERENCES machine_vaults(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS leases (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    grace_until INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    revoked_at INTEGER,
    revoke_reason TEXT,
    refresh_count INTEGER DEFAULT 0,
    last_refreshed INTEGER,
    FOREIGN KEY (vault_id) REFERENCES machine_vaults(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS lease_audit (
    id TEXT PRIMARY KEY,
    lease_id TEXT,
    event TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    vault_id TEXT NOT NULL,
    keys_accessed TEXT,
    source_ip TEXT,
    occurred_at INTEGER NOT NULL,
    metadata TEXT
  );
`);
try { db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_grants_unique ON vault_grants(vault_id, machine_id) WHERE active = 1"); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_leases_machine ON leases(machine_id, status)"); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_leases_expires ON leases(expires_at, status)"); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_leases_vault ON leases(vault_id, status)"); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_lease_audit_lease ON lease_audit(lease_id)"); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_lease_audit_machine ON lease_audit(machine_id, occurred_at)"); } catch {}
try { db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_machine_secrets_unique ON machine_secrets(vault_id, name)"); } catch {}

db.exec(`
`);

// ---------- Machine identities — Ed25519 public keys per machine ---------------
db.exec(`
  CREATE TABLE IF NOT EXISTS machine_identities (
    machine_id TEXT PRIMARY KEY,
    ed25519_public_key TEXT NOT NULL,
    kem_public_key TEXT,
    registered_at INTEGER NOT NULL
  );
`);

// Migrations — safe to run on existing DBs
const migrations = [
  "ALTER TABLE secrets ADD COLUMN secret_type TEXT DEFAULT 'custom'",
  "ALTER TABLE secrets ADD COLUMN url TEXT",
  "ALTER TABLE secrets ADD COLUMN username TEXT",
  "ALTER TABLE auth_config ADD COLUMN totp_secret TEXT",
  "ALTER TABLE auth_config ADD COLUMN totp_enabled INTEGER DEFAULT 0",
  // Fix 1: Session TTL per level
  "ALTER TABLE auth_config ADD COLUMN session_ttl TEXT DEFAULT '24h'",
  // Fix 3: Per-level lockout
  "ALTER TABLE auth_config ADD COLUMN failed_attempts INTEGER DEFAULT 0",
  "ALTER TABLE auth_config ADD COLUMN locked_until INTEGER DEFAULT 0",
  // Fix 4: Drop dead columns (SQLite 3.35+)
  "ALTER TABLE secrets DROP COLUMN iv",
  "ALTER TABLE secrets DROP COLUMN salt",
  // Folders
  "ALTER TABLE secrets ADD COLUMN folder TEXT DEFAULT NULL",
  // Blind/cached classification on machine secrets
  "ALTER TABLE machine_secrets ADD COLUMN classification TEXT NOT NULL DEFAULT 'cached'",
];
for (const m of migrations) {
  try { db.exec(m); } catch { /* column already exists or not supported */ }
}

// ---------- Server Ed25519 signing key (derived from LVLS_DB_KEY) ─────────────
// Used to sign offline tokens so clients can verify they came from this server.
const _serverEd25519Seed = new Uint8Array(crypto.hkdfSync(
  "sha256",
  Buffer.from(process.env.LVLS_DB_KEY!),
  Buffer.from("lvls-server-ed25519-v1"),
  Buffer.from("lvls-signing-key"),
  32
));
const SERVER_ED25519_PRIV: Uint8Array = _serverEd25519Seed;
const SERVER_ED25519_PUB: Uint8Array = ed25519.getPublicKey(SERVER_ED25519_PRIV);

// Verify an Ed25519 machine auth payload: signature over "lvls:{vaultId}:{machineId}:{timestamp}"
function verifyMachineSignature(vaultId: string, machineId: string, timestamp: number, signatureB64: string, publicKeyB64: string): boolean {
  try {
    const now = Date.now();
    if (Math.abs(now - timestamp) > 60_000) return false; // ±60s window
    const message = Buffer.from(`lvls:${vaultId}:${machineId}:${timestamp}`);
    const sig = Buffer.from(signatureB64, "base64");
    const pub = Buffer.from(publicKeyB64, "base64");
    return ed25519.verify(sig, message, pub);
  } catch { return false; }
}

// ---------- DB-backed rate limit functions (Fix 2) ----------
function authRateLimit(req: express.Request, res: express.Response, next: express.NextFunction) {
  const ip = req.ip || "unknown";
  const now = Date.now();
  const entry = db.prepare("SELECT count, reset_at FROM rate_limits WHERE ip = ?").get(ip) as any;
  if (!entry || now > entry.reset_at) {
    db.prepare("INSERT INTO rate_limits (ip, count, reset_at) VALUES (?, 0, ?) ON CONFLICT(ip) DO UPDATE SET count = 0, reset_at = excluded.reset_at")
      .run(ip, now + RATE_LIMIT_WINDOW_MS);
  } else if (entry.count >= RATE_LIMIT_MAX) {
    const mins = Math.ceil((entry.reset_at - now) / 60000);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${mins} min.` });
  }
  (req as any).rateLimitIp = ip;
  next();
}

function rateLimitOnFailure(ip: string) {
  db.prepare("UPDATE rate_limits SET count = count + 1 WHERE ip = ?").run(ip);
}

function rateLimitClear(ip: string) {
  db.prepare("DELETE FROM rate_limits WHERE ip = ?").run(ip);
}

// ---------- Lease audit helper ----------
function auditLease(
  event: string, leaseId: string | null, machineId: string,
  vaultId: string, sourceIp: string,
  keysAccessed?: string[], metadata?: Record<string, unknown>
) {
  try {
    db.prepare(
      "INSERT INTO lease_audit (id, lease_id, event, machine_id, vault_id, keys_accessed, source_ip, occurred_at, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(
      crypto.randomUUID(), leaseId, event, machineId, vaultId,
      keysAccessed ? JSON.stringify(keysAccessed) : null,
      sourceIp, Date.now(),
      metadata ? JSON.stringify(metadata) : null
    );
  } catch (e) {
    console.error("[LEASE_AUDIT] Failed to write audit event:", e);
  }
}

// ── H6 + M1 + M3: Periodic cleanup of expired rate limits, revoked tokens, used TOTPs ──
setInterval(() => {
  const now = Date.now();
  db.prepare("DELETE FROM rate_limits WHERE reset_at < ?").run(now);
  db.prepare("DELETE FROM revoked_tokens WHERE revoked_at < ?").run(now - 7 * 24 * 60 * 60 * 1000);
  db.prepare("DELETE FROM used_totps WHERE expires_at < ?").run(now);
}, 60 * 60 * 1000); // every hour

// ---------- Lease expiry background task (every 60s) ----------
setInterval(() => {
  const now = Date.now();
  // active → grace
  (db.prepare("SELECT id FROM leases WHERE status = 'active' AND expires_at < ?").all(now) as any[])
    .forEach((l: any) => db.prepare("UPDATE leases SET status = 'grace' WHERE id = ?").run(l.id));
  // grace → expired
  const expired = db.prepare("SELECT id, vault_id, machine_id FROM leases WHERE status = 'grace' AND grace_until < ?").all(now) as any[];
  for (const l of expired) {
    db.prepare("UPDATE leases SET status = 'expired' WHERE id = ?").run(l.id);
    auditLease("expired", l.id, l.machine_id, l.vault_id, "system");
  }
  if (expired.length > 0) console.log(`[LEASES] Expired ${expired.length} lease(s)`);
}, 60_000);

// ---------- TTL helper (Fix 1) ----------
function parseTTL(ttl: string): string {
  const map: Record<string, string> = {
    "15m": "15m", "30m": "30m", "1h": "1h", "2h": "2h",
    "4h": "4h", "8h": "8h", "24h": "24h", "Never": "168h", "Never cached": "1h",
  };
  return map[ttl] ?? "24h";
}

// ── M6: Strict level param validation ────────────────────────────────────────
function validLevelParam(param: string): number | null {
  if (!/^[0-3]$/.test(param)) return null;
  return parseInt(param, 10);
}

// ---------- TOTP (RFC 6238) — pure Node.js crypto, no deps ----------
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buf: Buffer): string {
  let bits = 0, val = 0, out = "";
  for (let i = 0; i < buf.length; i++) {
    val = (val << 8) | buf[i];
    bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}

function base32Decode(str: string): Buffer {
  const s = str.toUpperCase().replace(/=+$/, "");
  let bits = 0, val = 0;
  const out: number[] = [];
  for (const ch of s) {
    const idx = B32.indexOf(ch);
    if (idx === -1) throw new Error("Invalid base32");
    val = (val << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

function hotp(key: Buffer, counter: number): string {
  const cb = Buffer.alloc(8);
  cb.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  cb.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac("sha1", key).update(cb).digest();
  const offset = hmac[19] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return (code % 1_000_000).toString().padStart(6, "0");
}

function generateTotpSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

function verifyTotp(secret: string, token: string): boolean {
  try {
    const key = base32Decode(secret);
    const t = Math.floor(Date.now() / 1000 / 30);
    const clean = token.replace(/\s/g, "");
    const cleanBuf = Buffer.from(clean.padEnd(6, "0").slice(0, 6));
    for (let i = -1; i <= 1; i++) {
      const expected = Buffer.from(hotp(key, t + i));
      if (expected.length === cleanBuf.length && crypto.timingSafeEqual(expected, cleanBuf)) return true;
    }
    return false;
  } catch { return false; }
}

// ---------- Auth Middleware ----------
function requireAuth(minLevel: number) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const token = req.headers.authorization?.replace("Bearer ", "");
    if (!token) return res.status(401).json({ error: "No token" });
    try {
      const payload = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] }) as { level: number; sessionId: string };
      if (payload.level > minLevel) return res.status(403).json({ error: "Insufficient clearance" });
      // M1: Check token revocation
      if (payload.sessionId) {
        const revoked = db.prepare("SELECT 1 FROM revoked_tokens WHERE session_id = ?").get(payload.sessionId);
        if (revoked) return res.status(401).json({ error: "Token has been revoked" });
      }
      (req as any).authLevel = payload.level;
      (req as any).sessionId = payload.sessionId;
      next();
    } catch {
      res.status(401).json({ error: "Invalid token" });
    }
  };
}

// ---------- Health ----------
app.get("/api/health", (_req, res) => res.json({ status: "ok" }));

// ---------- Is vault configured? (public — used for onboarding gate) ----------
app.get("/api/auth/is-setup", (_req, res) => {
  const row = db.prepare("SELECT COUNT(*) as c FROM auth_config").get() as any;
  res.json({ configured: row.c > 0 });
});

// ---------- Bootstrap: first-time lvl3 PIN setup — locked out once any level exists ----------
app.post("/api/auth/bootstrap", authRateLimit, async (req, res) => {
  const existing = db.prepare("SELECT COUNT(*) as c FROM auth_config").get() as any;
  if (existing.c > 0) {
    return res.status(403).json({ error: "Vault already configured. Use /api/auth/setup." });
  }
  const { credential } = req.body;
  if (!credential) return res.status(400).json({ error: "credential required" });
  if (!/^\d+$/.test(credential)) return res.status(400).json({ error: "lvl3 must be a numeric PIN" });
  if (credential.length < 6) return res.status(400).json({ error: "PIN must be at least 6 digits" });

  try {
    const hash = await argon2.hash(credential, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
    db.prepare("INSERT INTO auth_config (level, credential_hash, method, session_ttl) VALUES (3, ?, 'pin', '24h')").run(hash);
    const sessionId = crypto.randomUUID();
    const token = jwt.sign({ level: 3, sessionId }, JWT_SECRET, { expiresIn: "24h" });
    db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
      .run(sessionId, 3, "bootstrap", JSON.stringify({ msg: "Vault initialised" }));
    res.json({ success: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Bootstrap failed" });
  }
});

// ---------- Auth: Check setup status ----------
app.get("/api/auth/status", requireAuth(3), (_req, res) => {
  const rows = db.prepare("SELECT level, method, kem_public_key, totp_enabled, session_ttl FROM auth_config").all() as any[];
  const configured: Record<number, { method: string; hasKemKey: boolean; totpEnabled: boolean; sessionTtl: string }> = {};
  for (const row of rows) {
    configured[row.level] = {
      method: row.method,
      hasKemKey: !!row.kem_public_key,
      totpEnabled: !!row.totp_enabled,
      sessionTtl: row.session_ttl || "24h",
    };
  }
  res.json({ configured, isSetup: rows.length === 4 });
});

// ---------- Auth: Setup a level's credential ----------
app.post("/api/auth/setup", requireAuth(3), async (req, res) => {
  const { level, credential, method, kemPublicKey } = req.body;
  if (level === undefined || !credential || !method) {
    return res.status(400).json({ error: "level, credential, and method are required" });
  }
  if (level < 0 || level > 3) return res.status(400).json({ error: "Invalid level" });
  // You must be authenticated at the target level or a more secure level (lower number = more secure)
  if ((req as any).authLevel < level) {
    return res.status(403).json({ error: "You must unlock this level before changing its credential" });
  }

  if (level === 3) {
    if (!/^\d+$/.test(credential)) return res.status(400).json({ error: "Lvl 3 must be numeric PIN" });
    if (credential.length < 6) return res.status(400).json({ error: "PIN must be at least 6 digits" });
  } else {
    if (credential.length < 6) return res.status(400).json({ error: "Must be at least 6 characters" });
    if (!/[a-zA-Z]/.test(credential) || !/[0-9]/.test(credential)) {
      return res.status(400).json({ error: "Must be alphanumeric (mix of letters and numbers)" });
    }
  }

  try {
    const hash = await argon2.hash(credential, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 1,
    });

    db.prepare(`
      INSERT INTO auth_config (level, credential_hash, kem_public_key, method, updated_at)
      VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(level) DO UPDATE SET
        credential_hash = excluded.credential_hash,
        kem_public_key = excluded.kem_public_key,
        method = excluded.method,
        updated_at = CURRENT_TIMESTAMP
    `).run(level, hash, kemPublicKey || null, method);

    db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
      .run((req as any).sessionId || "anon", level, "setup_credential", JSON.stringify({ level, method }));

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to set up credential" });
  }
});

// ---------- Auth: Unlock a level ----------
app.post("/api/auth/unlock", authRateLimit, async (req, res) => {
  const { level, credential, totp } = req.body;
  if (typeof level !== "number" || !Number.isInteger(level) || level < 0 || level > 3) {
    return res.status(400).json({ error: "level must be an integer 0-3" });
  }
  if (typeof credential !== "string" || !credential) {
    return res.status(400).json({ error: "credential must be a non-empty string" });
  }
  if (totp !== undefined && typeof totp !== "string") {
    return res.status(400).json({ error: "totp must be a string" });
  }

  try {
    const row = db.prepare("SELECT credential_hash, totp_secret, totp_enabled, session_ttl, failed_attempts, locked_until FROM auth_config WHERE level = ?").get(level) as any;

    if (!row) {
      return res.status(400).json({ error: "Vault not set up. Complete onboarding first." });
    }

    // Fix 3: Per-level lockout check
    if (row.locked_until && Date.now() < row.locked_until) {
      const mins = Math.ceil((row.locked_until - Date.now()) / 60000);
      return res.status(429).json({ error: `lvl${level} is locked. Try again in ${mins} min.` });
    }

    const valid = await argon2.verify(row.credential_hash, credential);
    if (!valid) {
      rateLimitOnFailure((req as any).rateLimitIp);
      const newAttempts = (row.failed_attempts || 0) + 1;
      const lockedUntil = newAttempts >= 5 ? Date.now() + 15 * 60 * 1000 : 0;
      db.prepare("UPDATE auth_config SET failed_attempts = ?, locked_until = ? WHERE level = ?")
        .run(newAttempts, lockedUntil, level);
      db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
        .run((req as any).rateLimitIp || "unknown", level, "auth_failed", JSON.stringify({ level, attempt: newAttempts }));
      if (lockedUntil) return res.status(429).json({ error: `Too many failed attempts. lvl${level} locked for 15 min.` });
      return res.status(401).json({ error: "Invalid credential" });
    }

    // TOTP check — required if enabled
    if (row.totp_enabled && row.totp_secret) {
      if (!totp) {
        return res.status(401).json({ error: "TOTP code required", totpRequired: true });
      }
      if (!verifyTotp(decryptTotp(row.totp_secret), totp)) {
        rateLimitOnFailure((req as any).rateLimitIp);
        db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
          .run((req as any).rateLimitIp || "unknown", level, "auth_failed_totp", JSON.stringify({ level }));
        return res.status(401).json({ error: "Invalid TOTP code" });
      }
      // M3: Replay prevention — reject already-used TOTP codes within their validity window
      const now = Date.now();
      const alreadyUsed = db.prepare("SELECT 1 FROM used_totps WHERE code = ? AND level = ? AND expires_at > ?").get(totp, level, now);
      if (alreadyUsed) {
        rateLimitOnFailure((req as any).rateLimitIp);
        return res.status(401).json({ error: "TOTP code already used" });
      }
      db.prepare("INSERT OR IGNORE INTO used_totps (code, level, expires_at) VALUES (?, ?, ?)").run(totp, level, now + 90_000);
    }

    // Fix 1 & 3: Use per-level TTL, reset lockout on success
    rateLimitClear((req as any).rateLimitIp);
    db.prepare("UPDATE auth_config SET failed_attempts = 0, locked_until = 0 WHERE level = ?").run(level);
    const ttl = parseTTL(row.session_ttl || "24h");
    const newSessionId = crypto.randomUUID();
    const token = jwt.sign({ level, sessionId: newSessionId }, JWT_SECRET, { expiresIn: ttl as any });
    db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
      .run(newSessionId, level, "auth_success", JSON.stringify({ level }));

    res.json({ success: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Auth failed" });
  }
});

// ---------- Auth: Get KEM public key ----------
app.get("/api/auth/kem-key/:level", requireAuth(3), (req, res) => {
  const level = validLevelParam(req.params.level);
  if (level === null) return res.status(400).json({ error: "Invalid level" });
  const row = db.prepare("SELECT kem_public_key FROM auth_config WHERE level = ?").get(level) as any;
  if (!row?.kem_public_key) return res.status(404).json({ error: "No KEM key for this level" });
  res.json({ publicKey: row.kem_public_key });
});

// ---------- Auth: Upload/update KEM public key (called after keypair generation on client) ----------
app.put("/api/auth/kem-key/:level", requireAuth(3), (req, res) => {
  const level = validLevelParam(req.params.level);
  if (level === null) return res.status(400).json({ error: "Invalid level" });
  if ((req as any).authLevel > level) return res.status(403).json({ error: "Insufficient clearance" });
  const { publicKey } = req.body;
  if (!publicKey) return res.status(400).json({ error: "publicKey required" });
  try {
    db.prepare("UPDATE auth_config SET kem_public_key = ?, updated_at = CURRENT_TIMESTAMP WHERE level = ?")
      .run(publicKey, level);
    db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
      .run((req as any).sessionId || "anon", level, "kem_key_updated", JSON.stringify({ level }));
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update KEM key" });
  }
});

// ---------- TOTP: Generate setup secret ----------
app.post("/api/auth/totp/setup/:level", authRateLimit, requireAuth(3), (req, res) => {
  const level = validLevelParam(req.params.level);
  if (level === null) return res.status(400).json({ error: "Invalid level" });
  if ((req as any).authLevel > level) return res.status(403).json({ error: "Insufficient clearance" });

  const secret = generateTotpSecret();
  // Store as pending (not yet enabled — needs confirmation)
  db.prepare("UPDATE auth_config SET totp_secret = ?, totp_enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE level = ?")
    .run(encryptTotp(secret), level);

  const issuer = "lvls Key Vault";
  const label = `lvls lvl${level}`;
  const uri = `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

  res.json({ secret, uri });
});

// ---------- TOTP: Confirm and enable ----------
app.post("/api/auth/totp/confirm/:level", authRateLimit, requireAuth(3), (req, res) => {
  const level = validLevelParam(req.params.level);
  if (level === null) return res.status(400).json({ error: "Invalid level" });
  if ((req as any).authLevel > level) return res.status(403).json({ error: "Insufficient clearance" });
  const { totp } = req.body;
  if (!totp) return res.status(400).json({ error: "totp code required" });

  const row = db.prepare("SELECT totp_secret FROM auth_config WHERE level = ?").get(level) as any;
  if (!row?.totp_secret) return res.status(400).json({ error: "Run setup first" });

  if (!verifyTotp(decryptTotp(row.totp_secret), totp)) {
    return res.status(401).json({ error: "Invalid TOTP code — make sure your authenticator clock is synced" });
  }

  db.prepare("UPDATE auth_config SET totp_enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE level = ?").run(level);
  db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
    .run((req as any).sessionId || "anon", level, "totp_enabled", JSON.stringify({ level }));

  res.json({ success: true });
});

// ---------- TOTP: Disable ----------
app.post("/api/auth/totp/disable/:level", requireAuth(3), (req, res) => {
  const level = validLevelParam(req.params.level);
  if (level === null) return res.status(400).json({ error: "Invalid level" });
  if ((req as any).authLevel > level) return res.status(403).json({ error: "Insufficient clearance" });

  db.prepare("UPDATE auth_config SET totp_secret = NULL, totp_enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE level = ?").run(level);
  db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
    .run((req as any).sessionId || "anon", level, "totp_disabled", JSON.stringify({ level }));

  res.json({ success: true });
});

// ---------- Auth: Update Session TTL (Fix 1) ----------
app.put("/api/auth/session-ttl/:level", requireAuth(3), (req, res) => {
  const level = validLevelParam(req.params.level);
  if (level === null) return res.status(400).json({ error: "Invalid level" });
  if ((req as any).authLevel > level) return res.status(403).json({ error: "Insufficient clearance" });
  const { ttl } = req.body;
  const valid = ["15m", "30m", "1h", "2h", "4h", "8h", "24h", "Never", "Never cached"];
  if (!valid.includes(ttl)) return res.status(400).json({ error: "Invalid TTL value" });
  try {
    db.prepare("UPDATE auth_config SET session_ttl = ?, updated_at = CURRENT_TIMESTAMP WHERE level = ?").run(ttl, level);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to update TTL" });
  }
});

// ── M1: Logout — revoke current token ────────────────────────────────────────
app.post("/api/auth/logout", requireAuth(3), (req, res) => {
  const sessionId = (req as any).sessionId;
  if (sessionId) {
    db.prepare("INSERT OR IGNORE INTO revoked_tokens (session_id, revoked_at) VALUES (?, ?)").run(sessionId, Date.now());
  }
  res.json({ success: true });
});

// ---------- Secrets: Create ----------
app.post("/api/secrets", requireAuth(3), async (req, res) => {
  const { name, level, secret_type, encrypted_value, tags, expiry, url, username, folder } = req.body;
  const authLevel = (req as any).authLevel;
  // C4: Prevent privilege escalation — can only create secrets at your own level or less secure
  if (level === undefined || level < authLevel) return res.status(403).json({ error: "Cannot create secrets above your clearance level" });
  if (level < 0 || level > 3) return res.status(400).json({ error: "Invalid level" });
  if (!name || !encrypted_value) return res.status(400).json({ error: "name and encrypted_value are required" });
  // C5: Server generates the ID — client cannot control the primary key
  const id = crypto.randomUUID();
  try {
    db.prepare(
      "INSERT INTO secrets (id, name, level, secret_type, encrypted_value, tags, expiry, url, username, folder) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(id, name, level, secret_type || "custom", encrypted_value, JSON.stringify(tags), expiry, url || null, username || null, folder || null);

    db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
      .run((req as any).sessionId || "anon", level, "create_secret", JSON.stringify({ id }));

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to save secret" });
  }
});

// ---------- Secrets: Update ----------
app.put("/api/secrets/:id", requireAuth(3), async (req, res) => {
  const { id } = req.params;
  const { name, secret_type, tags, url, username, folder } = req.body;
  try {
    const secret = db.prepare("SELECT level FROM secrets WHERE id = ?").get(id) as any;
    if (!secret) return res.status(404).json({ error: "Secret not found" });
    if ((req as any).authLevel > secret.level) return res.status(403).json({ error: "Insufficient clearance" });

    db.prepare(
      "UPDATE secrets SET name = ?, secret_type = ?, tags = ?, url = ?, username = ?, folder = ? WHERE id = ?"
    ).run(name, secret_type, JSON.stringify(tags), url || null, username || null, folder || null, id);

    db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
      .run((req as any).sessionId || "anon", secret.level, "update_secret", JSON.stringify({ name, id }));

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update secret" });
  }
});

// ---------- Secrets: List ----------
app.get("/api/secrets", requireAuth(3), (req, res) => {
  try {
    const authLevel = (req as any).authLevel;
    const secrets = db.prepare(
      "SELECT id, name, level, secret_type, encrypted_value, tags, expiry, url, username, folder, created_at FROM secrets WHERE level >= ? ORDER BY folder ASC, created_at DESC"
    ).all(authLevel).map((s: any) => ({ ...s, tags: s.tags ? JSON.parse(s.tags) : [] }));
    res.json(secrets);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch secrets" });
  }
});

// ---------- Secrets: By domain (for extension) ----------
app.get("/api/secrets/by-domain", requireAuth(3), (req, res) => {
  try {
    const hostname = req.query.hostname as string;
    if (!hostname) return res.status(400).json({ error: "hostname required" });
    if (hostname.length > 253 || !/^[a-zA-Z0-9.\-]+$/.test(hostname)) {
      return res.status(400).json({ error: "Invalid hostname" });
    }
    const authLevel = (req as any).authLevel;
    // Match secrets where url contains the hostname
    const secrets = db.prepare(
      "SELECT id, name, level, secret_type, encrypted_value, tags, url, username, folder, created_at FROM secrets WHERE level >= ? AND (url LIKE ? OR name LIKE ?) ORDER BY created_at DESC"
    ).all(authLevel, `%${hostname}%`, `%${hostname}%`)
      .map((s: any) => ({ ...s, tags: s.tags ? JSON.parse(s.tags) : [] }));
    res.json(secrets);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch secrets" });
  }
});

// ---------- Secrets: Get by ID ----------
app.get("/api/secrets/:id", requireAuth(3), (req, res) => {
  try {
    const secret = db.prepare("SELECT * FROM secrets WHERE id = ?").get(req.params.id) as any;
    if (!secret) return res.status(404).json({ error: "Secret not found" });
    if ((req as any).authLevel > secret.level) return res.status(403).json({ error: "Insufficient clearance" });
    secret.tags = secret.tags ? JSON.parse(secret.tags) : [];
    res.json(secret);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch secret" });
  }
});

// ---------- Secrets: Delete ----------
app.delete("/api/secrets/:id", requireAuth(3), (req, res) => {
  try {
    const secret = db.prepare("SELECT level FROM secrets WHERE id = ?").get(req.params.id) as any;
    if (!secret) return res.status(404).json({ error: "Secret not found" });
    if ((req as any).authLevel > secret.level) return res.status(403).json({ error: "Insufficient clearance" });
    db.prepare("DELETE FROM secrets WHERE id = ?").run(req.params.id);
    db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
      .run((req as any).sessionId || "anon", (req as any).authLevel, "delete_secret", JSON.stringify({ id: req.params.id }));
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete secret" });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// MACHINE VAULTS — isolated, ML-KEM encrypted, TOTP-gated credential stores
// ══════════════════════════════════════════════════════════════════════════════

// Create a machine vault
app.post("/api/machine/vaults", requireAuth(3), (req, res) => {
  const { name, description, ttl } = req.body;
  if (!name || typeof name !== "string" || !/^[a-z0-9_-]+$/i.test(name)) {
    return res.status(400).json({ error: "name required (alphanumeric, hyphens, underscores)" });
  }
  const ttlVal = typeof ttl === "number" && ttl > 0 ? ttl : 14400;
  const id = crypto.randomUUID();
  try {
    db.prepare("INSERT INTO machine_vaults (id, name, description, ttl) VALUES (?, ?, ?, ?)")
      .run(id, name, description || null, ttlVal);
    res.json({ id, name, description: description || null, ttl: ttlVal });
  } catch (err: any) {
    if (err.message?.includes("UNIQUE")) return res.status(409).json({ error: "Vault name already exists" });
    res.status(500).json({ error: "Failed to create vault" });
  }
});

// List machine vaults
app.get("/api/machine/vaults", requireAuth(3), (_req, res) => {
  const vaults = db.prepare(
    "SELECT id, name, description, ttl, totp_enabled, CASE WHEN kem_public_key IS NOT NULL THEN 1 ELSE 0 END as has_kem_key, created_at FROM machine_vaults ORDER BY created_at DESC"
  ).all();
  res.json(vaults);
});

// Get single vault
app.get("/api/machine/vaults/:id", requireAuth(3), (req, res) => {
  const vault = db.prepare(
    "SELECT id, name, description, ttl, totp_enabled, CASE WHEN kem_public_key IS NOT NULL THEN 1 ELSE 0 END as has_kem_key, created_at FROM machine_vaults WHERE id = ?"
  ).get(req.params.id) as any;
  if (!vault) return res.status(404).json({ error: "Vault not found" });
  const count = (db.prepare("SELECT COUNT(*) as c FROM machine_secrets WHERE vault_id = ?").get(req.params.id) as any).c;
  res.json({ ...vault, secret_count: count });
});

// Delete machine vault
app.delete("/api/machine/vaults/:id", requireAuth(3), (req, res) => {
  const vault = db.prepare("SELECT id FROM machine_vaults WHERE id = ?").get(req.params.id);
  if (!vault) return res.status(404).json({ error: "Vault not found" });
  db.prepare("DELETE FROM machine_vaults WHERE id = ?").run(req.params.id);
  res.json({ success: true });
});

// Register ML-KEM public key for a vault
app.put("/api/machine/vaults/:id/kem-key", requireAuth(3), (req, res) => {
  const { kem_public_key } = req.body;
  if (!kem_public_key || typeof kem_public_key !== "string") {
    return res.status(400).json({ error: "kem_public_key required" });
  }
  const vault = db.prepare("SELECT id FROM machine_vaults WHERE id = ?").get(req.params.id);
  if (!vault) return res.status(404).json({ error: "Vault not found" });
  db.prepare("UPDATE machine_vaults SET kem_public_key = ? WHERE id = ?").run(kem_public_key, req.params.id);
  res.json({ success: true });
});

// Get ML-KEM public key for a vault (used when adding secrets from another client)
app.get("/api/machine/vaults/:id/kem-key", requireAuth(3), (req, res) => {
  const vault = db.prepare("SELECT kem_public_key FROM machine_vaults WHERE id = ?").get(req.params.id) as any;
  if (!vault) return res.status(404).json({ error: "Vault not found" });
  if (!vault.kem_public_key) return res.status(404).json({ error: "No KEM key registered for this vault" });
  res.json({ kem_public_key: vault.kem_public_key });
});

// TOTP setup for a machine vault
app.post("/api/machine/vaults/:id/totp/setup", requireAuth(3), (req, res) => {
  const vault = db.prepare("SELECT id, name FROM machine_vaults WHERE id = ?").get(req.params.id) as any;
  if (!vault) return res.status(404).json({ error: "Vault not found" });
  const secret = generateTotpSecret();
  const encrypted = encryptTotp(secret);
  db.prepare("UPDATE machine_vaults SET totp_secret = ?, totp_enabled = 0 WHERE id = ?").run(encrypted, req.params.id);
  const uri = `otpauth://totp/lvls:machine-${vault.name}?secret=${secret}&issuer=lvls-vault&algorithm=SHA1&digits=6&period=30`;
  res.json({ uri, secret });
});

// Confirm TOTP for a machine vault
app.post("/api/machine/vaults/:id/totp/confirm", requireAuth(3), (req, res) => {
  const { totp } = req.body;
  if (!totp) return res.status(400).json({ error: "totp required" });
  const vault = db.prepare("SELECT totp_secret FROM machine_vaults WHERE id = ?").get(req.params.id) as any;
  if (!vault) return res.status(404).json({ error: "Vault not found" });
  if (!vault.totp_secret) return res.status(400).json({ error: "Run TOTP setup first" });
  if (!verifyTotp(decryptTotp(vault.totp_secret), totp)) {
    return res.status(401).json({ error: "Invalid TOTP code" });
  }
  db.prepare("UPDATE machine_vaults SET totp_enabled = 1 WHERE id = ?").run(req.params.id);
  res.json({ success: true });
});

// Add a secret to a machine vault.
// Cached: UI sends plaintext over TLS — server encrypts with AES-256-GCM (vault-specific key).
// Blind:  UI sends ML-KEM encrypted blob — server stores as-is, never decrypts.
app.post("/api/machine/vaults/:id/secrets", requireAuth(3), (req, res) => {
  const { name, encrypted_value, classification } = req.body;
  if (!name || !encrypted_value) return res.status(400).json({ error: "name and encrypted_value required" });
  if (typeof name !== "string" || name.length > 128) return res.status(400).json({ error: "Invalid secret name" });
  const cls = classification === "blind" ? "blind" : "cached";
  const vault = db.prepare("SELECT id FROM machine_vaults WHERE id = ?").get(req.params.id) as any;
  if (!vault) return res.status(404).json({ error: "Vault not found" });
  const id = crypto.randomUUID();
  try {
    const storedValue = cls === "cached"
      ? encryptCachedSecret(encrypted_value, vault.id)  // encrypt plaintext server-side
      : encrypted_value;                                 // blind: store ML-KEM blob as-is
    db.prepare("INSERT INTO machine_secrets (id, vault_id, name, encrypted_value, classification) VALUES (?, ?, ?, ?, ?)")
      .run(id, vault.id, name, storedValue, cls);
    res.json({ id, name, classification: cls });
  } catch (err: any) {
    if (err.message?.includes("UNIQUE")) return res.status(409).json({ error: `Secret '${name}' already exists in this vault` });
    res.status(500).json({ error: "Failed to store secret" });
  }
});

// List secrets in a vault (names only — no values)
app.get("/api/machine/vaults/:id/secrets", requireAuth(3), (req, res) => {
  const vault = db.prepare("SELECT id FROM machine_vaults WHERE id = ?").get(req.params.id);
  if (!vault) return res.status(404).json({ error: "Vault not found" });
  const secrets = db.prepare("SELECT id, name, classification, created_at FROM machine_secrets WHERE vault_id = ? ORDER BY name ASC").all(req.params.id);
  res.json(secrets);
});

// Delete a secret from a vault
app.delete("/api/machine/vaults/:id/secrets/:secretId", requireAuth(3), (req, res) => {
  const secret = db.prepare("SELECT id FROM machine_secrets WHERE id = ? AND vault_id = ?").get(req.params.secretId, req.params.id);
  if (!secret) return res.status(404).json({ error: "Secret not found" });
  db.prepare("DELETE FROM machine_secrets WHERE id = ?").run(req.params.secretId);
  res.json({ success: true });
});

// ── Machine identity registration (self-register Ed25519 + ML-KEM public keys) ─
app.post("/api/machine/identities", authRateLimit, (req, res) => {
  const { machine_id, ed25519_public_key, kem_public_key } = req.body;
  if (!machine_id || !ed25519_public_key) return res.status(400).json({ error: "machine_id and ed25519_public_key required" });
  if (typeof machine_id !== "string" || machine_id.length > 128) return res.status(400).json({ error: "Invalid machine_id" });
  try { Buffer.from(ed25519_public_key, "base64"); } catch { return res.status(400).json({ error: "Invalid ed25519_public_key encoding" }); }

  const existing = db.prepare("SELECT ed25519_public_key FROM machine_identities WHERE machine_id = ?").get(machine_id) as any;
  if (existing) {
    // Only allow re-registration if the key matches (identity is immutable once set)
    if (existing.ed25519_public_key !== ed25519_public_key) {
      return res.status(409).json({ error: "Machine identity already registered with a different key. Contact admin to reset." });
    }
    // Update KEM key if provided
    if (kem_public_key) db.prepare("UPDATE machine_identities SET kem_public_key = ? WHERE machine_id = ?").run(kem_public_key, machine_id);
    return res.json({ machine_id, registered: false, updated: !!kem_public_key });
  }

  db.prepare("INSERT INTO machine_identities (machine_id, ed25519_public_key, kem_public_key, registered_at) VALUES (?, ?, ?, ?)")
    .run(machine_id, ed25519_public_key, kem_public_key || null, Date.now());
  res.json({ machine_id, registered: true, server_ed25519_public_key: Buffer.from(SERVER_ED25519_PUB).toString("base64") });
});

// Return server's Ed25519 public key (clients need this to verify offline token signatures)
app.get("/api/machine/server-key", (_req, res) => {
  res.json({ ed25519_public_key: Buffer.from(SERVER_ED25519_PUB).toString("base64") });
});

// ── Credential Request — Ed25519 or TOTP-gated, lease-issuing, no session auth ─
app.post("/api/machine/vaults/:id/request", authRateLimit, (req, res) => {
  const vault = db.prepare("SELECT id, name, totp_secret, totp_enabled, ttl, kem_public_key FROM machine_vaults WHERE id = ?").get(req.params.id) as any;
  if (!vault) return res.status(404).json({ error: "Vault not found" });
  if (!vault.kem_public_key) return res.status(400).json({ error: "Vault has no KEM key — not ready for use" });

  const { totp, machine_id: rawMachineId, signature, timestamp, ed25519_public_key } = req.body;
  const sourceIp = (req as any).rateLimitIp || "unknown";
  const machineId = (typeof rawMachineId === "string" && rawMachineId.length > 0 && rawMachineId.length <= 128)
    ? rawMachineId : sourceIp;

  // Check vault grants — if any grant exists for this vault, machine_id must be explicitly granted
  const anyGrant = db.prepare("SELECT 1 FROM vault_grants WHERE vault_id = ? AND active = 1").get(vault.id);
  let effectiveTtl = vault.ttl;
  let scopedKeys: string[] | null = null;
  if (anyGrant) {
    const grant = db.prepare("SELECT max_ttl_seconds, scoped_keys FROM vault_grants WHERE vault_id = ? AND machine_id = ? AND active = 1").get(vault.id, machineId) as any;
    if (!grant) {
      auditLease("access_denied", null, machineId, vault.id, sourceIp, undefined, { reason: "no_grant" });
      return res.status(403).json({ error: "Machine not authorized for this vault" });
    }
    effectiveTtl = Math.min(vault.ttl, grant.max_ttl_seconds);
    scopedKeys = grant.scoped_keys ? JSON.parse(grant.scoped_keys) : null;
  }

  // Auth: Ed25519 takes priority over TOTP
  if (signature && timestamp) {
    // Look up machine identity
    let identity = db.prepare("SELECT ed25519_public_key FROM machine_identities WHERE machine_id = ?").get(machineId) as any;
    if (!identity) {
      // Auto-register if public key provided with request
      if (!ed25519_public_key) {
        auditLease("access_denied", null, machineId, vault.id, sourceIp, undefined, { reason: "identity_unknown" });
        return res.status(401).json({ error: "Machine identity not registered. POST /api/machine/identities first." });
      }
      try { Buffer.from(ed25519_public_key, "base64"); } catch {
        return res.status(400).json({ error: "Invalid ed25519_public_key" });
      }
      db.prepare("INSERT OR IGNORE INTO machine_identities (machine_id, ed25519_public_key, registered_at) VALUES (?, ?, ?)").run(machineId, ed25519_public_key, Date.now());
      identity = { ed25519_public_key };
    }
    if (!verifyMachineSignature(vault.id, machineId, Number(timestamp), signature, identity.ed25519_public_key)) {
      rateLimitOnFailure(sourceIp);
      auditLease("access_denied", null, machineId, vault.id, sourceIp, undefined, { reason: "sig_invalid" });
      return res.status(401).json({ error: "Invalid Ed25519 signature or stale timestamp" });
    }
    // Replay prevention: signature is over timestamp, block same timestamp+machineId combo
    const replayKey = `ed25519:${machineId}:${timestamp}`;
    const used = db.prepare("SELECT 1 FROM used_totps WHERE code = ? AND level = ?").get(replayKey, -2);
    if (used) return res.status(401).json({ error: "Timestamp already used — replay detected" });
    db.prepare("INSERT INTO used_totps (code, level, expires_at) VALUES (?, ?, ?)").run(replayKey, -2, Date.now() + 120_000);
  } else if (vault.totp_enabled && vault.totp_secret) {
    if (!totp) {
      auditLease("access_denied", null, machineId, vault.id, sourceIp, undefined, { reason: "totp_missing" });
      return res.status(401).json({ error: "TOTP required", totpRequired: true });
    }
    if (!verifyTotp(decryptTotp(vault.totp_secret), totp)) {
      rateLimitOnFailure(sourceIp);
      auditLease("access_denied", null, machineId, vault.id, sourceIp, undefined, { reason: "totp_invalid" });
      db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
        .run(sourceIp, -1, "machine_auth_failed", JSON.stringify({ vault: vault.name }));
      return res.status(401).json({ error: "Invalid TOTP code" });
    }
    const replayKey = `${vault.id}:${totp}`;
    const used = db.prepare("SELECT 1 FROM used_totps WHERE code = ? AND level = ?").get(replayKey, -1);
    if (used) return res.status(401).json({ error: "TOTP code already used" });
    db.prepare("INSERT INTO used_totps (code, level, expires_at) VALUES (?, ?, ?)").run(replayKey, -1, Date.now() + 90_000);
  }

  rateLimitClear(sourceIp);

  // Fetch secrets (scoped if grant has scoped_keys), include classification
  let secrets: any[];
  if (scopedKeys && scopedKeys.length > 0) {
    const ph = scopedKeys.map(() => "?").join(",");
    secrets = db.prepare(`SELECT id, name, encrypted_value, classification FROM machine_secrets WHERE vault_id = ? AND name IN (${ph})`).all(vault.id, ...scopedKeys) as any[];
  } else {
    secrets = db.prepare("SELECT id, name, encrypted_value, classification FROM machine_secrets WHERE vault_id = ?").all(vault.id) as any[];
  }

  const now = Date.now();
  const expiresAt = now + effectiveTtl * 1_000;
  const graceUntil = expiresAt + 30_000;
  const leaseId = crypto.randomUUID();

  db.prepare(
    "INSERT INTO leases (id, vault_id, machine_id, issued_at, expires_at, grace_until, status) VALUES (?, ?, ?, ?, ?, ?, 'active')"
  ).run(leaseId, vault.id, machineId, now, expiresAt, graceUntil);
  // Decrypt cached secrets server-side before serving; blind secrets served as-is (machine decrypts)
  const servedSecrets = secrets.map((s: any) => {
    if (s.classification === "cached") {
      try {
        return { ...s, encrypted_value: decryptCachedSecret(s.encrypted_value, vault.id) };
      } catch {
        console.warn(`[lvls] Cached secret has stale format — re-add via UI`);
        return { ...s, encrypted_value: null };
      }
    }
    return s; // blind — return ML-KEM blob as-is
  });

  auditLease("issued", leaseId, machineId, vault.id, sourceIp, secrets.map((s: any) => s.name));
  db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
    .run(sourceIp, -1, "machine_request", JSON.stringify({ vault: vault.name, secrets: secrets.length, lease_id: leaseId }));

  res.json({ secrets: servedSecrets, lease_id: leaseId, expires_at: new Date(expiresAt).toISOString(), vault_name: vault.name, ttl: effectiveTtl });
});

// ── Offline token — pre-signed ML-KEM token for offline operation ──────────────
app.post("/api/machine/vaults/:id/offline-token", authRateLimit, async (req, res) => {
  const vault = db.prepare("SELECT id, name, totp_secret, totp_enabled, ttl, kem_public_key FROM machine_vaults WHERE id = ?").get(req.params.id) as any;
  if (!vault) return res.status(404).json({ error: "Vault not found" });

  const { machine_id: rawMachineId, signature, timestamp, ttl_seconds } = req.body;
  const sourceIp = (req as any).rateLimitIp || "unknown";
  const machineId = (typeof rawMachineId === "string" && rawMachineId.length > 0 && rawMachineId.length <= 128)
    ? rawMachineId : sourceIp;

  // Ed25519 auth required for offline tokens (no TOTP fallback)
  if (!signature || !timestamp) {
    return res.status(401).json({ error: "Ed25519 signature required for offline token issuance" });
  }
  const identity = db.prepare("SELECT ed25519_public_key, kem_public_key FROM machine_identities WHERE machine_id = ?").get(machineId) as any;
  if (!identity) return res.status(401).json({ error: "Machine identity not registered" });
  if (!verifyMachineSignature(vault.id, machineId, Number(timestamp), signature, identity.ed25519_public_key)) {
    rateLimitOnFailure(sourceIp);
    return res.status(401).json({ error: "Invalid Ed25519 signature or stale timestamp" });
  }

  if (!identity.kem_public_key) return res.status(400).json({ error: "Machine has no ML-KEM public key registered. POST /api/machine/identities with kem_public_key first." });

  try {
    const token = await buildOfflineToken(vault.id, machineId, ttl_seconds || 86400, sourceIp);
    res.json(token);
  } catch (e: any) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

// ── Admin: Issue offline token for a machine (uses admin session, no Ed25519) ──
// Helper shared with machine-facing endpoint above:
async function buildOfflineToken(vaultId: string, machineId: string, ttlSeconds: number, sourceIp: string): Promise<object> {
  const vault = db.prepare("SELECT id, name, ttl FROM machine_vaults WHERE id = ?").get(vaultId) as any;
  if (!vault) throw Object.assign(new Error("Vault not found"), { status: 404 });

  const identity = db.prepare("SELECT kem_public_key FROM machine_identities WHERE machine_id = ?").get(machineId) as any;
  if (!identity?.kem_public_key) throw Object.assign(new Error("Machine has no ML-KEM public key registered"), { status: 400 });

  const grant = db.prepare("SELECT max_ttl_seconds, scoped_keys FROM vault_grants WHERE vault_id = ? AND machine_id = ? AND active = 1").get(vaultId, machineId) as any;
  const maxTtl = Math.min(vault.ttl, ttlSeconds || 86400, grant?.max_ttl_seconds ?? Infinity);
  const scopedKeys: string[] | null = grant?.scoped_keys ? JSON.parse(grant.scoped_keys) : null;

  let secrets: any[];
  if (scopedKeys && scopedKeys.length > 0) {
    const ph = scopedKeys.map(() => "?").join(",");
    secrets = db.prepare(`SELECT name, encrypted_value, classification FROM machine_secrets WHERE vault_id = ? AND name IN (${ph})`).all(vaultId, ...scopedKeys) as any[];
  } else {
    secrets = db.prepare("SELECT name, encrypted_value, classification FROM machine_secrets WHERE vault_id = ?").all(vaultId) as any[];
  }

  const now = Date.now();
  const expiresAt = now + maxTtl * 1_000;
  const payload = JSON.stringify({
    secrets: secrets.map((s: any) => ({ name: s.name, encrypted_value: s.encrypted_value, classification: s.classification })),
    vault_id: vaultId, vault_name: vault.name, machine_id: machineId, issued_at: now, expires_at: expiresAt,
  });

  const { ml_kem768 } = await import("@noble/post-quantum/ml-kem.js");
  const pubKey = Uint8Array.from(Buffer.from(identity.kem_public_key, "base64"));
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(pubKey, seed);
  const aesKey = Buffer.from(crypto.hkdfSync("sha256", Buffer.from(sharedSecret), Buffer.from("lvls-offline-token-v1"), Buffer.from(""), 32));
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  const encPayload = Buffer.concat([cipher.update(payload, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const aesPacked = Buffer.concat([iv, tag, encPayload]).toString("base64");
  const kemB64 = Buffer.from(cipherText).toString("base64");
  const sigInput = new TextEncoder().encode(`${kemB64}.${aesPacked}`);
  const serverSig = ed25519.sign(sigInput, SERVER_ED25519_PRIV);

  auditLease("offline_token_issued", null, machineId, vaultId, sourceIp, secrets.map((s: any) => s.name), { expires_at: expiresAt });

  return {
    kem_ciphertext: kemB64,
    aes_ciphertext: aesPacked,
    server_signature: Buffer.from(serverSig).toString("base64"),
    server_ed25519_public_key: Buffer.from(SERVER_ED25519_PUB).toString("base64"),
    machine_id: machineId,
    vault_id: vaultId,
    expires_at: new Date(expiresAt).toISOString(),
  };
}

app.post("/api/admin/machine/vaults/:id/offline-token", requireAuth(3), async (req, res) => {
  const { machine_id, ttl_seconds } = req.body;
  if (!machine_id) return res.status(400).json({ error: "machine_id required" });
  try {
    const token = await buildOfflineToken(req.params.id, machine_id, ttl_seconds || 86400, (req as any).sessionId || "admin");
    res.json(token);
  } catch (e: any) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

// ── Admin: List machine identities ─────────────────────────────────────────────
app.get("/api/admin/machine-identities", requireAuth(3), (_req, res) => {
  res.json(db.prepare("SELECT machine_id, registered_at, CASE WHEN kem_public_key IS NOT NULL THEN 1 ELSE 0 END as has_kem_key FROM machine_identities ORDER BY registered_at DESC").all());
});

app.delete("/api/admin/machine-identities/:machineId", requireAuth(3), (req, res) => {
  db.prepare("DELETE FROM machine_identities WHERE machine_id = ?").run(req.params.machineId);
  res.json({ deleted: true });
});

// ══════════════════════════════════════════════════════════════════════════════
// LEASE LIFECYCLE — revoke, refresh, status
// ══════════════════════════════════════════════════════════════════════════════

// Revoke a lease (machine-facing — authenticated by lease_id possession + machine_id)
app.delete("/api/machine/leases/:leaseId", authRateLimit, (req, res) => {
  const { machine_id } = req.body;
  if (!machine_id) return res.status(400).json({ error: "machine_id required" });
  const lease = db.prepare("SELECT id, vault_id, machine_id, status FROM leases WHERE id = ?").get(req.params.leaseId) as any;
  if (!lease) return res.status(404).json({ error: "Lease not found" });
  if (lease.machine_id !== machine_id) return res.status(403).json({ error: "Machine ID mismatch" });
  if (lease.status === "revoked") return res.json({ revoked: true, lease_id: lease.id });
  const now = Date.now();
  db.prepare("UPDATE leases SET status = 'revoked', revoked_at = ?, revoke_reason = 'explicit' WHERE id = ?").run(now, lease.id);
  auditLease("revoked", lease.id, machine_id, lease.vault_id, (req as any).rateLimitIp || "unknown");
  res.json({ revoked: true, lease_id: lease.id });
});

// Refresh a lease TTL — re-validates Ed25519 or TOTP, extends expiry
app.post("/api/machine/leases/:leaseId/refresh", authRateLimit, (req, res) => {
  const { machine_id, totp, signature, timestamp } = req.body;
  if (!machine_id) return res.status(400).json({ error: "machine_id required" });
  const lease = db.prepare("SELECT id, vault_id, machine_id, status FROM leases WHERE id = ?").get(req.params.leaseId) as any;
  if (!lease) return res.status(404).json({ error: "Lease not found" });
  if (lease.machine_id !== machine_id) return res.status(403).json({ error: "Machine ID mismatch" });
  if (lease.status === "revoked" || lease.status === "expired") return res.status(410).json({ error: "Lease is no longer active" });

  const vault = db.prepare("SELECT id, totp_secret, totp_enabled, ttl FROM machine_vaults WHERE id = ?").get(lease.vault_id) as any;
  if (!vault) return res.status(404).json({ error: "Vault not found" });

  if (signature && timestamp) {
    const identity = db.prepare("SELECT ed25519_public_key FROM machine_identities WHERE machine_id = ?").get(machine_id) as any;
    if (!identity || !verifyMachineSignature(vault.id, machine_id, Number(timestamp), signature, identity.ed25519_public_key)) {
      rateLimitOnFailure((req as any).rateLimitIp);
      return res.status(401).json({ error: "Invalid Ed25519 signature or stale timestamp" });
    }
    const replayKey = `ed25519:${machine_id}:${timestamp}`;
    const used = db.prepare("SELECT 1 FROM used_totps WHERE code = ? AND level = ?").get(replayKey, -2);
    if (used) return res.status(401).json({ error: "Timestamp already used" });
    db.prepare("INSERT INTO used_totps (code, level, expires_at) VALUES (?, ?, ?)").run(replayKey, -2, Date.now() + 120_000);
  } else if (vault.totp_enabled && vault.totp_secret) {
    if (!totp) return res.status(401).json({ error: "TOTP required for refresh", totpRequired: true });
    if (!verifyTotp(decryptTotp(vault.totp_secret), totp)) {
      rateLimitOnFailure((req as any).rateLimitIp);
      return res.status(401).json({ error: "Invalid TOTP code" });
    }
    const replayKey = `${vault.id}:${totp}`;
    const used = db.prepare("SELECT 1 FROM used_totps WHERE code = ? AND level = ?").get(replayKey, -1);
    if (used) return res.status(401).json({ error: "TOTP code already used" });
    db.prepare("INSERT INTO used_totps (code, level, expires_at) VALUES (?, ?, ?)").run(replayKey, -1, Date.now() + 90_000);
  }

  const grant = db.prepare("SELECT max_ttl_seconds FROM vault_grants WHERE vault_id = ? AND machine_id = ? AND active = 1").get(vault.id, machine_id) as any;
  const maxTtl = grant ? Math.min(vault.ttl, grant.max_ttl_seconds) : vault.ttl;
  const now = Date.now();
  const newExpiry = now + maxTtl * 1_000;
  db.prepare("UPDATE leases SET status = 'active', expires_at = ?, grace_until = ?, refresh_count = refresh_count + 1, last_refreshed = ? WHERE id = ?")
    .run(newExpiry, newExpiry + 30_000, now, lease.id);
  auditLease("refreshed", lease.id, machine_id, lease.vault_id, (req as any).rateLimitIp || "unknown", undefined, { new_expires_at: newExpiry });
  res.json({ lease_id: lease.id, expires_at: new Date(newExpiry).toISOString(), status: "active" });
});

// Lease status — heartbeat for client modules to detect admin revocation
app.get("/api/machine/leases/:leaseId/status", authRateLimit, (req, res) => {
  const machine_id = req.query.machine_id as string;
  if (!machine_id) return res.status(400).json({ error: "machine_id required" });
  const lease = db.prepare("SELECT id, vault_id, machine_id, status, expires_at, refresh_count FROM leases WHERE id = ?").get(req.params.leaseId) as any;
  if (!lease) return res.status(404).json({ error: "Lease not found" });
  if (lease.machine_id !== machine_id) return res.status(403).json({ error: "Machine ID mismatch" });
  res.json({ lease_id: lease.id, status: lease.status, expires_at: new Date(lease.expires_at).toISOString(), refresh_count: lease.refresh_count });
});

// ── Admin: Lease management ───────────────────────────────────────────────────

app.get("/api/admin/leases", requireAuth(3), (req, res) => {
  const { vault_id, machine_id, status } = req.query;
  let query = "SELECT id, vault_id, machine_id, issued_at, expires_at, status, refresh_count, revoke_reason FROM leases WHERE 1=1";
  const params: any[] = [];
  if (vault_id) { query += " AND vault_id = ?"; params.push(vault_id); }
  if (machine_id) { query += " AND machine_id = ?"; params.push(machine_id); }
  if (status) { query += " AND status = ?"; params.push(status); }
  query += " ORDER BY issued_at DESC LIMIT 200";
  res.json(db.prepare(query).all(...params));
});

app.post("/api/admin/leases/revoke-all", requireAuth(3), (req, res) => {
  const { machine_id, vault_id, reason } = req.body;
  if (!reason) return res.status(400).json({ error: "reason required" });
  let query = "SELECT id, vault_id, machine_id FROM leases WHERE status IN ('active', 'grace')";
  const params: any[] = [];
  if (machine_id) { query += " AND machine_id = ?"; params.push(machine_id); }
  if (vault_id) { query += " AND vault_id = ?"; params.push(vault_id); }
  const leases = db.prepare(query).all(...params) as any[];
  const now = Date.now();
  for (const l of leases) {
    db.prepare("UPDATE leases SET status = 'revoked', revoked_at = ?, revoke_reason = 'admin_revoke' WHERE id = ?").run(now, l.id);
    auditLease("admin_revoked", l.id, l.machine_id, l.vault_id, (req as any).sessionId || "admin", undefined, { reason });
  }
  res.json({ revoked_count: leases.length });
});

app.get("/api/admin/lease-audit", requireAuth(3), (req, res) => {
  const { machine_id, vault_id, event, from, to } = req.query;
  let query = "SELECT * FROM lease_audit WHERE 1=1";
  const params: any[] = [];
  if (machine_id) { query += " AND machine_id = ?"; params.push(machine_id); }
  if (vault_id) { query += " AND vault_id = ?"; params.push(vault_id); }
  if (event) { query += " AND event = ?"; params.push(event); }
  if (from) { query += " AND occurred_at >= ?"; params.push(Number(from)); }
  if (to) { query += " AND occurred_at <= ?"; params.push(Number(to)); }
  query += " ORDER BY occurred_at DESC LIMIT 500";
  res.json(db.prepare(query).all(...params));
});

// ── Admin: Vault grants ───────────────────────────────────────────────────────

app.get("/api/admin/grants", requireAuth(3), (_req, res) => {
  res.json(db.prepare(
    "SELECT g.id, g.vault_id, v.name as vault_name, g.machine_id, g.max_ttl_seconds, g.scoped_keys, g.active, g.created_at FROM vault_grants g LEFT JOIN machine_vaults v ON v.id = g.vault_id ORDER BY g.created_at DESC"
  ).all());
});

app.post("/api/admin/grants", requireAuth(3), (req, res) => {
  const { vault_id, machine_id, max_ttl_seconds, scoped_keys } = req.body;
  if (!vault_id || !machine_id) return res.status(400).json({ error: "vault_id and machine_id required" });
  if (typeof machine_id !== "string" || machine_id.length > 128) return res.status(400).json({ error: "Invalid machine_id" });
  if (!db.prepare("SELECT id FROM machine_vaults WHERE id = ?").get(vault_id)) return res.status(404).json({ error: "Vault not found" });
  const id = crypto.randomUUID();
  try {
    db.prepare(
      "INSERT INTO vault_grants (id, vault_id, machine_id, max_ttl_seconds, scoped_keys, active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)"
    ).run(id, vault_id, machine_id, max_ttl_seconds || 3600, scoped_keys ? JSON.stringify(scoped_keys) : null, Date.now());
    res.json({ id, vault_id, machine_id });
  } catch (err: any) {
    if (err.message?.includes("UNIQUE")) return res.status(409).json({ error: "Grant already exists for this machine+vault" });
    res.status(500).json({ error: "Failed to create grant" });
  }
});

app.delete("/api/admin/grants/:id", requireAuth(3), (req, res) => {
  const grant = db.prepare("SELECT id, vault_id, machine_id FROM vault_grants WHERE id = ?").get(req.params.id) as any;
  if (!grant) return res.status(404).json({ error: "Grant not found" });
  const now = Date.now();
  db.prepare("UPDATE vault_grants SET active = 0, revoked_at = ? WHERE id = ?").run(now, grant.id);
  const leases = db.prepare("SELECT id FROM leases WHERE vault_id = ? AND machine_id = ? AND status IN ('active', 'grace')").all(grant.vault_id, grant.machine_id) as any[];
  for (const l of leases) {
    db.prepare("UPDATE leases SET status = 'revoked', revoked_at = ?, revoke_reason = 'grant_revoked' WHERE id = ?").run(now, l.id);
    auditLease("admin_revoked", l.id, grant.machine_id, grant.vault_id, (req as any).sessionId || "admin", undefined, { reason: "grant_revoked" });
  }
  res.json({ success: true, leases_revoked: leases.length });
});

// ---------- Vault: Backup export ----------
app.post("/api/vault/backup", requireAuth(0), express.json({ limit: "1mb" }), (req, res) => {
  try {
    const { passphrase } = req.body;
    if (!passphrase || typeof passphrase !== "string" || passphrase.length < 12) {
      return res.status(400).json({ error: "Backup passphrase must be at least 12 characters" });
    }

    const bundle = {
      version: 1,
      created_at: new Date().toISOString(),
      tables: {
        secrets:            db.prepare("SELECT * FROM secrets").all(),
        auth_config:        db.prepare("SELECT * FROM auth_config").all(),
        machine_vaults:     db.prepare("SELECT * FROM machine_vaults").all(),
        machine_secrets:    db.prepare("SELECT * FROM machine_secrets").all(),
        machine_identities: db.prepare("SELECT * FROM machine_identities").all(),
        vault_grants:       db.prepare("SELECT * FROM vault_grants").all(),
      },
    };

    const payload = JSON.stringify(bundle);
    const salt = crypto.randomBytes(16);
    const iv   = crypto.randomBytes(12);
    const key  = crypto.pbkdf2Sync(passphrase, salt, 310000, 32, "sha256");
    const cipher    = crypto.createCipheriv("aes-256-gcm", key, iv);
    const encrypted = Buffer.concat([cipher.update(payload, "utf8"), cipher.final()]);
    const tag       = cipher.getAuthTag();

    // Format: magic(4) + version(1) + salt(16) + iv(12) + tag(16) + ciphertext
    const packed = Buffer.concat([Buffer.from("LVLS"), Buffer.from([0x01]), salt, iv, tag, encrypted]);
    res.json({ bundle: packed.toString("base64") });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Backup failed" });
  }
});

// ---------- Vault: Restore ----------
app.post("/api/vault/restore", requireAuth(0), (req, res) => {
  try {
    const { bundle, passphrase } = req.body;
    if (!bundle || !passphrase) {
      return res.status(400).json({ error: "bundle and passphrase are required" });
    }

    const packed = Buffer.from(bundle, "base64");
    if (packed.length < 49 || packed.slice(0, 4).toString() !== "LVLS") {
      return res.status(400).json({ error: "Invalid backup file" });
    }
    if (packed[4] !== 0x01) {
      return res.status(400).json({ error: `Unsupported backup version: ${packed[4]}` });
    }

    const salt       = packed.subarray(5, 21);
    const iv         = packed.subarray(21, 33);
    const tag        = packed.subarray(33, 49);
    const ciphertext = packed.subarray(49);

    let bk: any;
    try {
      const key      = crypto.pbkdf2Sync(passphrase, salt, 310000, 32, "sha256");
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(tag);
      const payload = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
      bk = JSON.parse(payload);
    } catch {
      return res.status(400).json({ error: "Wrong passphrase or corrupted backup" });
    }

    if (bk.version !== 1 || !bk.tables) {
      return res.status(400).json({ error: "Invalid backup format" });
    }

    const { tables } = bk;

    const restore = db.transaction(() => {
      db.exec("DELETE FROM secrets");
      db.exec("DELETE FROM auth_config");
      db.exec("DELETE FROM machine_vaults"); // CASCADE removes machine_secrets
      db.exec("DELETE FROM machine_identities");
      db.exec("DELETE FROM vault_grants");

      const insertSecret = db.prepare(
        "INSERT OR REPLACE INTO secrets (id, name, level, secret_type, encrypted_value, tags, expiry, url, username, folder, created_at) VALUES (@id, @name, @level, @secret_type, @encrypted_value, @tags, @expiry, @url, @username, @folder, @created_at)"
      );
      for (const row of (tables.secrets || [])) insertSecret.run(row);

      const insertAuth = db.prepare(
        "INSERT OR REPLACE INTO auth_config (level, credential_hash, kem_public_key, method, totp_secret, totp_enabled, session_ttl, failed_attempts, locked_until, created_at, updated_at) VALUES (@level, @credential_hash, @kem_public_key, @method, @totp_secret, @totp_enabled, @session_ttl, @failed_attempts, @locked_until, @created_at, @updated_at)"
      );
      for (const row of (tables.auth_config || [])) insertAuth.run(row);

      const insertVault = db.prepare(
        "INSERT OR REPLACE INTO machine_vaults (id, name, description, kem_public_key, totp_secret, totp_enabled, ttl, created_at) VALUES (@id, @name, @description, @kem_public_key, @totp_secret, @totp_enabled, @ttl, @created_at)"
      );
      for (const row of (tables.machine_vaults || [])) insertVault.run(row);

      const insertMS = db.prepare(
        "INSERT OR REPLACE INTO machine_secrets (id, vault_id, name, encrypted_value, classification, created_at) VALUES (@id, @vault_id, @name, @encrypted_value, @classification, @created_at)"
      );
      for (const row of (tables.machine_secrets || [])) insertMS.run(row);

      const insertMI = db.prepare(
        "INSERT OR REPLACE INTO machine_identities (machine_id, ed25519_public_key, kem_public_key, registered_at) VALUES (@machine_id, @ed25519_public_key, @kem_public_key, @registered_at)"
      );
      for (const row of (tables.machine_identities || [])) insertMI.run(row);

      const insertGrant = db.prepare(
        "INSERT OR REPLACE INTO vault_grants (id, vault_id, machine_id, granted_by, max_ttl_seconds, scoped_keys, active, created_at, revoked_at) VALUES (@id, @vault_id, @machine_id, @granted_by, @max_ttl_seconds, @scoped_keys, @active, @created_at, @revoked_at)"
      );
      for (const row of (tables.vault_grants || [])) insertGrant.run(row);
    });

    restore();
    console.warn("[RESTORE] Vault restored at", new Date().toISOString(), "from backup dated", bk.created_at);
    res.json({
      success: true,
      stats: {
        secrets:         (tables.secrets            || []).length,
        vaults:          (tables.machine_vaults     || []).length,
        machine_secrets: (tables.machine_secrets    || []).length,
        identities:      (tables.machine_identities || []).length,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Restore failed" });
  }
});

// ---------- Vault: Nuke (wipe everything) ----------
app.delete("/api/vault/nuke", requireAuth(0), (req, res) => {
  try {
    db.transaction(() => {
      db.exec("DELETE FROM secrets");
      db.exec("DELETE FROM session_logs");
      db.exec("DELETE FROM auth_config");
      db.exec("DELETE FROM vault_grants");
      db.exec("DELETE FROM machine_vaults"); // CASCADE removes machine_secrets
      db.exec("DELETE FROM machine_identities");
    })();
    console.warn("[NUKE] Vault wiped at", new Date().toISOString());
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Nuke failed" });
  }
});

// ---------- Logs ----------
app.get("/api/logs", requireAuth(3), (req, res) => {
  try {
    const authLevel = (req as any).authLevel;
    // Only return logs for levels the user is cleared to see (user_level >= authLevel)
    const logs = db.prepare(
      "SELECT * FROM session_logs WHERE user_level = ? ORDER BY created_at DESC LIMIT 200"
    ).all(authLevel);
    res.json(logs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch logs" });
  }
});

// ---------- C2: HTTPS Support ----------
const CERT_PATH = path.join(process.cwd(), "cert.pem");
const KEY_PATH  = path.join(process.cwd(), "key.pem");

function loadTlsOptions(): { cert: Buffer; key: Buffer } | null {
  try {
    if (fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) {
      return { cert: fs.readFileSync(CERT_PATH), key: fs.readFileSync(KEY_PATH) };
    }
  } catch (e) {
    console.warn("[TLS] Could not read cert/key files:", (e as Error).message);
  }
  return null;
}

// Add HSTS header when running HTTPS
let isHttps = false;
app.use((_req, res, next) => {
  if (isHttps) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});

// ---------- Start ----------
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static("dist"));
  }

  const tls = loadTlsOptions();

  const HOST = process.env.HOST || "127.0.0.1";

  if (tls) {
    isHttps = true;
    https.createServer(tls, app).listen(PORT, HOST, () => {
      console.log(`\x1b[32m[TLS]\x1b[0m lvls running on \x1b[1mhttps://${HOST}:${PORT}\x1b[0m`);
    });
  } else if (process.env.LVLS_ALLOW_HTTP === "true") {
    console.warn("\x1b[33m[SECURITY]\x1b[0m No TLS certificates found — running HTTP (LVLS_ALLOW_HTTP=true). Do not use in production.");
    http.createServer(app).listen(PORT, HOST, () => {
      console.log(`lvls running on http://${HOST}:${PORT} (no TLS — localhost only)`);
    });
  } else {
    console.error("[SECURITY] No TLS certificates found and LVLS_ALLOW_HTTP is not set — refusing to start.");
    console.error("  • Generate certs: see docs/tls.md");
    console.error("  • Or set LVLS_ALLOW_HTTP=true to explicitly allow plaintext HTTP (dev/localhost only).");
    process.exit(1);
  }
}

startServer();
