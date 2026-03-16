import "dotenv/config";
import express from "express";
import https from "https";
import http from "http";
import fs from "fs";
import path from "path";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3";
import crypto from "crypto";
import argon2 from "argon2";
import jwt from "jsonwebtoken";

const app = express();
const PORT = 3000;
if (!process.env.JWT_SECRET) {
  console.warn("[SECURITY] JWT_SECRET env var not set — using ephemeral random secret. All sessions will be invalidated on restart. Set JWT_SECRET in production.");
}
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

// ── M2: TOTP-at-rest encryption — key derived from JWT_SECRET, never stored ──
const TOTP_ENC_KEY = crypto.createHmac("sha256", JWT_SECRET).update("lvls-totp-enc-v1").digest();
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

// ── H4: HTTP Security Headers ────────────────────────────────────────────────
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});

// ---------- CORS — Fix 5: restrict to specific extension ID if set ----------
const ALLOWED_EXTENSION_ID = process.env.EXTENSION_ID || null;
app.use((req, res, next) => {
  const origin = req.headers.origin || "";
  const isLocalhost = origin.startsWith("http://localhost") || origin.startsWith("https://localhost") ||
    origin.startsWith("http://127.0.0.1") || origin.startsWith("https://127.0.0.1");
  const isExtension = origin.startsWith("chrome-extension://") || origin.startsWith("moz-extension://");
  const extensionAllowed = isExtension && (
    !ALLOWED_EXTENSION_ID ||
    origin === `chrome-extension://${ALLOWED_EXTENSION_ID}` ||
    origin === `moz-extension://${ALLOWED_EXTENSION_ID}`
  );
  if (isLocalhost || extensionAllowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ---------- Rate Limiter — Fix 2: DB-persisted, survives restarts ----------
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 10;

app.use(express.json({ limit: "50kb" }));

// ---------- Database ----------
const db = new Database("lvls.db");
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

// ---------- Rate limits table (Fix 2) ----------
db.exec(`
  CREATE TABLE IF NOT EXISTS rate_limits (
    ip TEXT PRIMARY KEY,
    count INTEGER DEFAULT 0,
    reset_at INTEGER NOT NULL
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
];
for (const m of migrations) {
  try { db.exec(m); } catch { /* column already exists or not supported */ }
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

// ── H6 + M1: Periodic cleanup of expired rate limits and revoked tokens ──────
setInterval(() => {
  const now = Date.now();
  db.prepare("DELETE FROM rate_limits WHERE reset_at < ?").run(now);
  db.prepare("DELETE FROM revoked_tokens WHERE revoked_at < ?").run(now - 7 * 24 * 60 * 60 * 1000);
}, 60 * 60 * 1000); // every hour

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
  // You must be authenticated at the target level (or higher security) to change its credential
  if ((req as any).authLevel > level) {
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
      .run("system", level, "setup_credential", JSON.stringify({ level, method }));

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to set up credential" });
  }
});

// ---------- Auth: Unlock a level ----------
app.post("/api/auth/unlock", authRateLimit, async (req, res) => {
  const { level, credential, totp } = req.body;
  if (level === undefined || !credential) {
    return res.status(400).json({ error: "level and credential are required" });
  }

  try {
    const row = db.prepare("SELECT credential_hash, totp_secret, totp_enabled, session_ttl, failed_attempts, locked_until FROM auth_config WHERE level = ?").get(level) as any;

    if (!row) {
      if (process.env.NODE_ENV !== "production") {
        const devPins: Record<number, string> = { 3: "1234", 2: "Pass2a1", 1: "Key1a1b", 0: "Master1a" };
        if (credential === devPins[level]) {
          const token = jwt.sign({ level, sessionId: crypto.randomUUID() }, JWT_SECRET, { expiresIn: "24h" });
          return res.json({ success: true, token, devMode: true });
        }
        return res.status(401).json({ error: "Invalid credential (dev mode)" });
      }
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
        .run("system", level, "auth_failed", JSON.stringify({ level, attempt: newAttempts }));
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
          .run("system", level, "auth_failed_totp", JSON.stringify({ level }));
        return res.status(401).json({ error: "Invalid TOTP code" });
      }
    }

    // Fix 1 & 3: Use per-level TTL, reset lockout on success
    rateLimitClear((req as any).rateLimitIp);
    db.prepare("UPDATE auth_config SET failed_attempts = 0, locked_until = 0 WHERE level = ?").run(level);
    const ttl = parseTTL(row.session_ttl || "24h");
    const token = jwt.sign({ level, sessionId: crypto.randomUUID() }, JWT_SECRET, { expiresIn: ttl as any });
    db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
      .run("system", level, "auth_success", JSON.stringify({ level }));

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
      .run("system", level, "kem_key_updated", JSON.stringify({ level }));
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update KEM key" });
  }
});

// ---------- TOTP: Generate setup secret ----------
app.post("/api/auth/totp/setup/:level", requireAuth(3), (req, res) => {
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
app.post("/api/auth/totp/confirm/:level", requireAuth(3), (req, res) => {
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
    .run("system", level, "totp_enabled", JSON.stringify({ level }));

  res.json({ success: true });
});

// ---------- TOTP: Disable ----------
app.post("/api/auth/totp/disable/:level", requireAuth(3), (req, res) => {
  const level = validLevelParam(req.params.level);
  if (level === null) return res.status(400).json({ error: "Invalid level" });
  if ((req as any).authLevel > level) return res.status(403).json({ error: "Insufficient clearance" });

  db.prepare("UPDATE auth_config SET totp_secret = NULL, totp_enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE level = ?").run(level);
  db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
    .run("system", level, "totp_disabled", JSON.stringify({ level }));

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
  const { name, level, secret_type, encrypted_value, tags, expiry, url, username } = req.body;
  const authLevel = (req as any).authLevel;
  // C4: Prevent privilege escalation — can only create secrets at your own level or less secure
  if (level === undefined || level < authLevel) return res.status(403).json({ error: "Cannot create secrets above your clearance level" });
  if (level < 0 || level > 3) return res.status(400).json({ error: "Invalid level" });
  if (!name || !encrypted_value) return res.status(400).json({ error: "name and encrypted_value are required" });
  // C5: Server generates the ID — client cannot control the primary key
  const id = crypto.randomUUID();
  try {
    db.prepare(
      "INSERT INTO secrets (id, name, level, secret_type, encrypted_value, tags, expiry, url, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(id, name, level, secret_type || "custom", encrypted_value, JSON.stringify(tags), expiry, url || null, username || null);

    db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
      .run("system", level, "create_secret", JSON.stringify({ id }));

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to save secret" });
  }
});

// ---------- Secrets: Update ----------
app.put("/api/secrets/:id", requireAuth(3), async (req, res) => {
  const { id } = req.params;
  const { name, secret_type, tags, url, username } = req.body;
  try {
    const secret = db.prepare("SELECT level FROM secrets WHERE id = ?").get(id) as any;
    if (!secret) return res.status(404).json({ error: "Secret not found" });
    if ((req as any).authLevel > secret.level) return res.status(403).json({ error: "Insufficient clearance" });

    db.prepare(
      "UPDATE secrets SET name = ?, secret_type = ?, tags = ?, url = ?, username = ? WHERE id = ?"
    ).run(name, secret_type, JSON.stringify(tags), url || null, username || null, id);

    db.prepare("INSERT INTO session_logs (session_id, user_level, action, details) VALUES (?, ?, ?, ?)")
      .run("system", secret.level, "update_secret", JSON.stringify({ name, id }));

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
      "SELECT id, name, level, secret_type, encrypted_value, tags, expiry, url, username, created_at FROM secrets WHERE level >= ? ORDER BY created_at DESC"
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
    const authLevel = (req as any).authLevel;
    // Match secrets where url contains the hostname
    const secrets = db.prepare(
      "SELECT id, name, level, secret_type, encrypted_value, tags, url, username, created_at FROM secrets WHERE level >= ? AND (url LIKE ? OR name LIKE ?) ORDER BY created_at DESC"
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
      .run("system", (req as any).authLevel, "delete_secret", JSON.stringify({ id: req.params.id }));
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete secret" });
  }
});

// ---------- Vault: Nuke (wipe everything) ----------
app.delete("/api/vault/nuke", requireAuth(0), (req, res) => {
  try {
    db.exec("DELETE FROM secrets");
    db.exec("DELETE FROM session_logs");
    db.exec("DELETE FROM auth_config");
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

  if (tls) {
    isHttps = true;
    https.createServer(tls, app).listen(PORT, "127.0.0.1", () => {
      console.log(`\x1b[32m[TLS]\x1b[0m lvls running on \x1b[1mhttps://127.0.0.1:${PORT}\x1b[0m`);
    });
  } else {
    console.warn("\x1b[33m[SECURITY]\x1b[0m No TLS certificates found — running HTTP.");
    console.warn("\x1b[33m[SECURITY]\x1b[0m To enable HTTPS (recommended), run:");
    console.warn("  npm install -g mkcert && mkcert -install && mkcert -cert-file cert.pem -key-file key.pem 127.0.0.1 localhost");
    http.createServer(app).listen(PORT, "127.0.0.1", () => {
      console.log(`lvls running on http://127.0.0.1:${PORT} (no TLS — localhost only)`);
    });
  }
}

startServer();
