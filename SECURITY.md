# Security Architecture

## Threat Model

lvls is designed for a **local-first, single-user (or small trusted group)** deployment. The primary threats it defends against:

- **Physical access to the machine** — encrypted DB means stolen hardware doesn't reveal secrets
- **DB file theft** — secrets encrypted client-side before storage; DB contains only ciphertext
- **Credential brute force** — Argon2id (memory-hard), rate limiting, per-level lockout, TOTP 2FA
- **Network interception** — HTTPS enforced; localhost-only binding prevents LAN exposure
- **Session hijacking** — short-lived JWTs, server-side revocation on logout, auto-lock
- **Post-quantum adversaries** — ML-KEM-768 (NIST FIPS 203) for lvl0/1/2

It is **not** designed as a multi-tenant SaaS. Do not expose the server publicly without IP-level firewall restrictions.

---

## Encryption Layers

### lvl3 — PIN-protected (AES-256-GCM + PBKDF2)

```
PIN
 └── PBKDF2-SHA256 (310,000 iterations, 16-byte random salt per secret)
      └── AES-256-GCM key (256-bit)
           └── Encrypts plaintext → ciphertext + 128-bit auth tag
```

Packed blob: `salt(16) || iv(12) || ciphertext` → base64

### lvl0/1/2 — Post-quantum hybrid (ML-KEM-768 + HKDF + AES-256-GCM)

```
ML-KEM-768 keypair (generated on unlock, private key encrypted in localStorage)
 ├── Public key → server (auth_config.kem_public_key)
 └── Private key → AES-GCM encrypted with PBKDF2(credential) → localStorage

On encrypt:
  ml_kem768.encapsulate(publicKey) → { kemCiphertext, sharedSecret(32 bytes) }
  HKDF-SHA256(sharedSecret, info="lvls-v1-aes-gcm-256") → AES-256-GCM key
  AES-256-GCM.encrypt(plaintext) → aesCiphertext
  stored: { type: "hybrid", kemCiphertext, aesCiphertext }

On decrypt:
  ml_kem768.decapsulate(kemCiphertext, privateKey) → sharedSecret(32 bytes)
  HKDF-SHA256(sharedSecret, info="lvls-v1-aes-gcm-256") → AES-256-GCM key
  AES-256-GCM.decrypt(aesCiphertext) → plaintext
```

### Credential Hashing (server)

```
Credential → Argon2id (memoryCost: 64MB, timeCost: 3, parallelism: 1) → stored hash
```

### TOTP Secrets (at rest)

TOTP secrets are encrypted before storage using AES-256-GCM with a key derived from the dedicated `TOTP_ENC_SECRET` env var (required at startup — server refuses to start if unset):

```
HMAC-SHA256(TOTP_ENC_SECRET, "lvls-totp-enc-v1") → 32-byte encryption key
AES-256-GCM.encrypt(totp_base32_secret) → stored in auth_config
```

### Session Tokens

- **Algorithm:** JWT HS256, algorithm explicitly pinned
- **TTL:** Configurable per level (15m / 30m / 1h / 2h / 4h / 8h / 24h)
- **Revocation:** `revoked_tokens` table checked on every authenticated request
- **SessionID:** Each token carries a UUID; revoked by logout

---

## Security Controls

| Control | Implementation |
|---------|---------------|
| Rate limiting | DB-persisted (survives restarts), 10 failures / 15 min per IP |
| Per-level lockout | 5 wrong credentials locks a level for 15 min |
| TOTP 2FA | RFC 6238, constant-time comparison (`crypto.timingSafeEqual`) |
| Auto-lock | Client-side: wipes session + KEM keys from memory after 5 min inactivity |
| Token revocation | Server-side JWT invalidation on logout |
| Server binding | `127.0.0.1` only — not reachable from LAN |
| TLS | HTTPS with HSTS (`max-age=31536000`) when certs present; refuses to start without certs unless `LVLS_ALLOW_HTTP=true` is explicitly set |
| Security headers | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` |
| CORS | Restricted to localhost + optionally one specific extension ID |
| Input validation | Level params validated with `/^[0-3]$/` regex; UUIDs server-generated |
| Body limit | 50KB max request body |
| Privilege check | Cannot create secrets above your authenticated clearance level |

---

## Key Management

| Key | Location | Protection |
|-----|----------|-----------|
| JWT_SECRET | `.env` file (server) | Required at startup; never exposed to client |
| TOTP_ENC_SECRET | `.env` file (server) | Required at startup; independent of JWT_SECRET |
| TOTP enc key | Derived at runtime from `TOTP_ENC_SECRET` | Never stored |
| ML-KEM private key | localStorage (encrypted) | AES-GCM + PBKDF2(credential) |
| ML-KEM public key | Server DB | Not secret |
| Credential hash | Server DB | Argon2id, not reversible |

---

## Known Limitations

| Item | Detail |
|------|--------|
| HTTPS cert | Self-signed by default. Use [mkcert](https://github.com/FiloSottile/mkcert) for trusted local cert |
| localStorage | ML-KEM private keys stored encrypted in browser localStorage. XSS on localhost could access this |
| No FIDO2 | Hardware security key UI exists but is not yet implemented |
| Backup passphrase | Encrypted backup/restore implemented. Backup bundle is passphrase-protected (AES-256-GCM). Loss of passphrase = unrecoverable backup |
| TOTP window | ±1 30-second window allowed to tolerate clock drift |
| SQLite | Single-file DB, no replication. Suitable for personal use |

---

## Vulnerability Disclosure

This is a private vault — if you find a vulnerability, open a private GitHub security advisory or contact the maintainer directly.

Do not open public issues for security vulnerabilities.
