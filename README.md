<div align="center">
  <img src="public/logo.png" alt="lvls Key Vault" width="380" />
  <br/><br/>
  <strong>Local-first, hierarchical key vault with post-quantum encryption</strong>
  <br/><br/>

  ![Node.js](https://img.shields.io/badge/Node.js-22+-339933?style=flat&logo=node.js)
  ![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat&logo=typescript)
  ![React](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react)
  ![SQLite](https://img.shields.io/badge/SQLite-WAL-003B57?style=flat&logo=sqlite)
  ![FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203-6B46C1?style=flat)
  ![License](https://img.shields.io/badge/license-MIT-purple?style=flat)
</div>

---

## What is lvls?

**lvls** is a self-hosted personal key vault with four independent security clearance levels. Each level has its own credential, its own encryption key, its own session, and its own JWT — breaching one level reveals nothing about the others.

Unlike cloud password managers, lvls runs entirely on your own hardware. No telemetry, no external sync, no third-party crypto dependencies. Secrets are encrypted client-side before ever reaching the server — the database contains only ciphertext.

**Designed for:** developers, operators, and privacy-conscious individuals who self-host their infrastructure and need a secure, local-first credential store — not a SaaS subscription.

---

## Security Architecture

### The Four Levels

| Level | Name | Purpose | Encryption |
|-------|------|---------|-----------|
| **lvl3** | Everyday | Social profiles, Wi-Fi passwords, subscriptions, low-impact tokens | AES-256-GCM + PBKDF2-SHA256 |
| **lvl2** | Professional | API keys, IAM credentials, DAO access, work secrets | ML-KEM-768 + HKDF-SHA256 + AES-256-GCM |
| **lvl1** | Personal | Financial APIs, SSH keys, health data, personal identity | ML-KEM-768 + HKDF-SHA256 + AES-256-GCM |
| **lvl0** | Critical | Seed phrases, master keys, break-glass credentials | ML-KEM-768 + HKDF-SHA256 + AES-256-GCM |

**lvl0 is the highest security.** Unlocking lvl3 does not grant access to lvl0, lvl1, or lvl2. Each level is a fully sealed compartment.

### Encryption Stack

```
lvl3 — PIN-based
  PIN → PBKDF2-SHA256 (310,000 iter, 16-byte random salt) → AES-256-GCM key
  AES-256-GCM.encrypt(plaintext) → stored ciphertext

lvl0 / lvl1 / lvl2 — Post-quantum hybrid
  Passphrase → Argon2id (64MB, 3 iter) → stored hash (server)
  Passphrase → PBKDF2-SHA256 → AES-GCM key → encrypts ML-KEM private key → localStorage

  On encrypt:
    ML-KEM-768.encapsulate(publicKey) → { kemCiphertext, sharedSecret (32B) }
    HKDF-SHA256(sharedSecret, info="lvls-v1-aes-gcm-256") → AES-256-GCM key
    AES-256-GCM.encrypt(plaintext) → stored ciphertext

  On decrypt:
    ML-KEM-768.decapsulate(kemCiphertext, privateKey) → sharedSecret (32B)
    HKDF-SHA256(sharedSecret) → AES-256-GCM key
    AES-256-GCM.decrypt(ciphertext) → plaintext
```

### Cryptographic Primitives

| Primitive | Algorithm | Standard | Use |
|-----------|-----------|----------|-----|
| Post-quantum KEM | ML-KEM-768 | NIST FIPS 203 | Key encapsulation for lvl0/1/2 |
| Symmetric encryption | AES-256-GCM | NIST FIPS 197 | All ciphertext storage |
| Key derivation | HKDF-SHA256 | RFC 5869 | KEM shared secret → AES key |
| Password derivation | PBKDF2-SHA256 (310k) | RFC 2898 | Client-side AES key for lvl3 |
| Password hashing | Argon2id (64MB, 3 iter) | RFC 9106 | Server-side credential hashing |
| 2FA | TOTP (HMAC-SHA1) | RFC 6238 | Optional per-level 2FA |
| Session tokens | JWT HS256 | RFC 7519 | Per-level sessions with TTL |
| TOTP at-rest | AES-256-GCM | — | TOTP seeds encrypted in DB |

### Security Controls

| Control | Detail |
|---------|--------|
| Rate limiting | DB-persisted (survives restarts) — 10 failures / 15 min per IP |
| Per-level lockout | 5 wrong credentials locks that level for 15 min |
| TOTP replay prevention | `used_totps` table — rejects any code used within its 90-second window |
| Token revocation | `revoked_tokens` table checked on every authenticated request |
| Auto-lock | Wipes session tokens and KEM private keys from memory after 5 min inactivity |
| CORS | Restricted to localhost + optionally one pinned Chrome extension ID |
| CSP | `default-src 'self'` — blocks external resource loading |
| Security headers | HSTS, X-Frame-Options: DENY, X-Content-Type-Options, Referrer-Policy |
| Privilege isolation | Authenticated level cannot access secrets above its clearance |
| Audit log | All auth events, secret mutations, and TOTP changes logged with session ID |

See [SECURITY.md](SECURITY.md) for the full threat model and vulnerability disclosure policy.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Express.js + TypeScript (tsx runtime) |
| Database | SQLite via better-sqlite3, WAL mode |
| Frontend | React 19, Vite 6, Tailwind CSS v4 |
| Animation | Framer Motion |
| PQC Crypto | @noble/post-quantum (ML-KEM-768, FIPS 203) |
| Browser Extension | Chrome / Edge MV3 (vanilla JS) |
| Process management | systemd or Docker |

---

## Features

- **4 independent clearance levels** — separate credential, encryption key, and session per level
- **Post-quantum encryption** — ML-KEM-768 hybrid for lvl0/1/2, harvest-now-decrypt-later resistant
- **TOTP 2FA** — optional per level, RFC 6238 compliant, encrypted seeds at rest
- **Built-in authenticator** — store TOTP seeds and generate live 6-digit codes in the vault UI
- **Browser extension** — detects login forms, injects fill badge, auto-fills credentials
- **Guided onboarding** — step-by-step first-run setup wizard
- **Auto-lock** — wipes session and KEM private keys from memory after inactivity
- **Configurable session TTL** — per level: 15 min to 24 hours
- **Per-level lockout** — brute-force protection per level, independent of rate limiter
- **Token revocation** — server-side logout invalidates JWT immediately
- **Rate limiting** — DB-persisted, survives server restarts
- **Audit logs** — tamper-evident session log with session ID attribution per action
- **HTTPS** — TLS with HSTS, auto-detects cert files on startup
- **Docker support** — multi-stage build, production-ready container
- **Secret folders** — organise secrets into collapsible groups
- **Domain matching** — extension auto-filters credentials by current site hostname

---

## Quick Start

### Prerequisites

- Node.js 22+
- npm 9+

### 1. Clone and install

```bash
git clone https://github.com/dhvr-era/lvls-key-vault.git
cd lvls-key-vault
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
```

Generate strong secrets for `.env`:

```bash
# JWT signing secret
node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"

# TOTP encryption secret (independent of JWT)
node -e "console.log('TOTP_ENC_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
```

Your `.env` should look like:

```env
JWT_SECRET=<64-char hex>
TOTP_ENC_SECRET=<64-char hex>
PORT=5000
HOST=127.0.0.1
EXTENSION_ID=          # set after loading the browser extension
```

### 3. Generate TLS certificates (recommended)

With [mkcert](https://github.com/FiloSottile/mkcert) (trusted local CA — no browser warning):

```bash
mkcert -install
mkcert -cert-file cert.pem -key-file key.pem 127.0.0.1 localhost
```

With OpenSSL (self-signed — browser warns once, then remembers):

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 825 -nodes \
  -subj "/CN=lvls" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
```

### 4. Start

```bash
# Development
npm run dev

# Production (recommended)
NODE_ENV=production npx tsx server.ts
```

Open `https://127.0.0.1:5000` in your browser.

### 5. Onboarding

On first run, the vault detects it is unconfigured and launches the setup wizard:

1. **Welcome** — overview of the four levels
2. **Create your lvl3 PIN** — minimum 6 digits, this is your vault entry point
3. **Configure higher levels** — set passphrases for lvl2, lvl1, lvl0 (or skip and do it later in Settings)
4. **Enter the vault** — you're in, token is live

Higher levels can always be configured or reconfigured from **Settings → Level Credentials**.

---

## Production Deployment

### Systemd (recommended for VPS)

```bash
# Copy the service file
cp lvls.service /etc/systemd/system/lvls.service

# Edit WorkingDirectory and EnvironmentFile paths if needed
systemctl daemon-reload
systemctl enable --now lvls
systemctl status lvls
```

The service sets `NODE_ENV=production` and loads secrets from `/path/to/.env`.

### Docker

```bash
# Build and start
docker compose up -d

# Logs
docker compose logs -f
```

The compose file binds `127.0.0.1:5000:5000` — not exposed publicly. Mount your `.env`, `cert.pem`, `key.pem`, and `lvls.db` as volumes.

### Security hardening (production checklist)

```bash
# Restrict file permissions
chmod 600 .env key.pem cert.pem lvls.db

# Set your extension ID in .env once the extension is loaded
EXTENSION_ID=your_extension_id_here

# Run as a non-root user (edit lvls.service: User=youruser)
```

---

## Browser Extension

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** → select the `extension/` folder
4. Copy the **Extension ID** shown
5. Set `EXTENSION_ID=<your-id>` in `.env` and restart lvls

The extension injects an **lvl** badge next to password fields on any site. Clicking it opens the vault popup, authenticates you, and auto-fills matching credentials.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Yes | 32-byte hex secret for JWT signing. Generate fresh — never reuse. |
| `TOTP_ENC_SECRET` | Yes | 32-byte hex secret for encrypting TOTP seeds at rest. Independent of JWT_SECRET. |
| `PORT` | No | Server port. Default: `5000`. |
| `HOST` | No | Bind address. Default: `127.0.0.1`. Use `0.0.0.0` for LAN/Tailscale access. |
| `EXTENSION_ID` | Recommended | Your Chrome extension ID. Restricts CORS to your extension only. Leave blank to allow any extension origin (dev only). |

---

## Project Structure

```
lvls-key-vault/
├── server.ts              Express API — auth, secrets CRUD, TOTP, DB, bootstrap
├── src/
│   ├── App.tsx            React SPA — all UI, onboarding, vault, settings
│   ├── lib/crypto.ts      Client-side crypto (AES-256-GCM, ML-KEM-768, HKDF, PBKDF2)
│   ├── types.ts           TypeScript interfaces
│   └── index.css          Global styles + Tailwind v4 theme
├── extension/
│   ├── manifest.json      MV3 manifest
│   ├── background.js      Service worker — token management, API proxy, sender validation
│   ├── content.js         Form detection, lvl badge injection
│   └── popup.html/js      Auth UI, credential display, client-side decryption
├── public/
│   └── logo.png           Application logo
├── Dockerfile             Multi-stage production build
├── docker-compose.yml     Production compose with bind mounts
├── .env.example           Environment variable template
├── SECURITY.md            Threat model, encryption layers, key management
└── AUDIT-ASVS-v4-L3.md   OWASP ASVS v4.0 Level 3 security audit report
```

---

## API Reference

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| GET | `/api/health` | None | Server health check |
| GET | `/api/auth/is-setup` | None | Whether vault has any configured levels |
| POST | `/api/auth/bootstrap` | None* | First-time lvl3 PIN setup — locked once any level exists |
| GET | `/api/auth/status` | lvl3+ | Configured levels, TOTP state, session TTLs |
| POST | `/api/auth/unlock` | Rate limited | Authenticate with credential (+ TOTP if enabled) |
| POST | `/api/auth/logout` | lvl3+ | Revoke current session token |
| POST | `/api/auth/setup` | lvl3+ | Set or update a level's credential |
| PUT | `/api/auth/session-ttl/:level` | lvl3+ | Update session TTL for a level |
| GET | `/api/auth/kem-key/:level` | lvl3+ | Retrieve ML-KEM public key |
| PUT | `/api/auth/kem-key/:level` | lvl3+ | Register ML-KEM public key |
| POST | `/api/auth/totp/setup/:level` | lvl3+ | Generate TOTP secret + QR URI |
| POST | `/api/auth/totp/confirm/:level` | lvl3+ | Confirm and activate TOTP |
| POST | `/api/auth/totp/disable/:level` | lvl3+ | Disable TOTP for a level |
| GET | `/api/secrets` | lvl3+ | List secrets accessible at current clearance |
| POST | `/api/secrets` | lvl3+ | Create encrypted secret |
| PUT | `/api/secrets/:id` | lvl3+ | Update secret metadata |
| DELETE | `/api/secrets/:id` | lvl3+ | Delete secret |
| GET | `/api/secrets/by-domain` | lvl3+ | Domain-matched secrets (used by extension) |
| GET | `/api/logs` | lvl3+ | Session audit log |
| DELETE | `/api/vault/nuke` | lvl0 | Irreversibly wipe all vault data |

*Bootstrap is only callable when zero levels are configured.

---

## Security Audit

A full [OWASP ASVS v4.0 Level 3](AUDIT-ASVS-v4-L3.md) audit was performed against this codebase. Summary:

| Metric | Result |
|--------|--------|
| Controls assessed | 142 |
| Pass | 121 (85%) |
| ASVS Level | 3 (highest) |
| Critical findings | 0 (all remediated) |
| High findings | 0 (all remediated) |
| npm audit CVEs | 0 |

---

## Known Limitations

| Item | Detail |
|------|--------|
| No encrypted backup | DB loss = permanent data loss. Encrypted export is on the roadmap. |
| Self-signed TLS | Use mkcert for a trusted local CA, or add your own CA-signed cert. |
| localStorage | ML-KEM private keys stored encrypted in browser localStorage. XSS on localhost could access the encrypted blob. |
| No FIDO2 | Hardware security key support is not yet implemented. |
| SQLite only | Single-file DB, no replication. Designed for personal/small-team use. |
| TOTP SHA-1 | RFC 6238 uses HMAC-SHA1 — compatible with all authenticator apps. Not practically exploitable in HOTP context. |

---

## Roadmap

- [ ] Encrypted backup / export (`.lvls` bundle — AES-256-GCM, passphrase-derived)
- [ ] Encrypted import / restore from backup
- [ ] Run as non-root user (systemd + Docker)
- [ ] FIDO2 / WebAuthn hardware key support
- [ ] Mobile companion app (React Native)
- [ ] Encrypted vault sync between instances

---

## License

MIT — see [LICENSE](LICENSE)
