<div align="center">
  <img src="public/logo.png" alt="lvls Key Vault" width="400" />
  <br/>
  <br/>
  <strong>Local-first, hierarchical key vault with post-quantum encryption</strong>
  <br/>
  <br/>

  ![Node.js](https://img.shields.io/badge/Node.js-20+-339933?style=flat&logo=node.js)
  ![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat&logo=typescript)
  ![React](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react)
  ![SQLite](https://img.shields.io/badge/SQLite-WAL-003B57?style=flat&logo=sqlite)
  ![License](https://img.shields.io/badge/license-MIT-purple?style=flat)
</div>

---

## What is lvls?

**lvls** is a personal, privacy-first key vault with four independent security clearance levels. Every level has its own credential, its own encryption key, and its own session — breaching one level reveals nothing about the others.

Unlike cloud password managers, lvls runs entirely on your hardware. No telemetry, no sync to external servers, no third-party dependencies for the crypto layer.

---

## Security Levels

| Level | Name | Encryption | Use case |
|-------|------|-----------|----------|
| **lvl3** | Public | AES-256-GCM + PBKDF2 | Social handles, guest Wi-Fi, public tokens |
| **lvl2** | Professional | ML-KEM-768 + AES-256-GCM + HKDF | API keys, work credentials, DAO access |
| **lvl1** | Personal | ML-KEM-768 + AES-256-GCM + HKDF | Finance, health, SSH keys, personal IDs |
| **lvl0** | Critical | ML-KEM-768 + AES-256-GCM + HKDF | Seed phrases, master identity, break-glass |

**lvl0 is the highest security.** Unlocking a level does not grant access to any level below it.

---

## Encryption Stack

```
lvl3  → PIN  →  PBKDF2-SHA256 (310k iterations)  →  AES-256-GCM
lvl0/1/2  →  Passphrase  →  Argon2id (64MB, 3 iter)  →  stored hash
           →  ML-KEM-768 keygen  →  private key encrypted with AES+PBKDF2 → localStorage
           →  public key → server
           →  on encrypt: ML-KEM encapsulate → shared secret → HKDF-SHA256 → AES-256-GCM
           →  on decrypt: ML-KEM decapsulate → shared secret → HKDF-SHA256 → AES-256-GCM
```

- **ML-KEM-768** — NIST FIPS 203 post-quantum key encapsulation (via `@noble/post-quantum`)
- **Argon2id** — credential hashing (server-side, 64MB memory cost)
- **PBKDF2-SHA256** — key derivation for AES (client-side, Web Crypto API)
- **HKDF-SHA256** — KDF for high-entropy KEM shared secrets
- **AES-256-GCM** — symmetric encryption with 128-bit authentication tag
- **TOTP (RFC 6238)** — optional 2FA per level, secrets encrypted at rest

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Express.js + TypeScript (tsx) |
| Database | SQLite (better-sqlite3, WAL mode) |
| Frontend | React 19 + Vite + Tailwind CSS v4 |
| Animation | Framer Motion |
| Auth | Argon2id + JWT (HS256) + TOTP |
| PQC Crypto | @noble/post-quantum (ML-KEM-768) |
| Extension | Chrome/Edge MV3 (vanilla JS) |

---

## Features

- **4 independent clearance levels** — separate credential, key, and session per level
- **Post-quantum encryption** — ML-KEM-768 hybrid for lvl0/1/2
- **TOTP 2FA** — per-level optional, RFC 6238 compliant
- **Built-in authenticator** — store TOTP seeds, generate live 6-digit codes
- **Browser extension** — detect login forms, auto-fill credentials
- **Auto-lock** — wipes session and KEM keys from memory after inactivity
- **Session TTL** — configurable token expiry per level
- **Per-level lockout** — 5 failed attempts locks a level for 15 min
- **Token revocation** — server-side logout invalidates JWT immediately
- **Rate limiting** — DB-persisted, survives server restarts
- **Audit logs** — tamper-evident session log per level
- **HTTPS** — TLS with auto-detection of cert files

---

## Quick Start

### Prerequisites
- Node.js 20+
- npm 9+

### 1. Clone and install

```bash
git clone https://github.com/your-org/lvls-key-vault.git
cd lvls-key-vault
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and set a strong `JWT_SECRET`:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 3. Enable HTTPS (recommended)

Generate TLS certificates. Requires [mkcert](https://github.com/FiloSottile/mkcert/releases) (binary, not npm):
```bash
mkcert -install
mkcert -cert-file cert.pem -key-file key.pem 127.0.0.1 localhost
```

Or with OpenSSL (self-signed, browser will warn once):
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 4. Start

```bash
npm run dev
```

Open `https://127.0.0.1:3000` (or `http://` if no certs).

### 5. Onboarding

On first run, the vault is in **dev mode** with temporary credentials. Complete onboarding before storing real secrets:

1. Scroll the `lvl` selector to **lvl3** and enter `1234`
2. Go to **Settings → Level Credentials** and set real credentials for all 4 levels
3. Optionally enable **TOTP 2FA** per level in Settings
4. Dev mode is disabled once all levels have real credentials set

---

## Dev Mode Credentials

> **These only work when no real credentials are configured.** Set real credentials immediately.

| Level | Credential |
|-------|-----------|
| lvl3 | `1234` |
| lvl2 | `Pass2a1` |
| lvl1 | `Key1a1b` |
| lvl0 | `Master1a` |

---

## Browser Extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder
4. Copy the extension ID shown and set `EXTENSION_ID=` in `.env`

The extension detects password fields on any site and injects an **lvl** badge. Click it to authenticate and auto-fill credentials.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Yes | 32-byte hex secret for JWT signing. Generate fresh. |
| `NODE_ENV` | Yes | `development` or `production`. Dev mode enables fallback credentials. |
| `EXTENSION_ID` | No | Chrome extension ID. Restricts CORS to your extension only. |

---

## Project Structure

```
lvls-key-vault/
├── server.ts              Express server, all API routes, auth, TOTP, DB
├── src/
│   ├── App.tsx            Main React application (all UI)
│   ├── lib/crypto.ts      Client-side crypto (AES, ML-KEM, HKDF, PBKDF2)
│   ├── types.ts           TypeScript interfaces
│   └── index.css          Global styles + Tailwind theme
├── extension/
│   ├── manifest.json      MV3 manifest
│   ├── background.js      Service worker (auth token, API proxy)
│   ├── content.js         Form detection, badge injection
│   └── popup.html/js      Auth + credential fill UI
├── public/
│   └── logo.png           Application logo
├── .env.example           Environment variable template
└── cert.pem / key.pem     TLS certificates (generated, not committed)
```

---

## API Routes

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| GET | `/api/health` | None | Server health check |
| GET | `/api/auth/status` | lvl3 | Vault setup status + TOTP config |
| POST | `/api/auth/unlock` | Rate limited | Authenticate and get JWT |
| POST | `/api/auth/logout` | lvl3 | Revoke current token |
| POST | `/api/auth/setup` | lvl3 | Set level credential |
| PUT | `/api/auth/session-ttl/:level` | lvl3 | Update session TTL |
| GET | `/api/auth/kem-key/:level` | lvl3 | Get ML-KEM public key |
| PUT | `/api/auth/kem-key/:level` | lvl3 | Upload ML-KEM public key |
| POST | `/api/auth/totp/setup/:level` | lvl3 | Generate TOTP secret |
| POST | `/api/auth/totp/confirm/:level` | lvl3 | Confirm and enable TOTP |
| POST | `/api/auth/totp/disable/:level` | lvl3 | Disable TOTP |
| GET | `/api/secrets` | lvl3 | List secrets (filtered by clearance) |
| POST | `/api/secrets` | lvl3 | Create secret |
| PUT | `/api/secrets/:id` | lvl3 | Update secret metadata |
| DELETE | `/api/secrets/:id` | lvl3 | Delete secret |
| GET | `/api/secrets/by-domain` | lvl3 | Domain-matched secrets (extension) |
| GET | `/api/logs` | lvl3 | Session audit logs |
| DELETE | `/api/vault/nuke` | lvl0 | Wipe entire vault |

---

## Security

See [SECURITY.md](SECURITY.md) for the full security architecture, threat model, and vulnerability disclosure policy.

---

## Roadmap

- [ ] Encrypted backup / export (`.lvls` file)
- [ ] Hetzner server deployment guide
- [ ] Android companion app (React Native)
- [ ] FIDO2 / WebAuthn hardware key support
- [ ] Encrypted vault sync between instances

---

## License

MIT — see [LICENSE](LICENSE)
