---
doc_id: LVLS-DEV-002
title: lvls Machine Vaults — Architecture & Integration Guide
version: 1.0
classification: CONFIDENTIAL
created: 2026-03-20
modified: 2026-03-20
by: ops
owner: dhvr
reviewed_by: ops
approved_by: ~
review_date: 2026-06-20
vps: hetzner-vps-1
scope: project
status: active
---

# lvls Machine Vaults — Architecture & Integration Guide

Machine vaults let a service (a "machine") fetch secrets programmatically from lvls at runtime without a human credential. The machine authenticates via cryptographic proof, receives a time-limited lease, and gets its secrets decrypted and delivered. No passwords, no hardcoded keys in `.env`.

---

## 1. Concepts

| Term | What it is |
|------|-----------|
| **Machine vault** | A named bucket of secrets. One vault per service (e.g. `clutch`, `litellm-vault`). |
| **Machine secret** | A key/value pair inside a vault. Has a classification: `cached` or `blind`. |
| **Machine identity** | A service's registered Ed25519 public key + optional ML-KEM public key. Bound to a `machine_id` string. |
| **Lease** | A time-limited grant issued after successful auth. Active while the service holds secrets in memory. |
| **Vault grant** | Optional: restricts a specific `machine_id` to a subset of keys + a max TTL. |

---

## 2. Secret Classifications

### `cached` — AES-256-GCM, server-side
- Server encrypts with a key derived from `LVLS_DB_KEY + vault_id` (HKDF-SHA256).
- On request: server decrypts and returns **plaintext** to the machine.
- Machine receives secrets ready to use — no client-side crypto needed.
- Use for: most secrets (DB passwords, API keys, tokens).

### `blind` — ML-KEM-768, client-side
- Server stores the ML-KEM ciphertext blob as-is — **never decrypts it**.
- On request: server returns the ciphertext blob. Machine decrypts with its ML-KEM private key.
- Server cannot read the value at any time.
- Use for: secrets that must never be exposed server-side (high-sensitivity keys).
- Requires: KEM keypair registered in the machine vault + machine holds the private key.

---

## 3. Authentication Methods

Two ways a machine can prove its identity. The vault requires at least one to be configured before it will serve requests.

### Method A — Ed25519 Digital Signature (recommended)

The machine signs each request with its Ed25519 private key. The server verifies the signature against the registered public key.

**How the signature works:**

```
message   = "lvls:{vaultId}:{machineId}:{timestamp}"
signature = Ed25519.sign(message, machine_private_key)
```

The server checks:
1. `|now - timestamp| ≤ 60s` — prevents stale replays
2. Signature is valid against the registered public key for that `machine_id`
3. `timestamp` hasn't been used before (stored in `used_totps` with 2-min TTL) — prevents exact replay within the window

**Key derivation (lvls-client):**

The client derives its Ed25519 keypair deterministically from `LVLS_TOTP_SEED`:

```
private_key = HKDF-SHA256(seed=LVLS_TOTP_SEED, salt="lvls-ed25519-seed-v1", info="ed25519-machine-key", len=32)
public_key  = Ed25519.getPublicKey(private_key)
```

No key files needed — identity is fully recoverable from the seed. Losing the seed = losing the identity.

**Auto-registration on first contact:**

The first request includes `ed25519_public_key` in the body. The server registers it automatically. After that the public key is immutable — re-registering with a different key is rejected.

### Method B — TOTP (fallback for simple clients)

The machine generates a TOTP code from `LVLS_TOTP_SEED` (RFC 6238 / HMAC-SHA1 / 30s) and sends it with each request. Only used if no Ed25519 identity is registered for that `machine_id`.

---

## 4. How a Request Works (Ed25519 path)

```
Machine                                    lvls server
  │                                            │
  │  POST /api/machine/vaults/{id}/request     │
  │  { machine_id, timestamp, signature,       │
  │    ed25519_public_key (first time only) }  │
  │ ─────────────────────────────────────────► │
  │                                            │  1. Look up machine identity
  │                                            │  2. If unknown + key provided → register
  │                                            │  3. Verify signature + timestamp
  │                                            │  4. Check replay (used_totps)
  │                                            │  5. Fetch + decrypt cached secrets
  │                                            │  6. Issue lease
  │  { secrets[], lease_id, expires_at, ttl }  │
  │ ◄───────────────────────────────────────── │
  │                                            │
  │  [at 75% of TTL] POST .../refresh          │
  │ ─────────────────────────────────────────► │
  │  [on shutdown] DELETE .../leases/{id}      │
  │ ─────────────────────────────────────────► │
```

---

## 5. Offline Tokens

Pre-issued JSON blob of all vault secrets, encrypted with the machine's ML-KEM public key and signed by the server's Ed25519 key. Allows a machine to operate without reaching the lvls server.

**Structure:** `kem_ciphertext` + `aes_ciphertext` + `server_signature` + `expires_at`

**Decryption (client):**
1. Verify `server_signature` over `{kem_ciphertext}.{aes_ciphertext}`
2. ML-KEM decapsulate `kem_ciphertext` → shared secret
3. HKDF-SHA256(shared_secret) → AES key
4. AES-256-GCM decrypt `aes_ciphertext` → secrets

Issue via UI: Machine Vaults → select vault → "Offline Token". Requires machine identity with ML-KEM public key registered.

---

## 6. Vault Grants (optional)

Fine-grained per-machine access control. If any grant exists for a vault, all machines must be explicitly granted.

- `scoped_keys`: restrict machine to a subset of secret names
- `max_ttl_seconds`: cap lease TTL for that machine

---

## 7. Lease System

| Field | Meaning |
|-------|---------|
| `expires_at` | `now + vault.ttl` (default 4h) |
| `grace_until` | `expires_at + 30s` |
| `status` | `active` → `grace` → `expired` / `revoked` |

lvls-client auto-refreshes at 75% of TTL. Revokes on SIGTERM/SIGINT.

---

## 8. Integration — Setup Steps

1. **Create vault** — Machine Vaults tab → Add Vault → name, TTL
2. **Add secrets** — select vault → Add Secret → key/value → classification
3. **Set `LVLS_TOTP_SEED`** on the service — `openssl rand -base64 32` — back it up
4. **Integrate lvls-client:**

```typescript
import { LvlsClient } from "./lvls-client";

const lvls = new LvlsClient({
  baseUrl:   "https://100.64.0.3:5000",
  vaultId:   "YOUR_VAULT_UUID",
  machineId: "your-service-name",
});

lvls.registerExitHandlers();
await lvls.acquire();               // auto-registers identity on first call

const dbUrl = lvls.get("DB_URL");
```

5. **(Optional) Register ML-KEM key** — required only for `blind` secrets or offline tokens

---

## 9. Two KEM Keys — Don't Confuse Them

| Where | Used for |
|-------|---------|
| `machine_vaults.kem_public_key` | Encrypting the vault's own private key into the human vault (lvl2) at creation. Not involved in secret delivery. |
| `machine_identities.kem_public_key` | Encrypting offline token payload for that machine. Required for offline tokens only. |

---

## Changelog

| Version | Date | By | Change |
|---------|------|----|--------|
| 1.0 | 2026-03-20 | ops | Initial document |
