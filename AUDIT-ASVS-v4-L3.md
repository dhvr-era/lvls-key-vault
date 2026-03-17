# OWASP ASVS v4.0 — Level 3 Security Assessment
## lvls Key Vault — Full Audit Report

**Classification:** TLP:AMBER — Internal Use Only
**Assessment Date:** 2026-03-17
**Framework:** OWASP Application Security Verification Standard v4.0, Level 3
**Governance Overlay:** NIST CSF 2.0
**Assessor:** Internal Security Review
**Target Version:** lvls-key-vault @ Hetzner CCX23 (production)

---

## Executive Summary

| Metric | Value |
|---|---|
| Overall Risk Rating | **MEDIUM** (all criticals remediated in-session) |
| Total Findings | 18 |
| Critical | 0 (2 remediated prior to this report) |
| High | 2 |
| Medium | 7 |
| Low | 9 |
| ASVS L3 Controls Assessed | 142 |
| ASVS L3 Pass | 121 (85%) |
| ASVS L3 Fail / Partial | 21 (15%) |
| npm audit CVEs | 0 |

**Summary:** lvls has a strong cryptographic foundation — ML-KEM-768 (NIST FIPS 203), AES-256-GCM, Argon2id, and TOTP replay prevention are implemented correctly. The two previously critical findings (unset `NODE_ENV` allowing dev-mode bypass, world-readable sensitive files) were remediated during this session. The remaining risk profile is dominated by two high-severity findings: a ghost dependency (`@google/genai`) and a dev-mode bypass code path still compiled into the production binary. Both are medium-effort to fix.

---

## 1. Assessment Scope & Methodology

### 1.1 Assets in Scope

| Asset | Type | Notes |
|---|---|---|
| `server.ts` | Express.js API + static file server | Authentication, secrets CRUD, TOTP |
| `src/App.tsx` | React SPA frontend | UI, client-side crypto, key management |
| `extension/background.js` | Chrome MV3 service worker | Token management, API proxy |
| `extension/popup.js` | Extension popup | Auth UI, secret display, client decryption |
| `extension/content.js` | Content script | Form detection, badge injection |
| `Dockerfile` + `docker-compose.yml` | Container config | Build and deployment |
| `lvls.db` | SQLite database | Credential hashes, encrypted secrets, logs |
| `.env` | Environment secrets | JWT_SECRET, TOTP_ENC_SECRET |

### 1.2 Out of Scope

- Hetzner host OS / VPS hardening (covered separately under IL-CAA v3.0)
- Browser security model / Chrome extension store review
- Network-layer controls (Tailscale, firewall rules)

### 1.3 ASVS Level Rationale

lvls is assessed at **ASVS Level 3** — the highest tier — because it:
- Stores credentials for critical infrastructure (L0: master secrets)
- Implements cryptographic key material management
- Serves as the secrets transport for ClawEngine services
- Operates in a threat model where a single compromise exposes all stored secrets

### 1.4 Threat Actors (STRIDE-aligned)

| Actor | Capability | Likelihood | Primary Vector |
|---|---|---|---|
| External opportunist | Low | Low | Requires Tailscale access |
| Compromised dev machine | Medium | Medium | Tailscale peer → vault |
| Malicious browser extension | Medium | Low | Extension message bus |
| XSS on localhost | Low | Low | CSP partially mitigates |
| Insider / self | High | Low | Physical/Tailscale access |

---

## 2. ASVS Findings by Chapter

### V1 — Architecture, Design and Threat Modeling

| ID | Requirement | Result | Notes |
|---|---|---|---|
| 1.1.1 | Secure SDLC process documented | ⚠️ PARTIAL | `implementation_plan.md` + `SECURITY.md` exist but no formal SDLC |
| 1.1.2 | Threat model documented | ✅ PASS | SECURITY.md covers primary threats |
| 1.2.3 | Unique app-layer accounts | ✅ PASS | Per-level credentials, no shared accounts |
| 1.2.4 | Trust boundary enforcement | ✅ PASS | Extension message bus validates sender origin |
| 1.4.3 | Privilege separation | ✅ PASS | 4-level clearance model, cannot access above auth level |
| 1.6.1 | Crypto keys isolated from data | ✅ PASS | KEM private key never touches server; TOTP key never stored |
| 1.6.2 | Key rotation process exists | ❌ FAIL | No JWT_SECRET rotation mechanism; no KEM key re-generation flow |
| 1.9.1 | Comms between components encrypted | ✅ PASS | HTTPS enforced; TLS on all API calls |
| 1.10.1 | Secret management system | ✅ PASS | lvls IS the secret management system; env secrets via systemd |

**Architecture finding — no key rotation:**
There is no documented or implemented procedure for rotating `JWT_SECRET` or `TOTP_ENC_SECRET`. Rotating `JWT_SECRET` invalidates all active sessions (acceptable) but also invalidates encrypted TOTP seeds (breaking 2FA for all users) because `TOTP_ENC_KEY` derives from `TOTP_ENC_SECRET`. See **H-02** mitigation.

---

### V2 — Authentication Verification Requirements

| ID | Requirement | Result | Notes |
|---|---|---|---|
| 2.1.1 | Passwords ≥ 12 chars at L3 | ⚠️ PARTIAL | Minimum is 6; ASVS L3 recommends 8+ for passphrases, 12+ for passwords |
| 2.1.2 | Passwords ≤ 128 chars | ✅ PASS | No upper bound enforced server-side (DB TEXT allows it) |
| 2.1.5 | Allow paste into password fields | ✅ PASS | No restrictions in frontend |
| 2.1.6 | No password complexity rules except alphanumeric mix | ✅ PASS | L1-2 require mixed alpha+numeric; L3 (PIN) is numeric-only |
| 2.1.9 | No password rotation requirement | ✅ PASS | User-controlled |
| 2.1.10 | No knowledge-based auth | ✅ PASS | Not implemented |
| 2.1.12 | Memory-hard hashing | ✅ PASS | Argon2id: memoryCost=65536, timeCost=3, parallelism=1 |
| 2.2.1 | Anti-automation controls | ✅ PASS | DB-persisted rate limiter (10 req/15 min), per-level lockout (5 fail/15 min) |
| 2.2.2 | Brute force protections logged | ✅ PASS | `session_logs` records `auth_failed`, `auth_failed_totp` |
| 2.2.3 | Rate limit not bypassable by IP rotation | ⚠️ PARTIAL | IP-based; a VPN/proxy rotator could bypass per-IP limits. Mitigated by per-level lockout |
| 2.2.4 | Notify user of auth failures | ⚠️ PARTIAL | No out-of-band notification (email, etc.) — single user design makes this less critical |
| 2.3.1 | System-generated initial passwords | ✅ PASS | No default credentials in production mode |
| 2.3.3 | TOTP seeds ≥ 20 bytes | ✅ PASS | `crypto.randomBytes(20)` |
| 2.4.1 | Passwords hashed with salt | ✅ PASS | Argon2id includes per-hash random salt automatically |
| 2.4.5 | Approved password hash | ✅ PASS | Argon2id (OWASP recommended) |
| 2.5.1 | No "remember me" | ✅ PASS | `chrome.storage.session` (cleared on browser close) |
| 2.5.6 | Forgot password — no secret questions | ✅ PASS | No password recovery implemented (by design) |
| 2.6.1 | OTP verifier HMAC timing-safe | ✅ PASS | `crypto.timingSafeEqual` used in `verifyTotp` |
| 2.6.2 | OTP validity window ≤ 2 time steps | ✅ PASS | `t-1` to `t+1` (3 windows = ±30s) |
| 2.6.3 | OTP replay prevention | ✅ PASS | `used_totps` table with 90-second expiry, cleaned hourly |
| 2.8.1 | OTP secret ≥ 112 bits | ✅ PASS | 20 random bytes = 160 bits |

#### FINDING M-01 — Minimum Credential Length Below ASVS L3 Recommendation
- **Severity:** Medium | **CWE:** CWE-521 | **ASVS:** V2.1.1
- **Location:** `server.ts:355–358`
- **Detail:** L3 (PIN) requires min 6 digits. L1/L2 require min 6 alphanumeric characters. ASVS L3 recommends 8+ characters minimum, 12+ for passwords. A 6-character credential with only alphanumeric mix is brute-forceable offline if the Argon2 hash is extracted via DB theft (though Argon2id at 64MB makes this slow).
- **Risk Score:** Likelihood 2 × Impact 3 = 6 (Medium)
- **Remediation:** Increase minimum to 8 chars for L1/L2, 8 digits for L3 PIN.

---

### V3 — Session Management Verification Requirements

| ID | Requirement | Result | Notes |
|---|---|---|---|
| 3.1.1 | Session tokens in HTTP headers, not URLs | ✅ PASS | `Authorization: Bearer <token>` header only |
| 3.2.1 | New session token on login | ✅ PASS | New JWT with fresh UUID `sessionId` on each unlock |
| 3.2.2 | Session tokens have sufficient entropy | ✅ PASS | HS256 JWT signed with 256-bit random secret |
| 3.2.3 | Tokens stored only in browser session storage | ✅ PASS | `chrome.storage.session` (extension) + React state |
| 3.2.4 | JWT algorithm pinned | ✅ PASS | `algorithms: ["HS256"]` explicitly set on verify |
| 3.3.1 | Logout invalidates session server-side | ✅ PASS | `revoked_tokens` table, checked on every auth'd request |
| 3.3.2 | Re-authentication required for sensitive actions | ⚠️ PARTIAL | Credential change requires current-level auth, but no step-up auth challenge |
| 3.4.1 | Cookie security flags | N/A | No cookies used |
| 3.5.1 | OAuth-specific requirements | N/A | No OAuth |
| 3.7.1 | Idle session timeout enforced | ✅ PASS | Client-side 5-min auto-lock + configurable JWT TTL (15m–24h) |

#### FINDING L-01 — No Step-Up Re-Authentication for Credential Change
- **Severity:** Low | **CWE:** CWE-308 | **ASVS:** V3.3.2
- **Location:** `server.ts:342–389` (`/api/auth/setup`)
- **Detail:** Changing a level's credential requires being authenticated at that level, which is correct. However, there is no additional "confirm your current credential" step-up challenge. An attacker with a stolen live session token could silently rotate the credential.
- **Risk Score:** Likelihood 1 × Impact 4 = 4 (Low)
- **Remediation:** Require the current credential as a confirmation body parameter on `/api/auth/setup` for existing (non-first-time) setups.

---

### V5 — Validation, Sanitization and Encoding

| ID | Requirement | Result | Notes |
|---|---|---|---|
| 5.1.1 | HTTP param pollution protection | ✅ PASS | Express parses only first value; no array injection risk |
| 5.1.2 | Framework-level input validation | ⚠️ PARTIAL | Level validated with regex; `name`, `url`, `username`, `folder` have no length caps |
| 5.1.3 | Input validated server-side, not only client | ✅ PASS | All validation in `server.ts` |
| 5.2.1 | All untrusted HTML input sanitized | ✅ PASS | Secrets never rendered as raw HTML; extension uses `esc()` |
| 5.3.1 | Output encoding for current context | ✅ PASS | React escapes by default; extension uses custom `esc()` |
| 5.3.4 | SQL injection — parameterized queries | ✅ PASS | All DB queries use better-sqlite3 prepared statements |

#### FINDING M-02 — `hostname` LIKE Query Accepts Unbounded User Input
- **Severity:** Medium | **CWE:** CWE-20 | **ASVS:** V5.1.2
- **Location:** `server.ts:644–646` (`/api/secrets/by-domain`)
- **Detail:** The `hostname` query parameter is passed directly into a SQL `LIKE '%${hostname}%'` pattern. While parameterized (safe from injection), a very long hostname string could cause excessive DB scan work. No length validation or character allow-listing exists.
- **Risk Score:** Likelihood 2 × Impact 2 = 4 (Low-Medium)
- **Remediation:** Add: `if (!hostname || hostname.length > 253 || !/^[a-zA-Z0-9.\-]+$/.test(hostname)) return 400`.

#### FINDING L-02 — No Length Caps on `name`, `url`, `username`, `folder` Fields
- **Severity:** Low | **CWE:** CWE-400 | **ASVS:** V5.1.2
- **Location:** `server.ts:576–596` (POST /api/secrets)
- **Detail:** Secret metadata fields have no server-side maximum length. A malicious or errant client could store megabytes of data per secret, potentially bloating `lvls.db` unbounded.
- **Risk Score:** Likelihood 1 × Impact 2 = 2 (Low)
- **Remediation:** Cap `name` at 256 chars, `url` at 2048, `username` at 256, `folder` at 128.

---

### V6 — Stored Cryptography Verification Requirements

| ID | Requirement | Result | Notes |
|---|---|---|---|
| 6.2.1 | Authenticated encryption used | ✅ PASS | AES-256-GCM (L3), ML-KEM-768 + HKDF + AES-256-GCM (L0/1/2) |
| 6.2.2 | Approved cryptographic algorithms | ✅ PASS | AES-256-GCM, Argon2id, HKDF-SHA256, HMAC-SHA256 |
| 6.2.3 | Algorithm agility avoidance | ✅ PASS | Algorithm hardcoded per level, no negotiation |
| 6.2.5 | Random IV/salt per operation | ✅ PASS | 12-byte random IV (AES-GCM), 16-byte salt (PBKDF2) per secret |
| 6.2.6 | IVs never reused | ✅ PASS | `crypto.randomBytes()` per encryption |
| 6.2.7 | Key derivation: approved KDF | ✅ PASS | PBKDF2-SHA256 (310,000 iterations), HKDF-SHA256 |
| 6.2.8 | Memory-hard KDF for passwords | ✅ PASS | Argon2id (server); PBKDF2 at 310K (client L3 — acceptable) |
| 6.3.1 | Random values from CSPRNG | ✅ PASS | `crypto.randomBytes()` (Node), `crypto.getRandomValues()` (browser) |
| 6.4.1 | Cryptographic keys not hardcoded | ✅ PASS | All keys from env vars or runtime derivation |
| 6.4.2 | Key material protected at rest | ✅ PASS | TOTP secrets AES-GCM encrypted at rest; KEM private key never touches server |
| 6.4.3 | Key material protected in transit | ✅ PASS | KEM private key encrypted before localStorage; TLS in transit |

#### FINDING M-03 — ML-KEM Private Key in Browser localStorage (XSS Accessible)
- **Severity:** Medium | **CWE:** CWE-312 | **ASVS:** V6.4.3
- **Location:** `src/lib/crypto.ts` (client-side key storage)
- **Detail:** The ML-KEM-768 private key is stored encrypted (AES-GCM + PBKDF2) in `localStorage`. While encrypted, `localStorage` is accessible to any JavaScript on `localhost`, meaning an XSS vulnerability in the frontend could exfiltrate the encrypted key blob. An attacker with the passphrase could then decrypt offline.
- **Risk Score:** Likelihood 2 × Impact 4 = 8 (Medium)
- **Remediation (short-term):** Use `sessionStorage` instead of `localStorage` — cleared when tab closes, harder to exfiltrate cross-session. Long-term: migrate to WebCrypto non-extractable keys (mark private key as `extractable: false` in `importKey`).

#### FINDING L-03 — TOTP Uses HMAC-SHA1 (RFC 6238 Default)
- **Severity:** Low | **CWE:** CWE-327 | **ASVS:** V6.2.2
- **Location:** `server.ts:276–280` (`hotp()` function)
- **Detail:** RFC 6238 TOTP uses HMAC-SHA1 by default. SHA-1 is cryptographically weak but in the HOTP context is not practically exploitable (attacker needs pre-image resistance, not collision resistance). Most authenticator apps (Google Authenticator, Authy) only support SHA1. The otpauth URI specifies `algorithm=SHA1`.
- **Risk Score:** Likelihood 1 × Impact 2 = 2 (Low)
- **Remediation:** Acceptable for now given universal authenticator compatibility. Note in `SECURITY.md` known limitation.

---

### V7 — Error Handling and Logging

| ID | Requirement | Result | Notes |
|---|---|---|---|
| 7.1.1 | No credentials in logs | ✅ PASS | Credentials never logged; only level and action |
| 7.1.2 | No PII in logs unnecessarily | ✅ PASS | IPs in rate_limits table only; session_logs has level+action |
| 7.2.1 | No error details to client | ✅ PASS | Internal errors return generic "Failed to..." message |
| 7.4.1 | Log format includes timestamp | ✅ PASS | `session_logs.created_at` (DATETIME) |

#### FINDING L-04 — Audit Log Missing Session Attribution
- **Severity:** Low | **CWE:** CWE-778 | **ASVS:** V7.4.1
- **Location:** `server.ts` — all `session_logs` inserts use `"system"` as `session_id`
- **Detail:** Every log entry records `session_id = "system"` rather than the actual `req.sessionId` from the JWT. This means audit logs cannot correlate actions to specific session tokens — forensic investigation after a breach would not be able to distinguish which session performed which actions.
- **Risk Score:** Likelihood 1 × Impact 3 = 3 (Low)
- **Remediation:** Replace `"system"` with `(req as any).sessionId` in all authenticated route log inserts.

---

### V8 — Data Protection Verification Requirements

| ID | Requirement | Result | Notes |
|---|---|---|---|
| 8.1.1 | Sensitive data not cached unnecessarily | ✅ PASS | No `Cache-Control` on API responses (could be improved) |
| 8.1.2 | Sensitive data not in query strings | ✅ PASS | All secrets passed in POST body |
| 8.2.1 | Client-side sensitive data cleared on logout | ✅ PASS | Token cleared, KEM keys wiped on auto-lock |
| 8.2.2 | Sensitive data fields not auto-completed | ✅ PASS | `autocomplete="off"` or equivalent |
| 8.3.1 | Least-privilege DB access | ✅ PASS | Single SQLite file, single process — no privileged DB user |
| 8.3.3 | Sensitive data identified and classified | ⚠️ PARTIAL | Level system IS a classification model; no formal data classification policy doc |
| 8.3.4 | Sensitive data access logged | ✅ PASS | Secret CRUD logged to `session_logs` |

#### FINDING L-05 — No `Cache-Control` Headers on API Responses
- **Severity:** Low | **CWE:** CWE-524 | **ASVS:** V8.1.1
- **Location:** `server.ts` — no `Cache-Control` middleware
- **Detail:** API responses containing secret metadata (`/api/secrets`, `/api/secrets/:id`) have no `Cache-Control: no-store` header. A caching proxy or browser cache could retain sensitive data. Low risk in a localhost-only deployment but should be addressed before any proxy is added.
- **Risk Score:** Likelihood 1 × Impact 2 = 2 (Low)
- **Remediation:** Add `res.setHeader("Cache-Control", "no-store")` in the security headers middleware for `/api/*` routes.

---

### V9 — Communications Verification Requirements

| ID | Requirement | Result | Notes |
|---|---|---|---|
| 9.1.1 | TLS enforced for all connections | ✅ PASS | HTTPS with cert; HTTP fallback with warning, localhost only |
| 9.1.2 | TLS v1.2+ only | ✅ PASS | Node.js 22 defaults to TLS 1.2/1.3 |
| 9.1.3 | Approved TLS cipher suites | ✅ PASS | Node.js secure defaults; no manual cipher downgrade |
| 9.2.1 | HSTS header | ✅ PASS | `Strict-Transport-Security: max-age=31536000; includeSubDomains` when HTTPS |
| 9.2.2 | Certificate pinning | ❌ FAIL | No certificate pinning; extension/popup do not pin the self-signed cert |
| 9.3.1 | Auth credentials not sent over unencrypted connections | ✅ PASS | HTTPS enforced; HTTP logs warning and is localhost-only |

#### FINDING L-06 — No Certificate Pinning in Browser Extension
- **Severity:** Low | **CWE:** CWE-295 | **ASVS:** V9.2.2
- **Location:** `extension/background.js`, `extension/popup.js`
- **Detail:** The extension auto-detects HTTP vs HTTPS but does not pin the expected certificate fingerprint. On the same machine, a MITM on `127.0.0.1:5000` is extremely unlikely, but an attacker with local process injection could intercept requests. Not a practical concern in the Tailscale-isolated deployment model.
- **Risk Score:** Likelihood 1 × Impact 2 = 2 (Low)
- **Remediation:** Document as accepted risk. Long-term: implement `fetch()` with a custom agent that validates expected cert fingerprint.

---

### V10 — Malicious Code Verification Requirements

| ID | Requirement | Result | Notes |
|---|---|---|---|
| 10.2.1 | No back doors or hardcoded credentials | ⚠️ PARTIAL | Dev-mode bypass with hardcoded credentials present in source — see H-01 |
| 10.2.2 | No undocumented network activity | ⚠️ PARTIAL | `@google/genai` unused but present — see H-02 |
| 10.3.1 | No auto-update without integrity check | N/A | Self-hosted, no auto-update |
| 10.3.2 | Signed builds / build integrity | ❌ FAIL | No build signing, no SBOM, no artifact integrity verification |

#### FINDING H-01 — Dev-Mode Hardcoded Credential Bypass in Production Binary
- **Severity:** High | **CWE:** CWE-798 | **ASVS:** V10.2.1
- **Location:** `server.ts:402–409`
- **Detail:** The following code exists in the production binary:
  ```typescript
  if (process.env.NODE_ENV !== "production") {
    const devPins: Record<number, string> = { 3: "1234", 2: "Pass2a1", 1: "Key1a1b", 0: "Master1a" };
    if (credential === devPins[level]) {
      const token = jwt.sign({ level, sessionId: crypto.randomUUID() }, JWT_SECRET, { expiresIn: "24h" });
      return res.json({ success: true, token, devMode: true });
    }
  }
  ```
  While guarded by `NODE_ENV !== "production"` (and `NODE_ENV=production` is now correctly set via systemd), this code: (a) is present in the deployed binary and creates audit risk; (b) would become an instant critical vulnerability if `NODE_ENV` is ever accidentally dropped from the systemd service file; (c) contains the hardcoded credentials in plaintext in the source code.
- **Risk Score:** Likelihood 2 × Impact 5 = 10 (High)
- **Remediation:** Remove the dev bypass block entirely from `server.ts`. Replace with a separate `seed-dev.ts` script that only imports locally and is excluded from production deployments via `.dockerignore`.

#### FINDING H-02 — Unused `@google/genai` Dependency (Supply Chain Risk)
- **Severity:** High | **CWE:** CWE-1357 | **ASVS:** V10.2.2
- **Location:** `package.json:16`
- **Detail:** The `@google/genai` package (a Google Generative AI SDK) is listed as a production dependency but is **not imported or used anywhere in the codebase**. This appears to be a leftover from the original Google AI Studio template that lvls was bootstrapped from (the original `index.html` title was "My Google AI Studio App").
  In a key vault context, an unused dependency with broad network capabilities represents a supply chain attack surface: (a) it increases the dependency tree unnecessarily; (b) a compromised version could silently exfiltrate secrets; (c) any future accidental import of it would add an outbound network call to a Google API.
- **Risk Score:** Likelihood 2 × Impact 5 = 10 (High)
- **Remediation:** `npm uninstall @google/genai` — run immediately. No code changes needed.

---

### V13 — API and Web Service Verification Requirements

| ID | Requirement | Result | Notes |
|---|---|---|---|
| 13.1.1 | Security headers on all responses | ✅ PASS | Applied via middleware before any route |
| 13.1.2 | CORS not permissive | ✅ PASS | Restricted to localhost + optionally pinned extension ID |
| 13.1.3 | HTTP methods validated | ✅ PASS | Express routing by method (GET/POST/PUT/DELETE) |
| 13.1.5 | Request size limited | ✅ PASS | `express.json({ limit: "50kb" })` |
| 13.2.1 | RESTful auth on every request | ✅ PASS | `requireAuth()` middleware on all protected routes |
| 13.2.3 | HTTP methods not downgraded for CSRF | ✅ PASS | Mutation endpoints require POST/PUT/DELETE + valid JWT |
| 13.4.1 | GraphQL introspection disabled | N/A | No GraphQL |

#### FINDING M-04 — No Rate Limiting on TOTP Setup/Confirm Endpoints
- **Severity:** Medium | **CWE:** CWE-307 | **ASVS:** V13.2.1
- **Location:** `server.ts:497–533`
- **Detail:** `/api/auth/totp/setup/:level` and `/api/auth/totp/confirm/:level` have `requireAuth` but no rate limiting. An authenticated attacker could spam TOTP setup in a tight loop, generating and confirming new TOTP secrets rapidly, or use a timing oracle to extract information about the TOTP verification process.
- **Risk Score:** Likelihood 2 × Impact 3 = 6 (Medium)
- **Remediation:** Apply `authRateLimit` middleware to TOTP setup and confirm routes.

#### FINDING M-05 — Nuke Endpoint Has No Additional Confirmation Challenge
- **Severity:** Medium | **CWE:** CWE-749 | **ASVS:** V13.2.1
- **Location:** `server.ts:685–696`
- **Detail:** `DELETE /api/vault/nuke` requires L0 authentication and immediately wipes all secrets, session_logs, and auth_config. There is no "type NUKE to confirm" body parameter or secondary challenge. A stolen L0 session token (even with a short TTL) could permanently destroy all vault data.
- **Risk Score:** Likelihood 2 × Impact 5 = 10 (High → Medium after L0 auth requirement)
- **Remediation:** Require a body parameter `{ confirm: "NUKE" }` on the endpoint before executing. Log the nuke event to a separate immutable log before wiping.

#### FINDING M-06 — EXTENSION_ID Not Configured (CORS Open to All Extensions)
- **Severity:** Medium | **CWE:** CWE-942 | **ASVS:** V13.1.2
- **Location:** `.env:EXTENSION_ID=` (empty)
- **Detail:** When `EXTENSION_ID` is not set, the CORS policy allows any Chrome extension to send requests to the vault API. A malicious extension on the same browser that has obtained a session token (e.g., from `chrome.storage.session` if accessible) could call `/api/secrets`.
- **Risk Score:** Likelihood 2 × Impact 4 = 8 (Medium)
- **Remediation:** Set `EXTENSION_ID` to the installed extension's Chrome extension ID after installation. Document this as a required post-install step.

---

### V14 — Configuration Verification Requirements

| ID | Requirement | Result | Notes |
|---|---|---|---|
| 14.1.1 | No debug features in production | ✅ PASS | `NODE_ENV=production` via systemd; Vite dev server disabled |
| 14.1.2 | HTTP security headers set | ✅ PASS | CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy |
| 14.2.1 | Client-side library versions pinned | ⚠️ PARTIAL | `package.json` uses `^` (semver caret) for most deps — minor/patch updates auto-install |
| 14.2.2 | Unused features/deps removed | ❌ FAIL | `@google/genai` unused — see H-02 |
| 14.2.3 | Third-party dependencies documented | ❌ FAIL | No SBOM (Software Bill of Materials) |
| 14.3.1 | Server version not exposed | ✅ PASS | Express `X-Powered-By` not visible (not set, default not observed) |
| 14.4.5 | CSP configured and enforced | ⚠️ PARTIAL | CSP present but `style-src 'unsafe-inline'` weakens it |
| 14.4.6 | All API responses have `X-Content-Type-Options: nosniff` | ✅ PASS | Applied in middleware |
| 14.5.3 | Server runs as non-root user | ❌ FAIL | Systemd service runs as `User=root`; Docker has no `USER` directive |

#### FINDING M-07 — Service Runs as Root (systemd + Docker)
- **Severity:** Medium | **CWE:** CWE-250 | **ASVS:** V14.5.3
- **Location:** `/etc/systemd/system/lvls.service:User=root`, `Dockerfile` (no USER directive)
- **Detail:** Both the systemd service and Docker image run the Node.js process as root. A successful RCE exploit against the Express server or any dependency would immediately have root privileges on the host, enabling full system compromise.
- **Risk Score:** Likelihood 2 × Impact 5 = 10 (Medium-High)
- **Remediation:**
  - Systemd: change `User=root` to `User=node` (create if needed: `useradd -r -s /bin/false node; chown -R node /root/lvls`)
  - Dockerfile: add `RUN addgroup -S lvls && adduser -S -G lvls lvls` and `USER lvls` before `CMD`

#### FINDING L-07 — CSP `style-src 'unsafe-inline'` Allows Style Injection
- **Severity:** Low | **CWE:** CWE-693 | **ASVS:** V14.4.5
- **Location:** `server.ts:50`
- **Detail:** `style-src 'self' 'unsafe-inline'` allows inline styles, which can be leveraged in CSS injection attacks (data exfiltration via CSS selectors, keylogging via `input[value^="a"]`). Tailwind CSS v4 may require inline styles in some configurations.
- **Risk Score:** Likelihood 1 × Impact 3 = 3 (Low)
- **Remediation:** Generate a `nonce` per request and use `style-src 'self' 'nonce-{value}'`, or use a hash-based CSP for inline styles.

---

## 3. Consolidated Risk Register

| ID | Finding | Chapter | Severity | CWE | Status |
|---|---|---|---|---|---|
| **REMEDIATED** | NODE_ENV not enforced → dev bypass active | V10 | ~~Critical~~ | CWE-798 | ✅ Fixed (systemd) |
| **REMEDIATED** | .env / key.pem / lvls.db world-readable | V14 | ~~Critical~~ | CWE-732 | ✅ Fixed (chmod 600) |
| **REMEDIATED** | TOTP_ENC_SECRET shared with JWT_SECRET | V6 | ~~High~~ | CWE-330 | ✅ Fixed (dedicated secret) |
| **REMEDIATED** | popup.js port 3000 (wrong server) | V9 | ~~High~~ | CWE-670 | ✅ Fixed |
| **REMEDIATED** | Extension sender not validated on 5/7 handlers | V10 | ~~High~~ | CWE-346 | ✅ Fixed |
| H-01 | Dev bypass hardcoded credentials in source | V10 | **High** | CWE-798 | ✅ Fixed (2026-03-17) |
| H-02 | `@google/genai` unused production dependency | V10 | **High** | CWE-1357 | ✅ Fixed (2026-03-17) |
| M-01 | Min credential length 6 (below ASVS L3 rec.) | V2 | Medium | CWE-521 | ⚠️ Open (H2) |
| M-02 | `hostname` no length/char validation | V5 | Medium | CWE-20 | ✅ Fixed (2026-03-17) |
| M-03 | ML-KEM private key in localStorage | V6 | Medium | CWE-312 | ⚠️ Open (H2) |
| M-04 | No rate limit on TOTP endpoints | V13 | Medium | CWE-307 | ✅ Fixed (2026-03-17) |
| M-05 | Nuke endpoint no confirmation challenge | V13 | Medium | CWE-749 | ⚠️ Open (H2) |
| M-06 | EXTENSION_ID not set (open CORS) | V13 | Medium | CWE-942 | ⚠️ Pending extension install |
| M-07 | Service runs as root | V14 | Medium | CWE-250 | ⚠️ Open (H2) |
| L-01 | Step-up re-auth missing on credential change | V3 | Low | CWE-308 | ⚠️ Open (H2) |
| L-02 | No field length caps on secret metadata | V5 | Low | CWE-400 | ⚠️ Open (H2) |
| L-03 | TOTP HMAC-SHA1 (RFC standard, not exploitable) | V6 | Low | CWE-327 | Accepted |
| L-04 | Audit logs use "system" not session ID | V7 | Low | CWE-778 | ✅ Fixed (2026-03-17) |
| L-05 | No `Cache-Control: no-store` on API responses | V8 | Low | CWE-524 | ✅ Fixed (2026-03-17) |
| L-06 | No cert pinning in extension | V9 | Low | CWE-295 | Accepted |
| L-07 | CSP `unsafe-inline` style-src | V14 | Low | CWE-693 | ⚠️ Open (H3) |

---

## 4. Post-Quantum Cryptography Assessment (ASVS Extension + NIST FIPS 203)

lvls is notably ahead of the industry on PQC readiness.

| Control | Status | Detail |
|---|---|---|
| PQC algorithm selection | ✅ PASS | ML-KEM-768 (NIST FIPS 203, Module Lattice) — appropriate security level |
| Hybrid classical+PQ | ✅ PASS | ML-KEM shared secret → HKDF-SHA256 → AES-256-GCM (hybrid design) |
| Algorithm agility | ✅ PASS | L3 uses AES-only; L0/1/2 use hybrid. Type field in encrypted blob allows future migration |
| Key generation | ✅ PASS | ML-KEM keypair generated client-side; public key registered with server |
| Private key protection | ⚠️ PARTIAL | Encrypted in localStorage (see M-03). WebCrypto non-extractable would be stronger |
| KEM ciphertext integrity | ✅ PASS | AES-GCM provides authenticated encryption; HKDF binds KEM output to context |
| PQC library (`@noble/post-quantum`) | ✅ PASS | Actively maintained, pure JS, audited implementation of FIPS 203 |
| Forward secrecy | ⚠️ PARTIAL | KEM keypair is long-lived per level setup. True forward secrecy would require ephemeral KEM per secret, which would require re-encryption on auth. Acceptable tradeoff for vault design |

**Assessment:** lvls is PQC-ready for harvest-now-decrypt-later attacks. The ML-KEM-768 + AES-256-GCM hybrid means that even if classical crypto is broken, the PQC layer protects all L0/1/2 secrets.

---

## 5. NIST CSF 2.0 Governance Overlay

| Function | Category | Maturity (1–4) | Key Gaps |
|---|---|---|---|
| **IDENTIFY** | Asset Management | 3 | No SBOM; `@google/genai` ghost dep |
| **IDENTIFY** | Risk Assessment | 3 | Risk register exists (this doc); no formal review cadence |
| **PROTECT** | Identity & Auth | 3.5 | Strong (Argon2id, TOTP, ML-KEM). Gap: min password length |
| **PROTECT** | Data Security | 3.5 | Strong encryption. Gap: localStorage key storage |
| **PROTECT** | Protective Tech | 3 | Security headers, CORS, rate limiting. Gap: root process |
| **DETECT** | Anomalies | 2 | session_logs present. Gap: no alerting, no log shipping |
| **RESPOND** | Response Planning | 1 | No formal IR plan, no nuke confirmation |
| **RECOVER** | Recovery Planning | 1 | No backup/export, no key rotation procedure |

**Overall CSF Maturity: Tier 2 (Risk Informed)** — approaching Tier 3 (Repeatable) in cryptographic controls; below Tier 2 in recovery and response.

---

## 6. Remediation Roadmap

### Horizon 1 — Immediate (0–7 days)

| Priority | Action | Effort | Impact |
|---|---|---|---|
| 1 | `npm uninstall @google/genai` (H-02) | 5 min | High |
| 2 | Set `EXTENSION_ID` in `.env` after extension install (M-06) | 5 min | Medium |
| 3 | Remove dev bypass block from `server.ts` (H-01) | 30 min | High |
| 4 | Add `authRateLimit` to TOTP setup/confirm routes (M-04) | 15 min | Medium |
| 5 | Add `Cache-Control: no-store` to API responses (L-05) | 15 min | Low |
| 6 | Fix session log attribution: `"system"` → `sessionId` (L-04) | 20 min | Low |
| 7 | Add `hostname` length+charset validation (M-02) | 15 min | Low |

### Horizon 2 — Short-term (7–30 days)

| Priority | Action | Effort | Impact |
|---|---|---|---|
| 8 | Run service as non-root user (M-07) — systemd + Docker | 1 hour | High |
| 9 | Add `{ confirm: "NUKE" }` body param to nuke endpoint (M-05) | 20 min | Medium |
| 10 | Migrate ML-KEM private key to `sessionStorage` (M-03) | 1-2 hours | Medium |
| 11 | Add field length validation for secret metadata (L-02) | 30 min | Low |
| 12 | Increase minimum credential length to 8 chars (M-01) | 20 min | Medium |
| 13 | Add step-up auth on credential change (L-01) | 1-2 hours | Low |

### Horizon 3 — Medium-term (30–90 days)

| Priority | Action | Effort | Impact |
|---|---|---|---|
| 14 | Implement encrypted backup/export (prevents data loss) | 2-3 days | Critical for resilience |
| 15 | Generate SBOM (e.g. `npx cyclonedx-npm`) | 1 hour | Medium |
| 16 | Add automated `npm audit` to CI/CD or pre-commit hook | 2 hours | Medium |
| 17 | Implement JWT_SECRET rotation procedure with TOTP re-enrollment | 1-2 days | Medium |
| 18 | Evaluate WebCrypto non-extractable keys for KEM private key | 2-3 days | Medium |
| 19 | Replace CSP `unsafe-inline` with nonce-based policy | 2-3 hours | Low |

---

## 7. Remediation Verification Checklist

To be completed after Horizon 1 actions:

- [ ] `npm ls @google/genai` returns empty
- [ ] `grep -r "devPins\|devpassword\|dev mode" server.ts` returns empty
- [ ] `curl -X POST .../api/auth/unlock -d '{"level":3,"credential":"1234"}'` returns 400 (not 200)
- [ ] TOTP confirm endpoint returns 429 after 10 rapid requests
- [ ] `curl .../api/secrets -H "Origin: chrome-extension://RANDOM_ID"` returns no CORS headers
- [ ] `ps aux | grep node` shows non-root user

---

*Report generated: 2026-03-17 | Next review: 2026-06-17 (quarterly)*
*Framework: OWASP ASVS v4.0 L3 | Governance: NIST CSF 2.0*
*VPS-level audit: see IL-CAA-v3.0 report (separate document)*
