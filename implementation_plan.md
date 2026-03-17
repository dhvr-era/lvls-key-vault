# SSDLC Security Audit Plan

This plan documents the findings of the comprehensive code check using a Secure Software Development Life Cycle (SSDLC) framework approach (incorporating OWASP SAMM and NIST SSDF principles) to scrutinize all edges and provide proposed fixes.

## 1. Findings & Vulnerabilities

### Finding 1: IP Spoofing bypasses Rate Limiting (High Severity)
**Description:** `server.ts` uses `req.ip` for rate-limiting. Without `app.set('trust proxy', 1)`, if the backend runs behind a reverse proxy (like Nginx, Caddy, or Tailscale), `req.ip` will erroneously register as the proxy's IP. This can lead to all users sharing the same rate limit bucket (DoS) or an attacker bypassing rate limits entirely by spoofing `X-Forwarded-For`.
**Impact:** Denial of Service or Credential Brute-force.
**Fix:** Add `app.set('trust proxy', 1 /* or specific subnet */);` to `server.ts`. 

### Finding 2: TOTP Replay Vulnerability (Medium Severity)
**Description:** The `/api/auth/unlock` endpoint verifies TOTP using `verifyTotp` which accepts codes within a ±1 clock drift window (up to 90 seconds total validity). However, there is no mechanism to track and reject *already used* TOTP codes within that time window.
**Impact:** An attacker who intercepts the network traffic or shoulder-surfs an active TOTP login can replay that TOTP code immediately to authenticate another session concurrently.
**Fix:** Introduce a `used_totps` table or an in-memory cache to block codes that have already been validated until they expire.

### Finding 3: Missing Content Security Policy (CSP) (Medium Severity)
**Description:** `server.ts` implements several HTTP security headers, but completely omits the `Content-Security-Policy` (CSP). Because the architecture relies on local storage for holding ML-KEM private keys and JWT tokens, an XSS vulnerability would be catastrophic.
**Impact:** A successful XSS attack could completely exfiltrate the encrypted KEM keys and JWT session tokens, leading to vault compromise.
**Fix:** Add a strict CSP header in `server.ts`: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' chrome-extension: moz-extension:;`

### Finding 4: Inadequate Extension Origin Validation (Medium Severity)
**Description:** In `extension/background.js`, the `OPEN_FILL_POPUP` handler opens the extension popup but does not validate if the caller is a trusted content script.
**Impact:** A malicious webpage that somehow gains the extension ID could attempt to send messages directly to the background script, potentially spamming popup windows.
**Fix:** Validate `sender.tab` and `sender.origin` in the `background.js` message listener to ensure messages only originate from injected content scripts on valid tabs.

### Finding 5: KEM Key Injection into Extension (Informational / Feature Gap)
**Description:** The extension `popup.js` currently cannot decrypt Lvl 0/1/2 secrets because it lacks the ML-KEM-768 logic and the encrypted ML-KEM private key, which lives securely in `localStorage` of the web app (`App.tsx`).
**Impact:** Legitimate users cannot auto-fill high-clearance secrets from the extension.
**Fix:** Out of scope for this immediate security patch, but the eventual solution involves adding `externally_connectable` to the extension manifest, and having the web app securely message the decrypted KEM private keys to the extension's `chrome.storage.session` while the web session is unlocked.

## User Review Required
> [!IMPORTANT]
> The SSDLC phase audit is complete. The implementation below will immediately fix the **Rate Limiting bypass (trust proxy)**, **TOTP Replay attack**, **Missing CSP header**, and the **Extension Origin Validation**. Shall I proceed with EXECUTION to apply these patches?

## Proposed Changes

### [Backend API]
#### [MODIFY] server.ts
- Add `app.set("trust proxy", 1);` for secure IP extraction.
- Add `Content-Security-Policy` header in the security headers middleware.
- Create a `used_totps` table alongside the DB init statements.
- In `/api/auth/unlock`, query `used_totps` to ensure the TOTP token isn't being reused, and insert the token upon successful auth.
- Clean up the `used_totps` table periodically inside the existing hourly interval.

### [Browser Extension]
#### [MODIFY] extension/background.js
- In the `chrome.runtime.onMessage.addListener`, inspect `sender.tab` and `sender.origin` for the `OPEN_FILL_POPUP` and `FILL_IN_PAGE` cases to prevent a malicious webpage from impersonating the content script.

## Verification Plan

### Automated/Manual Verification
1. Run `npm run dev` and ensure the application boots.
2. Observe HTTP headers on `/` and `/api/health` to confirm CSP is active and hasn't broken Vite's hot reloading or the Extension CORS.
3. Successfully log in with a credential and confirm no regressions.
4. If TOTP is enabled, try logging in twice in a row very quickly with the *same* 6-digit TOTP code. It should be rejected the second time as a replayed code.
