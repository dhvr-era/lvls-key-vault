/**
 * lvls Crypto Library
 * Client-side encryption using Web Crypto API (AES-256-GCM)
 * and @noble/post-quantum (ML-KEM-768) for Lvl 0/1/2 at-rest protection.
 */

// ---------- Safe base64 encoding (avoids spread-operator stack overflow on large arrays) ----------
function u8ToB64(arr: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
  return btoa(binary);
}

// ---------- AES-256-GCM keyed from passphrase (PBKDF2) — Lvl 3 / PIN ----------

export async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt.buffer as ArrayBuffer, iterations: 310000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptAES(plaintext: string, passphrase: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext)
  );
  // Pack: salt(16) + iv(12) + ciphertext → base64
  const combined = new Uint8Array(16 + 12 + ciphertext.byteLength);
  combined.set(salt, 0);
  combined.set(iv, 16);
  combined.set(new Uint8Array(ciphertext), 28);
  return u8ToB64(combined);
}

export async function decryptAES(encryptedB64: string, passphrase: string): Promise<string> {
  const combined = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ciphertext = combined.slice(28);
  const key = await deriveKey(passphrase, salt);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}

// ---------- AES-256-GCM keyed from raw bytes via HKDF — for ML-KEM hybrid ----------
// Uses HKDF (not PBKDF2) because the input material is already high-entropy (256-bit KEM secret).

async function deriveKeyHKDF(secretBytes: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey("raw", secretBytes, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt.buffer as ArrayBuffer,
      info: new TextEncoder().encode("lvls-v1-aes-gcm-256"),
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptAESBytes(plaintext: string, secretBytes: Uint8Array): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyHKDF(secretBytes, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext)
  );
  const combined = new Uint8Array(16 + 12 + ciphertext.byteLength);
  combined.set(salt, 0);
  combined.set(iv, 16);
  combined.set(new Uint8Array(ciphertext), 28);
  return u8ToB64(combined);
}

async function decryptAESBytes(encryptedB64: string, secretBytes: Uint8Array): Promise<string> {
  const combined = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ciphertext = combined.slice(28);
  const key = await deriveKeyHKDF(secretBytes, salt);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}

// ---------- ML-KEM-768 (PQC, for Lvl 0/1/2 at rest) ----------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let mlKem: any = null;

async function getMlKem() {
  if (!mlKem) {
    mlKem = await import("@noble/post-quantum/ml-kem.js");
  }
  return mlKem;
}

export interface KemKeyPair {
  publicKey: string;   // base64
  privateKey: string;  // base64
}

export async function generateKemKeyPair(): Promise<KemKeyPair> {
  const { ml_kem768 } = await getMlKem();
  const seed = crypto.getRandomValues(new Uint8Array(64));
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return {
    publicKey: u8ToB64(publicKey),
    privateKey: u8ToB64(secretKey),
  };
}

/**
 * Derive a deterministic ML-KEM-768 keypair from a TOTP seed string.
 * Uses HKDF-SHA256 to expand the seed into 64 bytes for ML-KEM keygen.
 * This allows machines to regenerate their keypair from the seed without storing keys.
 */
export async function deriveKemKeypairFromSeed(totpSeed: string): Promise<KemKeyPair> {
  const { ml_kem768 } = await getMlKem();
  const enc = new TextEncoder();
  // HKDF: expand seed → 64 bytes deterministically
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(totpSeed), "HKDF", false, ["deriveBits"]);
  const derived = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode("lvls-kem-seed-v1"), info: enc.encode("ml-kem-768-keypair") },
    keyMaterial,
    512 // 64 bytes
  );
  const seed = new Uint8Array(derived);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return {
    publicKey: u8ToB64(publicKey),
    privateKey: u8ToB64(secretKey),
  };
}

/**
 * Decrypt an offline token issued by the lvls server.
 * The token was encrypted with this machine's ML-KEM public key.
 * Returns the decrypted payload as a parsed object.
 */
export async function decryptOfflineToken(token: {
  kem_ciphertext: string;
  aes_ciphertext: string;
  server_signature: string;
  server_ed25519_public_key: string;
}, privateKeyB64: string): Promise<{
  secrets: Array<{ name: string; encrypted_value: string; classification: string }>;
  vault_id: string; machine_id: string; expires_at: number;
}> {
  // 1. Verify server signature over kemCiphertext + aesCiphertext
  const sigInput = new TextEncoder().encode(token.kem_ciphertext + "." + token.aes_ciphertext);
  const sig = Uint8Array.from(atob(token.server_signature), c => c.charCodeAt(0));
  const serverPub = Uint8Array.from(atob(token.server_ed25519_public_key), c => c.charCodeAt(0));
  // Ed25519 verify via Web Crypto (supported in modern browsers)
  const pubKey = await crypto.subtle.importKey("raw", serverPub, { name: "Ed25519" }, false, ["verify"]);
  const valid = await crypto.subtle.verify({ name: "Ed25519" }, pubKey, sig, sigInput);
  if (!valid) throw new Error("Offline token signature verification failed");

  // 2. ML-KEM decapsulate → shared secret
  const sharedSecret = await kemDecapsulate(privateKeyB64, token.kem_ciphertext);

  // 3. HKDF shared secret → AES key
  const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode("lvls-offline-token-v1"), info: new TextEncoder().encode("") },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  // 4. AES-GCM decrypt: iv(12) + tag(16) + ciphertext
  const packed = Uint8Array.from(atob(token.aes_ciphertext), c => c.charCodeAt(0));
  const iv = packed.slice(0, 12);
  const tag = packed.slice(12, 28);
  const ciphertext = packed.slice(28);
  // Re-pack for Web Crypto (it expects tag appended to ciphertext)
  const ciphertextWithTag = new Uint8Array(ciphertext.length + tag.length);
  ciphertextWithTag.set(ciphertext);
  ciphertextWithTag.set(tag, ciphertext.length);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertextWithTag);

  return JSON.parse(new TextDecoder().decode(plaintext));
}

export async function kemEncapsulate(publicKeyB64: string): Promise<{ ciphertext: string; sharedSecret: Uint8Array }> {
  const { ml_kem768 } = await getMlKem();
  const publicKey = Uint8Array.from(atob(publicKeyB64), c => c.charCodeAt(0));
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey, seed);
  return {
    ciphertext: u8ToB64(cipherText),
    sharedSecret: new Uint8Array(sharedSecret), // raw bytes, NOT base64 — avoids the slice bug
  };
}

export async function kemDecapsulate(privateKeyB64: string, ciphertextB64: string): Promise<Uint8Array> {
  const { ml_kem768 } = await getMlKem();
  const secretKey = Uint8Array.from(atob(privateKeyB64), c => c.charCodeAt(0));
  const cipherText = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
  const sharedSecret = ml_kem768.decapsulate(cipherText, secretKey);
  return new Uint8Array(sharedSecret); // raw 32 bytes = full 256 bits
}

// ---------- Hybrid Encryption: ML-KEM-768 + AES-256-GCM (HKDF) ----------
// Correct: sharedSecret stays as raw bytes throughout — no base64 truncation bug.

export interface HybridEncrypted {
  kemCiphertext: string;   // ML-KEM encapsulated key (base64)
  aesCiphertext: string;   // AES-GCM encrypted value (base64), keyed via HKDF from KEM secret
}

export async function hybridEncrypt(plaintext: string, publicKeyB64: string): Promise<HybridEncrypted> {
  const { ciphertext: kemCiphertext, sharedSecret } = await kemEncapsulate(publicKeyB64);
  // Full 32 raw bytes → HKDF → AES-256-GCM key. No truncation.
  const aesCiphertext = await encryptAESBytes(plaintext, sharedSecret);
  return { kemCiphertext, aesCiphertext };
}

export async function hybridDecrypt(encrypted: HybridEncrypted, privateKeyB64: string): Promise<string> {
  const sharedSecret = await kemDecapsulate(privateKeyB64, encrypted.kemCiphertext);
  return decryptAESBytes(encrypted.aesCiphertext, sharedSecret);
}

// ---------- Top-level: encrypt/decrypt for a given level ----------

/**
 * Lvl 0/1/2: hybrid ML-KEM-768 + AES-256-GCM (requires publicKeyB64 from server).
 * Lvl 3:     AES-256-GCM keyed from PIN via PBKDF2 (no asymmetric key needed).
 */
export async function encryptForLevel(
  plaintext: string,
  level: number,
  credential: string,
  publicKeyB64?: string
): Promise<string> {
  if (level < 3 && publicKeyB64) {
    const hybrid = await hybridEncrypt(plaintext, publicKeyB64);
    return JSON.stringify({ type: "hybrid", ...hybrid });
  }
  // Lvl 3 or fallback (no KEM key available): AES-GCM keyed from credential
  const ciphertext = await encryptAES(plaintext, credential);
  return JSON.stringify({ type: "aes", ciphertext });
}

export async function decryptForLevel(
  encryptedJson: string,
  credential: string,
  privateKeyB64?: string
): Promise<string> {
  const parsed = JSON.parse(encryptedJson);
  if (parsed.type === "hybrid" && privateKeyB64) {
    return hybridDecrypt(
      { kemCiphertext: parsed.kemCiphertext, aesCiphertext: parsed.aesCiphertext },
      privateKeyB64
    );
  }
  if (parsed.type === "aes") {
    return decryptAES(parsed.ciphertext, credential);
  }
  throw new Error(`Unknown encryption type: ${parsed.type ?? "none"}`);
}
