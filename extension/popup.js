// popup.js — lvls Key Vault extension popup

// Auto-detect server protocol (HTTPS preferred)
async function detectBaseUrl() {
  try {
    const r = await fetch("https://127.0.0.1:5000/api/health", { signal: AbortSignal.timeout(1200) });
    if (r.ok) return "https://127.0.0.1:5000";
  } catch {}
  return "http://127.0.0.1:5000";
}

let selectedLevel = 3;
let currentHostname = "";
let allSecrets = [];
let showingAll = false;

const $ = id => document.getElementById(id);

// ---------- Init ----------
(async function init() {
  // Get current tab hostname
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) {
    try {
      currentHostname = new URL(tab.url).hostname;
      $("domain-label").textContent = currentHostname;
    } catch { $("domain-label").textContent = "—"; }
  }

  // Check if already authenticated
  const { token } = await sendMessage({ type: "GET_TOKEN" });
  if (token) {
    await showSecrets();
  }

  // Set up level buttons
  $("level-btns").querySelectorAll(".level-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      $("level-btns").querySelectorAll(".level-btn").forEach(b => b.classList.remove("selected"));
      btn.classList.add("selected");
      selectedLevel = parseInt(btn.dataset.level);
    });
  });

  // Unlock button
  $("unlock-btn").addEventListener("click", handleUnlock);
  $("credential-input").addEventListener("keydown", e => { if (e.key === "Enter") handleUnlock(); });
  $("totp-input").addEventListener("keydown", e => { if (e.key === "Enter") handleUnlock(); });

  // Show all button
  $("show-all-btn").addEventListener("click", async () => {
    showingAll = !showingAll;
    $("show-all-btn").textContent = showingAll ? "Domain only" : "Show all";
    renderSecrets(showingAll ? allSecrets : filterByDomain(allSecrets));
  });

  // Logout button
  $("logout-btn").addEventListener("click", async () => {
    await sendMessage({ type: "LOGOUT" });
    $("auth-section").style.display = "block";
    $("secrets-section").style.display = "none";
    $("status-dot").classList.remove("authed");
    $("credential-input").value = "";
    $("totp-input").value = "";
  });
})();

// ---------- Unlock ----------
async function handleUnlock() {
  const credInput = $("credential-input");
  const credential = credInput.value.trim();
  const totp = $("totp-input").value.trim();
  if (!credential) return showError("Enter your credential");

  setLoading(true);
  try {
    // M5: Call server directly — credential stays in popup JS context only, never enters message bus
    const body = { level: selectedLevel, credential };
    if (totp) body.totp = totp;
    const baseUrl = await detectBaseUrl();
    const res = await fetch(`${baseUrl}/api/auth/unlock`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    credInput.value = ""; // clear immediately after use
    if (res.ok && data.token) {
      await chrome.storage.session.set({ lvls_token: data.token });
      hideError();
      await showSecrets();
    } else {
      showError(data.error || "Authentication failed");
    }
  } catch (err) {
    showError("Cannot reach lvls server");
  }
  setLoading(false);
}

// ---------- Show secrets after auth ----------
async function showSecrets() {
  $("status-dot").classList.add("authed");

  // Fetch all secrets
  const result = await sendMessage({ type: "GET_ALL_SECRETS" });
  if (result.error) {
    // Token expired
    $("auth-section").style.display = "block";
    $("secrets-section").style.display = "none";
    $("status-dot").classList.remove("authed");
    showError(result.error);
    return;
  }

  allSecrets = result.secrets || [];
  $("auth-section").style.display = "none";
  $("secrets-section").style.display = "block";

  const domain = filterByDomain(allSecrets);
  renderSecrets(domain);
  $("secrets-label").textContent = domain.length > 0
    ? `${domain.length} credential${domain.length !== 1 ? "s" : ""} for ${currentHostname}`
    : `No matches — showing all`;

  if (domain.length === 0) {
    showingAll = true;
    $("show-all-btn").textContent = "Domain only";
    renderSecrets(allSecrets);
  }
}

// ---------- Filter secrets ----------
function filterByDomain(secrets) {
  if (!currentHostname) return secrets;
  const h = currentHostname.toLowerCase();
  return secrets.filter(s =>
    (s.url && s.url.toLowerCase().includes(h)) ||
    s.name.toLowerCase().includes(h)
  );
}

// ---------- Render ----------
function renderSecrets(secrets) {
  const list = $("secrets-list");
  list.innerHTML = "";

  if (!secrets.length) {
    list.innerHTML = `<div class="empty">No credentials found</div>`;
    return;
  }

  // Separate password-type secrets from others
  const fillable = secrets.filter(s => ["password", "pin", "api_key", "oauth_token"].includes(s.secret_type));
  const others = secrets.filter(s => !["password", "pin", "api_key", "oauth_token"].includes(s.secret_type));

  [...fillable, ...others].forEach(secret => {
    const card = document.createElement("div");
    card.className = "secret-card";
    const badgeClass = `badge l${secret.level}`;
    const isFillable = fillable.includes(secret);

    card.innerHTML = `
      <div class="secret-name">${esc(secret.name)}</div>
      <div class="secret-meta">
        <span class="${badgeClass}">L${secret.level}</span>
        <span>${esc(secret.secret_type?.replace(/_/g, " ") || "secret")}</span>
        ${secret.username ? `<span>👤 ${esc(secret.username)}</span>` : ""}
        ${secret.url ? `<span>🌐 ${esc(trimUrl(secret.url))}</span>` : ""}
      </div>
      ${isFillable ? `<div class="actions">
        <button class="btn-primary btn-sm fill-btn" data-id="${esc(secret.id)}" type="button">Fill password</button>
        ${secret.username ? `<button class="btn-ghost btn-sm fill-user-btn" data-id="${esc(secret.id)}" type="button">Fill username</button>` : ""}
      </div>` : ""}
    `;

    // Fill password button
    const fillBtn = card.querySelector(".fill-btn");
    if (fillBtn) {
      fillBtn.addEventListener("click", async (e) => {
        e.stopPropagation();
        await fillSecret(secret, "both");
      });
    }

    // Fill username only button
    const fillUserBtn = card.querySelector(".fill-user-btn");
    if (fillUserBtn) {
      fillUserBtn.addEventListener("click", async (e) => {
        e.stopPropagation();
        await fillSecret(secret, "username");
      });
    }

    list.appendChild(card);
  });
}

// ---------- Fill ----------
async function fillSecret(secret, mode) {
  // We need to decrypt the password client-side
  // The encrypted_value is a JSON blob with type aes or hybrid
  // For the extension, we ask the user for their credential again to decrypt
  // Since we stored it in session during unlock — we'll use a simple approach:
  // Show a modal asking for credential to decrypt, then fill

  // For now, to keep it simple: we pass the encrypted value to the background
  // which can't decrypt it (no key). So we show a fill-confirm modal with
  // a credential prompt for decryption.
  showFillModal(secret, mode);
}

function showFillModal(secret, mode) {
  const list = $("secrets-list");
  list.innerHTML = `
    <div class="fill-confirm">
      <div class="name">${esc(secret.name)}</div>
      ${secret.username ? `<div class="fields"><span><span style="color:#71717a">User:</span> <span class="val">${esc(secret.username)}</span></span></div>` : ""}
      <div style="margin-top:8px;">
        <label>Enter your level ${secret.level} passphrase to decrypt</label>
        <input type="password" id="decrypt-cred" placeholder="Your credential…" style="margin-top:4px;" />
        <div id="decrypt-error" class="error" style="display:none;"></div>
        <div class="actions" style="margin-top:8px;">
          <button class="btn-primary" id="decrypt-fill-btn" type="button">Decrypt &amp; Fill</button>
          <button class="btn-ghost" id="decrypt-cancel-btn" type="button">Cancel</button>
        </div>
      </div>
    </div>
  `;

  $("decrypt-fill-btn").addEventListener("click", async () => {
    const cred = $("decrypt-cred").value;
    if (!cred) return;

    try {
      const plaintext = await decryptSecret(secret.encrypted_value, cred);
      const username = mode !== "both" && mode !== "username" ? null : secret.username;
      const password = mode === "username" ? null : plaintext;

      await sendMessage({ type: "FILL_IN_PAGE", username, password });
      window.close();
    } catch (err) {
      $("decrypt-error").style.display = "block";
      $("decrypt-error").textContent = "Decryption failed — check your credential";
    }
  });

  $("decrypt-cancel-btn").addEventListener("click", () => {
    renderSecrets(showingAll ? allSecrets : filterByDomain(allSecrets));
  });
}

// ---------- Client-side decryption (mirrors src/lib/crypto.ts) ----------
async function decryptSecret(encryptedJson, passphrase) {
  const parsed = JSON.parse(encryptedJson);
  if (parsed.type === "aes") {
    return decryptAES(parsed.ciphertext, passphrase);
  }
  // Legacy fallback
  try { return atob(encryptedJson); } catch { return encryptedJson; }
}

async function deriveKey(passphrase, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt.buffer, iterations: 310000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function decryptAES(encryptedB64, passphrase) {
  const combined = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ciphertext = combined.slice(28);
  const key = await deriveKey(passphrase, salt);
  const dec = new TextDecoder();
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return dec.decode(plaintext);
}

// ---------- Helpers ----------
function sendMessage(msg) {
  return chrome.runtime.sendMessage(msg);
}

function showError(msg) {
  const el = $("auth-error");
  if (!el) return;
  el.style.display = "block";
  el.textContent = msg;
}

function hideError() {
  const el = $("auth-error");
  if (el) el.style.display = "none";
}

function setLoading(on) {
  const btn = $("unlock-btn");
  btn.disabled = on;
  btn.innerHTML = on ? '<span class="spinner"></span>' : "Unlock Vault";
}

function esc(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function trimUrl(url) {
  return url.replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
}
