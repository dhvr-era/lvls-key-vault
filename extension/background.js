// background.js — lvls Key Vault service worker
// Manages auth token and proxies API calls to avoid CORS issues from content scripts

// Auto-detect HTTPS or HTTP — prefers HTTPS if TLS certs are present on server
let LVLS_SERVER = "https://127.0.0.1:5000";
async function detectServer() {
  try {
    const res = await fetch("https://127.0.0.1:5000/api/health", { signal: AbortSignal.timeout(1500) });
    if (res.ok) { LVLS_SERVER = "https://127.0.0.1:5000"; return; }
  } catch {}
  try {
    const res = await fetch("http://127.0.0.1:5000/api/health", { signal: AbortSignal.timeout(1500) });
    if (res.ok) { LVLS_SERVER = "http://127.0.0.1:5000"; return; }
  } catch {}
}
detectServer(); // runs once on service worker startup

// Store token in session storage (cleared when browser closes)
async function getToken() {
  const data = await chrome.storage.session.get("lvls_token");
  return data.lvls_token || null;
}

async function setToken(token) {
  await chrome.storage.session.set({ lvls_token: token });
}

async function clearToken() {
  await chrome.storage.session.remove("lvls_token");
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender).then(sendResponse).catch(err => sendResponse({ error: err.message }));
  return true; // keep message channel open for async response
});

// Sender is the extension itself (popup, options page, etc.)
function isExtensionSender(sender) {
  return sender.id === chrome.runtime.id && !sender.tab;
}

// Sender is an injected content script running in a real tab
function isContentScript(sender) {
  return sender.id === chrome.runtime.id && !!(sender.tab && sender.tab.id);
}

// Trusted = extension itself OR injected content script
function isTrustedSender(sender) {
  return isExtensionSender(sender) || isContentScript(sender);
}

async function handleMessage(msg, sender) {
  switch (msg.type) {

    case "UNLOCK": {
      // Only the extension popup should be able to trigger an auth flow
      if (!isExtensionSender(sender)) return { error: "Untrusted sender" };
      const body = { level: msg.level, credential: msg.credential };
      if (msg.totp) body.totp = msg.totp;
      const res = await fetch(`${LVLS_SERVER}/api/auth/unlock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (res.ok && data.token) {
        await setToken(data.token);
        return { success: true };
      }
      return { success: false, error: data.error, totpRequired: data.totpRequired };
    }

    case "GET_TOKEN": {
      if (!isExtensionSender(sender)) return { error: "Untrusted sender" };
      const token = await getToken();
      return { token };
    }

    case "LOGOUT": {
      if (!isExtensionSender(sender)) return { error: "Untrusted sender" };
      await clearToken();
      return { success: true };
    }

    case "GET_SECRETS_BY_DOMAIN": {
      if (!isTrustedSender(sender)) return { error: "Untrusted sender" };
      const token = await getToken();
      if (!token) return { error: "Not authenticated" };
      const res = await fetch(
        `${LVLS_SERVER}/api/secrets/by-domain?hostname=${encodeURIComponent(msg.hostname)}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!res.ok) {
        if (res.status === 401) await clearToken();
        return { error: "Auth expired" };
      }
      return { secrets: await res.json() };
    }

    case "GET_ALL_SECRETS": {
      if (!isExtensionSender(sender)) return { error: "Untrusted sender" };
      const token = await getToken();
      if (!token) return { error: "Not authenticated" };
      const res = await fetch(`${LVLS_SERVER}/api/secrets`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        if (res.status === 401) await clearToken();
        return { error: "Auth expired" };
      }
      return { secrets: await res.json() };
    }

    case "GET_AUTH_STATUS": {
      if (!isTrustedSender(sender)) return { error: "Untrusted sender" };
      const res = await fetch(`${LVLS_SERVER}/api/auth/status`).catch(() => null);
      if (!res) return { configured: {} };
      return await res.json();
    }

    case "OPEN_FILL_POPUP": {
      if (!isContentScript(sender)) return { error: "Untrusted sender" };
      // Open the extension popup as a window when badge is clicked in the page
      const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
      await chrome.windows.create({
        url: chrome.runtime.getURL("popup.html"),
        type: "popup",
        width: 380,
        height: 560,
        focused: true,
      });
      return { success: true };
    }

    case "FILL_IN_PAGE": {
      if (!isExtensionSender(sender)) return { error: "Untrusted sender" };
      // Ask the active tab's content script to fill the form
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return { error: "No active tab" };
      await chrome.tabs.sendMessage(tab.id, {
        type: "FILL_FORM",
        username: msg.username,
        password: msg.password,
      });
      return { success: true };
    }

    default:
      return { error: "Unknown message type" };
  }
}
