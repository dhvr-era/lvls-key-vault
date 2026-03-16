// background.js — lvls Key Vault service worker
// Manages auth token and proxies API calls to avoid CORS issues from content scripts

// Auto-detect HTTPS or HTTP — prefers HTTPS if TLS certs are present on server
let LVLS_SERVER = "https://127.0.0.1:3000";
async function detectServer() {
  try {
    const res = await fetch("https://127.0.0.1:3000/api/health", { signal: AbortSignal.timeout(1500) });
    if (res.ok) { LVLS_SERVER = "https://127.0.0.1:3000"; return; }
  } catch {}
  try {
    const res = await fetch("http://127.0.0.1:3000/api/health", { signal: AbortSignal.timeout(1500) });
    if (res.ok) { LVLS_SERVER = "http://127.0.0.1:3000"; return; }
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

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  handleMessage(msg).then(sendResponse).catch(err => sendResponse({ error: err.message }));
  return true; // keep message channel open for async response
});

async function handleMessage(msg) {
  switch (msg.type) {

    case "UNLOCK": {
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
        return { success: true, devMode: data.devMode };
      }
      return { success: false, error: data.error, totpRequired: data.totpRequired };
    }

    case "GET_TOKEN": {
      const token = await getToken();
      return { token };
    }

    case "LOGOUT": {
      await clearToken();
      return { success: true };
    }

    case "GET_SECRETS_BY_DOMAIN": {
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
      const res = await fetch(`${LVLS_SERVER}/api/auth/status`).catch(() => null);
      if (!res) return { configured: {} };
      return await res.json();
    }

    case "OPEN_FILL_POPUP": {
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
