// content.js — detects login forms and injects lvls fill button

(function () {
  // M3: Closure-scoped flag — not detectable by page scripts
  let _injected = false;
  if (_injected) return;
  _injected = true;
  // M3: WeakMap instead of DOM property to avoid page script access
  const usernameFieldMap = new WeakMap();

  const BADGE_CLASS = "lvls-fill-badge";
  const STYLE_ID = "lvls-style";

  function injectStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const s = document.createElement("style");
    s.id = STYLE_ID;
    s.textContent = `
      .${BADGE_CLASS} {
        position: absolute;
        right: 6px;
        top: 50%;
        transform: translateY(-50%);
        background: #09090b;
        border: 1px solid #10b981;
        color: #10b981;
        font-family: monospace;
        font-size: 10px;
        font-weight: bold;
        padding: 2px 6px;
        border-radius: 4px;
        cursor: pointer;
        z-index: 999999;
        user-select: none;
        line-height: 1.4;
        white-space: nowrap;
        transition: background 0.15s;
      }
      .${BADGE_CLASS}:hover {
        background: #10b981;
        color: #09090b;
      }
      .lvls-field-wrap {
        position: relative !important;
        display: inline-block !important;
        width: 100%;
      }
    `;
    document.head.appendChild(s);
  }

  function findUsernameField(passwordInput) {
    // Walk backwards through the form's inputs to find text/email field
    const form = passwordInput.closest("form");
    const inputs = form
      ? Array.from(form.querySelectorAll("input"))
      : Array.from(document.querySelectorAll("input"));
    const idx = inputs.indexOf(passwordInput);
    for (let i = idx - 1; i >= 0; i--) {
      const t = inputs[i].type.toLowerCase();
      if (t === "text" || t === "email" || t === "tel") return inputs[i];
    }
    return null;
  }

  function addBadge(passwordInput) {
    if (passwordInput.dataset.lvlsInjected) return;
    passwordInput.dataset.lvlsInjected = "1";

    // Wrap the input in a relative container
    const parent = passwordInput.parentElement;
    if (!parent) return;

    const wrap = document.createElement("div");
    wrap.className = "lvls-field-wrap";
    parent.insertBefore(wrap, passwordInput);
    wrap.appendChild(passwordInput);

    const badge = document.createElement("button");
    badge.className = BADGE_CLASS;
    badge.textContent = "lvl";
    badge.type = "button";
    badge.title = "Fill with lvls Key Vault";
    wrap.appendChild(badge);

    badge.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      // Store which field was clicked, then open the popup
      chrome.runtime.sendMessage({
        type: "BADGE_CLICKED",
        hostname: window.location.hostname,
      });
      // Open extension popup via a new window (MV3 limitation workaround)
      chrome.runtime.sendMessage({ type: "OPEN_FILL_POPUP", hostname: window.location.hostname });
    });

    usernameFieldMap.set(passwordInput, findUsernameField(passwordInput));
  }

  function scanAndInject() {
    injectStyle();
    const passwords = document.querySelectorAll("input[type='password']:not([data-lvls-injected])");
    passwords.forEach(addBadge);
  }

  // Initial scan
  scanAndInject();

  // M4: Throttled MutationObserver — debounced to avoid performance issues on heavy SPAs
  let _scanTimer = null;
  const observer = new MutationObserver(() => {
    if (_scanTimer) return;
    _scanTimer = setTimeout(() => { _scanTimer = null; scanAndInject(); }, 300);
  });
  observer.observe(document.body, { childList: true, subtree: true });

  // Listen for fill messages from background/popup
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type !== "FILL_FORM") return;

    const passwords = document.querySelectorAll("input[type='password']");
    if (!passwords.length) return;

    const targetPassword = passwords[passwords.length - 1];
    const usernameField = usernameFieldMap.get(targetPassword) || findUsernameField(targetPassword);

    if (usernameField && msg.username) {
      nativeInputSet(usernameField, msg.username);
    }
    if (msg.password) {
      nativeInputSet(targetPassword, msg.password);
    }
  });

  // React-compatible field fill (triggers React's synthetic onChange)
  function nativeInputSet(el, value) {
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, "value"
    )?.set;
    if (nativeInputValueSetter) {
      nativeInputValueSetter.call(el, value);
    } else {
      el.value = value;
    }
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.focus();
  }
})();
