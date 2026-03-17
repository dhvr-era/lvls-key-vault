import React, { useState, useEffect, useRef } from "react";
import {
  Shield,
  Lock,
  Activity,
  Settings,
  Key,
  Plus,
  Trash2,
  Search,
  FileText,
  AlertTriangle,
  Unlock,
  Eye,
  EyeOff,
  Fingerprint,
  Smartphone,
  Hexagon,
  Pencil,
  X,
  Check,
  RefreshCw,
  Copy,
  Globe,
  User,
  Folder,
  FolderOpen,
} from "lucide-react";

// ---------- Helpers ----------
function generatePassword(length = 20): string {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).catch(() => {});
}
import { motion, AnimatePresence } from "motion/react";
import type { Secret, SessionLog } from "./types";
import { encryptForLevel, decryptForLevel, generateKemKeyPair, encryptAES, decryptAES } from "./lib/crypto";

const SETTLE_MS = 2000; // ms after last scroll before auth/content fires

const LevelSelector = ({ onChange }: { currentLevel: number, onChange: (l: number) => void }) => {
  // display: what the selector shows (0 = s, 1-4 = level positions)
  // Always starts at 0 (s); shows the scrolled-to number while settling
  const [display, setDisplay] = React.useState(0);
  const containerRef = React.useRef<HTMLDivElement>(null);
  const displayRef = React.useRef(0);
  const onChangeRef = React.useRef(onChange);
  const deltaAccRef = React.useRef(0);
  const cooldownRef = React.useRef(false);
  const settleTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const PIXEL_THRESHOLD = 60;
  const COOLDOWN_MS = 180;

  React.useEffect(() => { onChangeRef.current = onChange; }, [onChange]);

  const move = React.useCallback((delta: number) => {
    if (cooldownRef.current) return;
    const next = Math.max(0, Math.min(4, displayRef.current + delta));
    if (next === displayRef.current) return;
    displayRef.current = next;
    setDisplay(next);

    // Cancel any pending settle — user is still scrolling
    if (settleTimerRef.current) clearTimeout(settleTimerRef.current);

    if (next === 0) {
      // Scrolled back to standby — fire immediately, no delay needed
      onChangeRef.current(0);
    } else {
      // Wait for user to stop scrolling before acting
      settleTimerRef.current = setTimeout(() => {
        onChangeRef.current(displayRef.current);
        // Return display to s after settling
        displayRef.current = 0;
        setDisplay(0);
      }, SETTLE_MS);
    }

    cooldownRef.current = true;
    setTimeout(() => { cooldownRef.current = false; }, COOLDOWN_MS);
  }, []);

  // Non-passive wheel listener so we can preventDefault and guarantee timing
  React.useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      if (e.deltaMode === 1) {
        // Line mode — mechanical mouse: each detent = exactly one level
        if (e.deltaY > 0) move(1);
        else if (e.deltaY < 0) move(-1);
      } else {
        // Pixel mode — trackpad: accumulate until threshold
        deltaAccRef.current += e.deltaY;
        if (deltaAccRef.current >= PIXEL_THRESHOLD) {
          deltaAccRef.current -= PIXEL_THRESHOLD; // preserve remainder for chaining
          move(1);
        } else if (deltaAccRef.current <= -PIXEL_THRESHOLD) {
          deltaAccRef.current += PIXEL_THRESHOLD;
          move(-1);
        }
      }
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [move]);

  return (
    <div className="flex items-center text-4xl font-bold text-white tracking-tighter select-none">
      <div className="text-violet-400">lvl</div>
      <div
        ref={containerRef}
        className="relative h-10 w-8 overflow-hidden cursor-ns-resize"
      >
        <motion.div
          animate={{ y: -display * 40 }}
          transition={{ type: "spring", stiffness: 400, damping: 35, mass: 0.6 }}
          className="absolute inset-x-0 top-0"
          drag="y"
          dragConstraints={{ top: 0, bottom: 0 }}
          onDragEnd={(_e, info) => {
            if (info.offset.y < -12) move(1);
            else if (info.offset.y > 12) move(-1);
          }}
        >
          {['s', 3, 2, 1, 0].map((n, i) => (
            <div
              key={i}
              className="h-10 flex items-center justify-start cursor-pointer text-violet-400"
              onClick={() => move(i - displayRef.current)}
            >
              {n}
            </div>
          ))}
        </motion.div>
      </div>
    </div>
  );
};

// ---------- Auth Modal (outside App to prevent re-animation on keystroke) ----------
interface AuthModalProps {
  authLevel: number;
  targetLevel: number;
  totpStatus: Record<number, boolean>;
  authInput: string;
  setAuthInput: (v: string) => void;
  totpInput: string;
  setTotpInput: (v: string) => void;
  authError: string;
  setAuthError: (v: string) => void;
  authLoading: boolean;
  handleAuth: (e?: React.FormEvent) => void;
  onClose: () => void;
}

function AuthModal({ authLevel, targetLevel, totpStatus, authInput, setAuthInput, totpInput, setTotpInput, authError, setAuthError, authLoading, handleAuth, onClose }: AuthModalProps) {
  const [showPass, setShowPass] = useState(false);

  if (authLevel === 0) return null;

  const levelColor = targetLevel === 3 ? "bg-zinc-800 text-zinc-300"
    : targetLevel === 2 ? "bg-blue-900/30 text-blue-400"
    : targetLevel === 1 ? "bg-amber-900/30 text-amber-400"
    : "bg-red-900/30 text-red-400";

  const levelIcon = targetLevel === 3 ? <Lock className="w-10 h-10" />
    : targetLevel === 2 ? <Fingerprint className="w-10 h-10" />
    : targetLevel === 1 ? <Key className="w-10 h-10" />
    : <Shield className="w-10 h-10" />;

  const levelDesc = targetLevel === 3 ? "Enter your PIN to access the vault"
    : targetLevel === 2 ? "Enter your passphrase to continue"
    : targetLevel === 1 ? "Enter your credential to continue"
    : "Enter your master passphrase";

  const btnClass = targetLevel === 3 ? "bg-zinc-700 hover:bg-zinc-600"
    : targetLevel === 2 ? "bg-blue-600 hover:bg-blue-500"
    : targetLevel === 1 ? "bg-amber-700 hover:bg-amber-600"
    : "bg-red-700 hover:bg-red-600";

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-zinc-950/90 backdrop-blur-xl border border-zinc-800/60 p-8 rounded-2xl w-full max-w-md shadow-2xl relative">
        <button
            onClick={onClose}
            className="absolute top-4 right-4 p-1.5 rounded-lg text-zinc-500 hover:text-white hover:bg-zinc-800 transition-colors"
            title="Close"
          >
            <X className="w-4 h-4" />
          </button>
        <div className="flex justify-center mb-6">
          <div className={`p-4 rounded-full ${levelColor}`}>{levelIcon}</div>
        </div>
        <h2 className="text-2xl font-bold text-white text-center mb-2 tracking-tight">Unlock</h2>
        <p className="text-zinc-400 text-center mb-8 text-sm">{levelDesc}</p>

        <form onSubmit={handleAuth} className="space-y-4">
          <div className="relative">
            <input
              type={showPass ? "text" : "password"}
              value={authInput}
              onChange={e => { setAuthInput(e.target.value); setAuthError(""); }}
              className="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-4 py-3 pr-11 text-white focus:outline-none focus:ring-2 focus:ring-violet-600/50 focus:border-violet-600 transition-colors text-center tracking-widest"
              autoFocus
              autoComplete="current-password"
            />
            <button
              type="button"
              onClick={() => setShowPass(v => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 transition-colors"
              tabIndex={-1}
            >
              {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>

          {totpStatus[targetLevel] && (
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={totpInput}
              onChange={e => { setTotpInput(e.target.value); setAuthError(""); }}
              placeholder="6-digit TOTP code"
              className="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-violet-600/50 focus:border-violet-600 transition-colors text-center tracking-[0.5em] font-mono"
            />
          )}

          {authError && <p className="text-red-400 text-sm text-center">{authError}</p>}

          <button
            type="submit"
            disabled={authLoading}
            className={`w-full font-medium py-3 rounded-xl transition-colors flex items-center justify-center gap-2 text-white ${btnClass} disabled:opacity-60 disabled:cursor-wait`}
          >
            {authLoading
              ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              : <Unlock className="w-4 h-4" />}
            {authLoading ? "Verifying…" : "Authenticate"}
          </button>
        </form>
      </div>
    </div>
  );
}

// ---------- Nuke Vault Component ----------
function NukeVault() {
  const [phase, setPhase] = React.useState<"idle" | "confirm" | "nuking" | "done">("idle");
  const [confirmText, setConfirmText] = React.useState("");
  const CONFIRM_PHRASE = "NUKE VAULT";

  const nuke = async () => {
    if (confirmText !== CONFIRM_PHRASE) return;
    setPhase("nuking");
    try {
      await fetch("/api/vault/nuke", { method: "DELETE" });
      // Clear all local KEM keys
      for (let i = 0; i <= 3; i++) localStorage.removeItem(`lvls_kemenc_L${i}`);
      setPhase("done");
    } catch {
      setPhase("confirm");
    }
  };

  if (phase === "done") {
    return (
      <div className="bg-red-950/30 border border-red-900 rounded-xl px-5 py-4 text-center">
        <p className="text-red-400 font-medium text-sm">Vault wiped. Reload the page to start fresh.</p>
        <button onClick={() => window.location.reload()} className="mt-3 text-xs text-zinc-400 hover:text-white border border-zinc-700 px-3 py-1.5 rounded-lg transition-colors">
          Reload Now
        </button>
      </div>
    );
  }

  return (
    <div className="bg-red-950/20 border border-red-900/50 rounded-xl px-5 py-4 space-y-3">
      <div className="flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-medium text-red-400">Nuke Vault</p>
          <p className="text-xs text-zinc-500 mt-0.5">
            Permanently deletes ALL secrets, credentials, logs, and KEM keys. This cannot be undone.
          </p>
        </div>
      </div>

      {phase === "idle" && (
        <button
          onClick={() => setPhase("confirm")}
          className="text-xs text-red-400 border border-red-900 hover:border-red-700 hover:bg-red-950 px-4 py-2 rounded-lg transition-colors"
        >
          Wipe Everything
        </button>
      )}

      {phase === "confirm" && (
        <div className="space-y-2">
          <p className="text-xs text-zinc-400">
            Type <span className="font-mono text-red-400 font-bold">{CONFIRM_PHRASE}</span> to confirm:
          </p>
          <div className="flex gap-2">
            <input
              type="text"
              value={confirmText}
              onChange={e => setConfirmText(e.target.value)}
              className="flex-1 bg-zinc-950 border border-red-900 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-red-500"
              placeholder={CONFIRM_PHRASE}
              autoFocus
            />
            <button
              onClick={nuke}
              disabled={confirmText !== CONFIRM_PHRASE}
              className="bg-red-700 hover:bg-red-600 disabled:opacity-30 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
            >
              {phase === "nuking" ? "Wiping…" : "Confirm Nuke"}
            </button>
            <button
              onClick={() => { setPhase("idle"); setConfirmText(""); }}
              className="text-zinc-400 hover:text-white border border-zinc-800 px-3 py-2 rounded-lg text-sm transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------- Credential Setup Component ----------
function CredentialSetup({ authLevel, sessionToken }: { authLevel: number; sessionToken: string | null }) {
  const LEVELS = [
    { level: 3, label: "lvl3 — PIN", color: "text-zinc-300", borderColor: "border-zinc-700", hint: "Numeric digits only, min 6", inputMode: "numeric" as const, isPin: true },
    { level: 2, label: "lvl2 — Professional", color: "text-blue-400", borderColor: "border-blue-900", hint: "Alphanumeric, min 6 chars (letters + numbers)", inputMode: "text" as const, isPin: false },
    { level: 1, label: "lvl1 — Personal", color: "text-amber-400", borderColor: "border-amber-900", hint: "Alphanumeric, min 6 chars (letters + numbers)", inputMode: "text" as const, isPin: false },
    { level: 0, label: "lvl0 — Critical", color: "text-red-400", borderColor: "border-red-900", hint: "Alphanumeric, min 6 chars (letters + numbers)", inputMode: "text" as const, isPin: false },
  ];

  const [values, setValues] = React.useState<Record<number, { cred: string; confirm: string; saving: boolean; result: string }>>({
    0: { cred: "", confirm: "", saving: false, result: "" },
    1: { cred: "", confirm: "", saving: false, result: "" },
    2: { cred: "", confirm: "", saving: false, result: "" },
    3: { cred: "", confirm: "", saving: false, result: "" },
  });

  const save = async (level: number) => {
    const { cred, confirm } = values[level];
    if (!cred) return setResult(level, "Enter a credential");
    if (cred !== confirm) return setResult(level, "Credentials don't match");

    setValues(prev => ({ ...prev, [level]: { ...prev[level], saving: true, result: "" } }));
    try {
      const res = await fetch("/api/auth/setup", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({ level, credential: cred, method: level === 3 ? "pin" : "passphrase" }),
      });
      const data = await res.json();
      if (res.ok) {
        setValues(prev => ({ ...prev, [level]: { cred: "", confirm: "", saving: false, result: "✓ Saved" } }));
      } else {
        setResult(level, data.error || "Failed");
      }
    } catch {
      setResult(level, "Server unreachable");
    }
  };

  const setResult = (level: number, result: string) =>
    setValues(prev => ({ ...prev, [level]: { ...prev[level], saving: false, result } }));

  const unlockedLevels = LEVELS.filter(({ level }) => authLevel <= level);

  if (unlockedLevels.length === 0) {
    return <p className="text-xs text-zinc-600">Unlock a level first to manage its credential.</p>;
  }

  return (
    <div className="space-y-3">
      {unlockedLevels.map(({ level, label, color, borderColor, hint, inputMode, isPin }) => (
        <details key={level} className={`bg-zinc-950 border ${borderColor} rounded-xl`}>
          <summary className="flex items-center justify-between px-5 py-4 cursor-pointer list-none">
            <div>
              <p className={`text-sm font-medium ${color}`}>{label}</p>
              <p className="text-xs text-zinc-600 mt-0.5">{hint}</p>
            </div>
            <span className="text-xs text-zinc-400 border border-zinc-700 px-3 py-1.5 rounded-lg">Change ▾</span>
          </summary>
          <div className="px-5 pb-5 pt-3 border-t border-zinc-800 space-y-3">
            <div>
              <label className="block text-xs text-zinc-500 uppercase tracking-wider mb-1">
                {isPin ? "New PIN" : "New Passphrase"}
              </label>
              <input
                type="password"
                inputMode={inputMode}
                value={values[level].cred}
                onChange={e => setValues(prev => ({ ...prev, [level]: { ...prev[level], cred: e.target.value, result: "" } }))}
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-violet-600"
                placeholder={isPin ? "e.g. 123456" : "e.g. MyVault2a"}
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-500 uppercase tracking-wider mb-1">Confirm</label>
              <input
                type="password"
                inputMode={inputMode}
                value={values[level].confirm}
                onChange={e => setValues(prev => ({ ...prev, [level]: { ...prev[level], confirm: e.target.value, result: "" } }))}
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-violet-600"
                placeholder="Repeat credential"
              />
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => save(level)}
                disabled={values[level].saving}
                className="bg-violet-600 hover:bg-violet-600 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
              >
                {values[level].saving ? "Saving…" : "Save Credential"}
              </button>
              {values[level].result && (
                <span className={`text-xs ${values[level].result.startsWith("✓") ? "text-violet-600" : "text-red-400"}`}>
                  {values[level].result}
                </span>
              )}
            </div>
          </div>
        </details>
      ))}
    </div>
  );
}

// ---------- Folder Input with level-scoped dropdown ----------
function FolderInput({ value, onChange, folders }: {
  value: string;
  onChange: (v: string) => void;
  folders: string[];
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const filtered = folders.filter(f => f.toLowerCase().includes(value.toLowerCase()));

  useEffect(() => {
    const handler = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <input
        type="text"
        value={value}
        onChange={e => { onChange(e.target.value); setOpen(true); }}
        onFocus={() => setOpen(true)}
        className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-violet-600 placeholder:text-zinc-600"
        placeholder="e.g. AWS, GitHub, Vanta"
        autoComplete="off"
      />
      {open && filtered.length > 0 && (
        <div className="absolute z-50 top-full mt-1 w-full bg-zinc-900 border border-zinc-800 rounded-lg shadow-xl overflow-hidden">
          {filtered.map(f => (
            <button
              key={f}
              type="button"
              onMouseDown={e => { e.preventDefault(); onChange(f); setOpen(false); }}
              className="w-full text-left px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800 hover:text-white transition-colors flex items-center gap-2"
            >
              <span className="text-zinc-500 text-xs">📁</span> {f}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------- Live TOTP Code Display ----------
function TotpCodeDisplay({ seed }: { seed: string }) {
  const [code, setCode] = useState("------");
  const [secsLeft, setSecsLeft] = useState(30);

  useEffect(() => {
    let mounted = true;

    const update = async () => {
      try {
        const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        const s = seed.toUpperCase().replace(/[^A-Z2-7]/g, "");
        let bits = 0, val = 0;
        const keyBytes: number[] = [];
        for (const ch of s) {
          const idx = B32.indexOf(ch);
          if (idx === -1) continue;
          val = (val << 5) | idx;
          bits += 5;
          if (bits >= 8) { keyBytes.push((val >>> (bits - 8)) & 255); bits -= 8; }
        }
        const nowSec = Math.floor(Date.now() / 1000);
        const counter = Math.floor(nowSec / 30);
        const sLeft = 30 - (nowSec % 30);
        const cb = new Uint8Array(8);
        const dv = new DataView(cb.buffer);
        dv.setUint32(0, Math.floor(counter / 0x100000000), false);
        dv.setUint32(4, counter >>> 0, false);
        const key = await crypto.subtle.importKey("raw", new Uint8Array(keyBytes), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
        const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, cb));
        const offset = hmac[19] & 0xf;
        const num = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset+1] & 0xff) << 16) | ((hmac[offset+2] & 0xff) << 8) | (hmac[offset+3] & 0xff);
        if (mounted) { setCode((num % 1_000_000).toString().padStart(6, "0")); setSecsLeft(sLeft); }
      } catch { if (mounted) setCode("error"); }
    };

    update();
    const iv = setInterval(update, 1000);
    return () => { mounted = false; clearInterval(iv); };
  }, [seed]);

  const urgent = secsLeft <= 7;
  const pct = (secsLeft / 30) * 100;

  return (
    <div className="flex items-center gap-2.5">
      <span className={`font-mono text-sm font-bold tracking-[0.3em] ${urgent ? "text-red-400" : "text-violet-600"}`}>
        {code.slice(0, 3)} {code.slice(3)}
      </span>
      <div className="flex items-center gap-1">
        <div className="w-14 h-1 bg-zinc-800 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-1000 ${urgent ? "bg-red-500" : "bg-violet-600"}`}
            style={{ width: `${pct}%` }}
          />
        </div>
        <span className={`text-xs font-mono tabular-nums w-5 ${urgent ? "text-red-400" : "text-zinc-500"}`}>{secsLeft}s</span>
      </div>
      <button onClick={() => copyToClipboard(code)} className="text-zinc-500 hover:text-zinc-300 transition-colors" title="Copy code">
        <Copy className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState<"vault" | "logs">("vault");
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [logs, setLogs] = useState<SessionLog[]>([]);
  const [isAdding, setIsAdding] = useState(false);
  const [newSecret, setNewSecret] = useState({
    name: "",
    level: 3,
    type: "password",
    value: "",
    tags: "",
    url: "",
    username: "",
    folder: "",
  });
  const [collapsedFolders, setCollapsedFolders] = useState<Set<string>>(new Set());
  
  // Progressive Auth State
  const [authLevel, setAuthLevel] = useState<number>(4);
  const [viewLevel, setViewLevel] = useState<number>(0);
  const [pendingAuthLevel, setPendingAuthLevel] = useState<number>(3); // the level we're trying to unlock
  const [showAuthModal, setShowAuthModal] = useState(true);
  const [authInput, setAuthInput] = useState("");
  const [authError, setAuthError] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  const [revealedSecrets, setRevealedSecrets] = useState<Set<string>>(new Set());
  const [revealedValues, setRevealedValues] = useState<Record<string, string>>({});
  const [showSettings, setShowSettings] = useState(false);
  const [settingsTab, setSettingsTab] = useState<"auth" | "docs">("auth");
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [sessionCredentials, setSessionCredentials] = useState<Record<number, string>>({});
  const [editingSecret, setEditingSecret] = useState<string | null>(null);
  const [editForm, setEditForm] = useState({ name: "", type: "password", tags: "", url: "", username: "", folder: "" });

  // TOTP setup state
  const [totpSetup, setTotpSetup] = useState<{ level: number; secret: string; uri: string } | null>(null);
  const [totpConfirmCode, setTotpConfirmCode] = useState("");
  const [totpConfirmError, setTotpConfirmError] = useState("");
  const [totpStatus, setTotpStatus] = useState<Record<number, boolean>>({});
  const [totpInput, setTotpInput] = useState("");
  const [sessionTtls, setSessionTtls] = useState<Record<number, string>>({ 0: "1h", 1: "1h", 2: "8h", 3: "24h" });

  // Filter state for vault and logs tabs
  const [vaultLevelFilter, setVaultLevelFilter] = useState<number[]>([]);
  const [logsLevelFilter, setLogsLevelFilter] = useState<number[]>([]);
  const [showLevelCol, setShowLevelCol] = useState(false);
  const [lvlDropdownOpen, setLvlDropdownOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  // KEM private keys held in memory after unlock — never stored unencrypted
  const [kemPrivateKeys, setKemPrivateKeys] = useState<Record<number, string>>({});

  // Auto-lock
  const AUTO_LOCK_MS = 5 * 60 * 1000; // 5 minutes of inactivity
  const lastActivityRef = useRef(Date.now());
  const revealTimersRef = useRef<Record<string, ReturnType<typeof setTimeout>>>({});

  useEffect(() => {
    if (authLevel <= 3) {
      fetchSecrets();
      fetchLogs();
      setVaultLevelFilter([authLevel]);
      setShowLevelCol(false);
      setSearchQuery("");
    }
  }, [authLevel, sessionToken]);

  // Auto-lock on inactivity
  useEffect(() => {
    const updateActivity = () => { lastActivityRef.current = Date.now(); };
    window.addEventListener("mousemove", updateActivity);
    window.addEventListener("keydown", updateActivity);
    window.addEventListener("click", updateActivity);
    const interval = setInterval(() => {
      if (authLevel <= 3 && Date.now() - lastActivityRef.current > AUTO_LOCK_MS) {
        setAuthLevel(4);
        setSessionToken(null);
        setSessionCredentials({});
        setKemPrivateKeys({}); // wipe private keys from memory
        setRevealedSecrets(new Set());
        setRevealedValues({});
        setShowAuthModal(true);
      }
    }, 30_000);
    return () => {
      window.removeEventListener("mousemove", updateActivity);
      window.removeEventListener("keydown", updateActivity);
      window.removeEventListener("click", updateActivity);
      clearInterval(interval);
    };
  }, [authLevel]);

  // Fetch TOTP status + session TTLs for settings panel
  useEffect(() => {
    fetch("/api/auth/status")
      .then(r => r.json())
      .then(data => {
        if (data.configured) {
          const status: Record<number, boolean> = {};
          const ttls: Record<number, string> = {};
          for (const [lvl, info] of Object.entries(data.configured as Record<string, any>)) {
            const l = parseInt(lvl);
            status[l] = info.totpEnabled;
            ttls[l] = info.sessionTtl || "24h";
          }
          setTotpStatus(status);
          setSessionTtls(prev => ({ ...prev, ...ttls }));
        }
      })
      .catch(() => {});
  }, [showSettings]);

  const fetchSecrets = async () => {
    try {
      const res = await fetch("/api/secrets", {
        headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
      });
      if (res.ok) {
        const data: Secret[] = await res.json();
        setSecrets(data);
        // Auto-collapse all folders by default
        setCollapsedFolders(prev => {
          const next = new Set(prev);
          data.forEach(s => { if (s.folder) next.add(s.folder); });
          return next;
        });
      }
    } catch (error) {
      console.error("Failed to fetch secrets", error);
    }
  };

  const fetchLogs = async () => {
    try {
      const res = await fetch("/api/logs", {
        headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
      });
      if (res.ok) {
        const data = await res.json();
        setLogs(data);
      }
    } catch (error) {
      console.error("Failed to fetch logs", error);
    }
  };

  const handleAuth = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setAuthLoading(true);
    setAuthError("");
    const targetLevel = pendingAuthLevel;
    try {
      const body: any = { level: targetLevel, credential: authInput };
      if (totpInput.trim()) body.totp = totpInput.trim();
      const res = await fetch("/api/auth/unlock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setAuthLevel(targetLevel);
        setSessionToken(data.token);
        setSessionCredentials(prev => ({ ...prev, [targetLevel]: authInput }));

        // Load or generate ML-KEM keypair for levels 0/1/2
        if (targetLevel < 3) {
          await ensureKemKeyPair(targetLevel, authInput, data.token);
        }

        setAuthInput("");
        setTotpInput("");
        setShowAuthModal(false);
      } else {
        setAuthError(data.error || "Invalid credential");
      }
    } catch {
      setAuthError("Server unreachable");
    } finally {
      setAuthLoading(false);
    }
  };

  const handleTotpSetup = async (level: number) => {
    try {
      const res = await fetch(`/api/auth/totp/setup/${level}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${sessionToken}` },
      });
      const data = await res.json();
      if (res.ok) {
        setTotpSetup({ level, secret: data.secret, uri: data.uri });
        setTotpConfirmCode("");
        setTotpConfirmError("");
      }
    } catch { /* ignore */ }
  };

  const handleTotpConfirm = async () => {
    if (!totpSetup) return;
    try {
      const res = await fetch(`/api/auth/totp/confirm/${totpSetup.level}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${sessionToken}` },
        body: JSON.stringify({ totp: totpConfirmCode }),
      });
      const data = await res.json();
      if (res.ok) {
        setTotpStatus(prev => ({ ...prev, [totpSetup.level]: true }));
        setTotpSetup(null);
      } else {
        setTotpConfirmError(data.error || "Invalid code");
      }
    } catch { setTotpConfirmError("Network error"); }
  };

  /**
   * Ensures a ML-KEM keypair exists for the given level.
   * - Private key is encrypted with the level credential and stored in localStorage.
   * - Public key is stored on the server (auth_config.kem_public_key).
   * - After this call, the private key is held in memory in kemPrivateKeys state.
   */
  const ensureKemKeyPair = async (level: number, credential: string, token: string) => {
    const storageKey = `lvls_kemenc_L${level}`;
    const stored = localStorage.getItem(storageKey);

    if (stored) {
      // Decrypt the stored private key using the credential
      try {
        const privateKey = await decryptAES(stored, credential);
        setKemPrivateKeys(prev => ({ ...prev, [level]: privateKey }));
        return;
      } catch {
        // Stored key can't be decrypted (credential changed?) — regenerate
        localStorage.removeItem(storageKey);
      }
    }

    // Generate a new keypair
    try {
      const { publicKey, privateKey } = await generateKemKeyPair();
      // Encrypt the private key with the credential before storing
      const encryptedPrivKey = await encryptAES(privateKey, credential);
      localStorage.setItem(storageKey, encryptedPrivKey);
      // Upload the public key to the server
      await fetch(`/api/auth/kem-key/${level}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ publicKey }),
      });
      setKemPrivateKeys(prev => ({ ...prev, [level]: privateKey }));
    } catch (err) {
      console.error("KEM keypair generation failed:", err);
    }
  };

  const handleTotpDisable = async (level: number) => {
    try {
      await fetch(`/api/auth/totp/disable/${level}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${sessionToken}` },
      });
      setTotpStatus(prev => ({ ...prev, [level]: false }));
    } catch { /* ignore */ }
  };

  const handleAddSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      // Use the credential for this level, or the highest-security credential available
      const credential = sessionCredentials[newSecret.level] ??
        sessionCredentials[Math.min(...Object.keys(sessionCredentials).map(Number))] ?? "";

      // Fetch KEM public key from server for Lvl 0/1/2 (enables ML-KEM-768 + AES-256-GCM hybrid)
      let publicKeyB64: string | undefined;
      if (newSecret.level < 3 && sessionToken) {
        try {
          const kemRes = await fetch(`/api/auth/kem-key/${newSecret.level}`, {
            headers: { Authorization: `Bearer ${sessionToken}` },
          });
          if (kemRes.ok) {
            const kemData = await kemRes.json();
            publicKeyB64 = kemData.publicKey;
          }
        } catch { /* fall back to AES-only */ }
      }

      const encryptedValue = await encryptForLevel(
        newSecret.value,
        newSecret.level,
        credential,
        publicKeyB64
      );

      const res = await fetch("/api/secrets", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({
          id: crypto.randomUUID(),
          name: newSecret.name,
          level: newSecret.level,
          secret_type: newSecret.type,
          encrypted_value: encryptedValue,
          tags: newSecret.tags.split(",").map(t => t.trim()).filter(Boolean),
          expiry: null,
          url: newSecret.url || null,
          username: newSecret.username || null,
          folder: newSecret.folder.trim() || null,
        }),
      });

      if (res.ok) {
        setIsAdding(false);
        setNewSecret({ name: "", level: 3, type: "password", value: "", tags: "", url: "", username: "", folder: "" });
        fetchSecrets();
      }
    } catch (error) {
      console.error("Failed to add secret", error);
    }
  };

  const handleDeleteSecret = async (id: string) => {
    try {
      const res = await fetch(`/api/secrets/${id}`, {
        method: "DELETE",
        headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
      });
      if (res.ok) fetchSecrets();
    } catch (error) {
      console.error("Failed to delete secret", error);
    }
  };

  const handleEditSave = async (id: string) => {
    try {
      const res = await fetch(`/api/secrets/${id}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({
          name: editForm.name,
          secret_type: editForm.type,
          tags: editForm.tags.split(",").map(t => t.trim()).filter(Boolean),
          folder: editForm.folder.trim() || null,
        }),
      });
      if (res.ok) {
        setEditingSecret(null);
        fetchSecrets();
      }
    } catch (error) {
      console.error("Failed to update secret", error);
    }
  };

  const REVEAL_TTL_MS = 5000;

  const scheduleHide = (id: string) => {
    if (revealTimersRef.current[id]) clearTimeout(revealTimersRef.current[id]);
    revealTimersRef.current[id] = setTimeout(() => {
      setRevealedSecrets(prev => { const next = new Set(prev); next.delete(id); return next; });
      delete revealTimersRef.current[id];
    }, REVEAL_TTL_MS);
  };

  const cancelHide = (id: string) => {
    if (revealTimersRef.current[id]) { clearTimeout(revealTimersRef.current[id]); delete revealTimersRef.current[id]; }
  };

  const decryptSecret = async (id: string, secretLevel: number, encryptedValue: string): Promise<string> => {
    if (revealedValues[id]) return revealedValues[id];
    const credential = sessionCredentials[secretLevel]
      ?? sessionCredentials[Math.min(...Object.keys(sessionCredentials).map(Number))] ?? "";
    const privateKeyB64 = kemPrivateKeys[secretLevel];
    try {
      const plaintext = await decryptForLevel(encryptedValue, credential, privateKeyB64);
      setRevealedValues(prev => ({ ...prev, [id]: plaintext }));
      return plaintext;
    } catch {
      try {
        const plaintext = atob(encryptedValue);
        setRevealedValues(prev => ({ ...prev, [id]: plaintext }));
        return plaintext;
      } catch {
        return "[decryption failed]";
      }
    }
  };

  const toggleReveal = async (id: string, secretLevel: number, encryptedValue: string) => {
    const newRevealed = new Set(revealedSecrets);
    if (newRevealed.has(id)) {
      newRevealed.delete(id);
      cancelHide(id);
      setRevealedSecrets(newRevealed);
      return;
    }
    const plaintext = await decryptSecret(id, secretLevel, encryptedValue);
    if (plaintext) {
      newRevealed.add(id);
      setRevealedSecrets(newRevealed);
      scheduleHide(id);
    }
  };

  const copySecret = async (id: string, secretLevel: number, encryptedValue: string) => {
    const plaintext = await decryptSecret(id, secretLevel, encryptedValue);
    if (plaintext && plaintext !== "[decryption failed]") copyToClipboard(plaintext);
  };

  const getLevelInfo = (level: number) => {
    switch(level) {
      case 3: return { name: "Everyday Info", color: "text-zinc-300", bg: "bg-zinc-800", desc: "Social profiles, Wi-Fi, car plates, subs — low impact if exposed" };
      case 2: return { name: "Professional / Social", color: "text-blue-400", bg: "bg-blue-900/30", desc: "API keys, IAM roles, DAO voting, AV access" };
      case 1: return { name: "Personal / Infra", color: "text-amber-400", bg: "bg-amber-900/30", desc: "Financial APIs, HealthKit/BCI data, SSH, smart home admin" };
      case 0: return { name: "Critical / Private", color: "text-red-400", bg: "bg-red-900/30", desc: "Seed phrases, master identity hashes, break-glass keys" };
      default: return { name: "Unknown", color: "text-zinc-500", bg: "bg-zinc-800", desc: "" };
    }
  };

  // AuthModal is defined outside App (see below) to prevent re-animation on every keystroke

  return (
    <div className="min-h-screen bg-black text-zinc-300 font-sans flex">
      {showAuthModal && (
        <AuthModal
          authLevel={authLevel}
          targetLevel={pendingAuthLevel}
          totpStatus={totpStatus}
          authInput={authInput}
          setAuthInput={setAuthInput}
          totpInput={totpInput}
          setTotpInput={setTotpInput}
          authError={authError}
          setAuthError={setAuthError}
          authLoading={authLoading}
          handleAuth={handleAuth}
          onClose={() => { setShowAuthModal(false); setAuthInput(""); setAuthError(""); setTotpInput(""); }}
        />
      )}

      {/* Sidebar */}
      <div className="w-64 bg-black flex flex-col z-10">
        <div className="h-16 bg-black flex items-center justify-center border-b border-zinc-900">
          <img src="/logo.png" alt="lvls" className="h-10 w-auto object-contain" />
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          <button
            onClick={() => setActiveTab("vault")}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${activeTab === "vault" ? "bg-zinc-900 text-violet-400 border border-zinc-800" : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900/60"}`}
          >
            <Key className="w-4 h-4 shrink-0" /> Secrets
          </button>
          <button
            onClick={() => setActiveTab("logs")}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${activeTab === "logs" ? "bg-zinc-900 text-violet-400 border border-zinc-800" : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900/60"}`}
          >
            <Activity className="w-4 h-4 shrink-0" /> Session Logs
          </button>
        </nav>

        <div className="px-4 py-4 flex items-center justify-between bg-black">
          <LevelSelector
            currentLevel={viewLevel}
            onChange={(l) => {
              // l=0 means standby (s) — keep current view, do nothing
              if (l === 0) return;
              setViewLevel(l);
              const neededAuthLevel = 4 - l;
              if (authLevel > neededAuthLevel) {
                // Need higher clearance — ask for credential
                setPendingAuthLevel(neededAuthLevel);
                setShowAuthModal(true);
              } else {
                // Already cleared — just switch view, no auth needed
                setVaultLevelFilter([neededAuthLevel]);
              }
            }}
          />
          <button
            onClick={async () => {
              // M1: Revoke token server-side before clearing locally
              if (sessionToken) {
                fetch("/api/auth/logout", { method: "POST", headers: { Authorization: `Bearer ${sessionToken}` } }).catch(() => {});
              }
              setAuthLevel(4);
              setViewLevel(0);
              setSessionToken(null);
              setSessionCredentials({});
              setKemPrivateKeys({});
              setRevealedSecrets(new Set());
              setRevealedValues({});
              setShowAuthModal(true);
            }}
            className="p-2 text-zinc-600 hover:text-violet-400 hover:bg-zinc-900 rounded-lg transition-all duration-150"
            title="Lock lvl"
          >
            <Lock className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col h-screen overflow-hidden">
        <header className="h-16 border-b border-zinc-900 flex items-center justify-end px-6 bg-black/80 backdrop-blur-md shrink-0">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600" />
              <input
                type="text"
                placeholder="Search secrets…"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="bg-zinc-950 border border-zinc-800/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-zinc-300 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-700 focus:bg-zinc-900 transition-all w-48 focus:w-64"
              />
            </div>
            <div className="w-px h-5 bg-zinc-800" />
            <button
              onClick={() => setShowSettings(true)}
              className="p-1.5 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-900 rounded-lg transition-all"
              title="Settings"
            >
              <Settings className="w-4 h-4" />
            </button>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-6 w-full">
          {activeTab === "vault" && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="w-full space-y-6"
            >
              <div className="flex justify-end items-center gap-4">
                <button
                  onClick={() => setIsAdding(true)}
                  className="bg-violet-600 hover:bg-violet-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-all duration-150 flex items-center gap-2 shrink-0 shadow-lg shadow-violet-900/30"
                >
                  <Plus className="w-4 h-4" /> Add Secret
                </button>
              </div>

              {isAdding && (
                <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-6 mb-6 shadow-xl">
                  <h3 className="text-white font-medium mb-4">
                    Add New Secret
                  </h3>
                  <form onSubmit={handleAddSecret} className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-xs font-medium text-zinc-500 mb-1 uppercase tracking-wider">
                          Name / Identifier
                        </label>
                        <input
                          type="text"
                          required
                          value={newSecret.name}
                          onChange={(e) =>
                            setNewSecret({ ...newSecret, name: e.target.value })
                          }
                          className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-violet-600"
                          placeholder="e.g. Anthropic_API_Key, GitHub_Email, Ledger_Seed"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-zinc-500 mb-1 uppercase tracking-wider">
                          Secret Type
                        </label>
                        <select
                          value={newSecret.type}
                          onChange={(e) => setNewSecret({ ...newSecret, type: e.target.value })}
                          className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-violet-600"
                        >
                          <optgroup label="Identity">
                            <option value="email">Email Address</option>
                            <option value="username">Username / Handle</option>
                            <option value="national_id">National ID / Passport</option>
                            <option value="device_id">Device ID / Serial</option>
                            <option value="did">DID / ENS / Web3 Identity</option>
                          </optgroup>
                          <optgroup label="Credentials">
                            <option value="password">Password</option>
                            <option value="pin">PIN</option>
                            <option value="passphrase">Passphrase / Recovery Phrase</option>
                            <option value="totp_seed">TOTP Seed (Authenticator)</option>
                          </optgroup>
                          <optgroup label="Keys & Tokens">
                            <option value="api_key">API Key</option>
                            <option value="oauth_token">OAuth Token</option>
                            <option value="ssh_key">SSH Key</option>
                            <option value="gpg_key">GPG Key</option>
                            <option value="crypto_seed">Crypto Seed Phrase</option>
                            <option value="crypto_key">Crypto Private Key</option>
                          </optgroup>
                          <optgroup label="Access">
                            <option value="nfc_card">NFC Card / Key Fob</option>
                            <option value="certificate">Certificate / Licence</option>
                            <option value="wifi">Wi-Fi Credential</option>
                          </optgroup>
                          <optgroup label="Other">
                            <option value="note">Secure Note</option>
                            <option value="custom">Custom</option>
                          </optgroup>
                        </select>
                      </div>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-zinc-500 mb-1 uppercase tracking-wider">
                        Security Tier
                      </label>
                      <select
                        value={newSecret.level}
                        onChange={(e) =>
                          setNewSecret({
                            ...newSecret,
                            level: Number(e.target.value),
                          })
                        }
                        className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-violet-600"
                      >
                        <option value={3} disabled={authLevel > 3}>lvl3 — Everyday (Social, Wi-Fi, plates, basic info)</option>
                        <option value={2} disabled={authLevel > 2}>Lvl 2 — Professional (APIs, IAM, Work Email, DAOs)</option>
                        <option value={1} disabled={authLevel > 1}>Lvl 1 — Personal/Infra (Finance, Health, SSH, Personal IDs)</option>
                        <option value={0} disabled={authLevel > 0}>Lvl 0 — Critical (Seeds, Master Identity, BCI, NFC Cards)</option>
                      </select>

                    </div>
                    {["password", "pin", "passphrase", "api_key", "oauth_token"].includes(newSecret.type) && (
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-xs font-medium text-zinc-500 mb-1 uppercase tracking-wider">
                            Username / Email
                          </label>
                          <div className="relative">
                            <User className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
                            <input
                              type="text"
                              value={newSecret.username}
                              onChange={(e) => setNewSecret({ ...newSecret, username: e.target.value })}
                              className="w-full bg-zinc-950 border border-zinc-800 rounded-lg pl-8 pr-3 py-2 text-sm text-white focus:outline-none focus:border-violet-600"
                              placeholder="user@example.com"
                            />
                          </div>
                        </div>
                        <div>
                          <label className="block text-xs font-medium text-zinc-500 mb-1 uppercase tracking-wider">
                            Site URL
                          </label>
                          <div className="relative">
                            <Globe className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
                            <input
                              type="text"
                              value={newSecret.url}
                              onChange={(e) => setNewSecret({ ...newSecret, url: e.target.value })}
                              className="w-full bg-zinc-950 border border-zinc-800 rounded-lg pl-8 pr-3 py-2 text-sm text-white focus:outline-none focus:border-violet-600"
                              placeholder="github.com"
                            />
                          </div>
                        </div>
                      </div>
                    )}
                    <div>
                      <label className="block text-xs font-medium text-zinc-500 mb-1 uppercase tracking-wider">
                        Secret Value
                      </label>
                      <div className="flex gap-2">
                        <input
                          type="password"
                          required
                          value={newSecret.value}
                          onChange={(e) =>
                            setNewSecret({ ...newSecret, value: e.target.value })
                          }
                          className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-violet-600"
                          placeholder="Enter the secret value..."
                        />
                        {["password", "pin", "passphrase", "api_key"].includes(newSecret.type) && (
                          <button
                            type="button"
                            title="Generate strong password"
                            onClick={() => setNewSecret({ ...newSecret, value: generatePassword() })}
                            className="px-3 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-zinc-400 hover:text-white transition-colors flex items-center gap-1.5 text-xs shrink-0"
                          >
                            <RefreshCw className="w-3.5 h-3.5" /> Generate
                          </button>
                        )}
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-xs font-medium text-zinc-500 mb-1 uppercase tracking-wider">
                          Folder
                        </label>
                        <FolderInput
                          value={newSecret.folder}
                          onChange={v => setNewSecret({ ...newSecret, folder: v })}
                          folders={[...new Set<string>(
                            secrets
                              .filter(s => s.level === newSecret.level && s.folder)
                              .map(s => s.folder!)
                          )]}
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-zinc-500 mb-1 uppercase tracking-wider">
                          Tags (comma separated)
                        </label>
                        <input
                          type="text"
                          value={newSecret.tags}
                          onChange={(e) => setNewSecret({ ...newSecret, tags: e.target.value })}
                          className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-violet-600"
                          placeholder="e.g. ai, finance, infra"
                        />
                      </div>
                    </div>
                    <div className="flex justify-end gap-3 pt-2">
                      <button
                        type="button"
                        onClick={() => setIsAdding(false)}
                        className="px-4 py-2 text-sm text-zinc-400 hover:text-white transition-colors"
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        className="bg-violet-600 hover:bg-violet-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
                      >
                        Save & Encrypt
                      </button>
                    </div>
                  </form>
                </div>
              )}

              <div className="bg-zinc-950/50 border border-zinc-900 rounded-xl overflow-hidden shadow-2xl">
                <table className="w-full text-left text-sm">
                  <thead className="bg-black/60 text-zinc-600 text-[10px] uppercase tracking-widest border-b border-zinc-900">
                    <tr>
                      <th className="px-5 py-3 font-medium">Identifier</th>
                      <th className="px-5 py-3 font-medium">Value</th>
                      {showLevelCol && (
                        <th className="px-4 py-4 font-medium">
                          <div className="relative flex items-center gap-1.5">
                            <button
                              onClick={() => setLvlDropdownOpen(v => !v)}
                              className="hover:text-zinc-300 transition-colors"
                              title="Filter by level"
                            >
                              lvl
                            </button>
                            {lvlDropdownOpen && (
                              <>
                                <div className="fixed inset-0 z-10" onClick={() => setLvlDropdownOpen(false)} />
                                <div className="absolute top-6 left-0 z-20 bg-zinc-950 border border-zinc-700 rounded-lg shadow-xl p-2 space-y-1 min-w-[100px]">
                                  {[3, 2, 1, 0].filter(l => l >= authLevel).map(l => (
                                    <button
                                      key={l}
                                      onClick={(e) => { e.stopPropagation(); setVaultLevelFilter(prev => prev.includes(l) ? prev.filter(x => x !== l) : [...prev, l]); }}
                                      className="w-full flex items-center gap-2 px-2 py-1.5 rounded text-xs font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 transition-colors"
                                    >
                                      <span className={`w-2 h-2 rounded-sm border ${vaultLevelFilter.includes(l) ? "bg-zinc-400 border-zinc-400" : "border-zinc-600 bg-transparent"}`} />
                                      lvl{l}
                                    </button>
                                  ))}
                                </div>
                              </>
                            )}
                          </div>
                        </th>
                      )}
                      <th className="px-5 py-3 font-medium">Tags</th>
                      <th className="px-5 py-3 font-medium text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(() => {
                      const q = searchQuery.toLowerCase().trim();
                      const filtered = secrets.filter((s) =>
                        authLevel < 4 &&
                        s.level >= authLevel &&
                        (vaultLevelFilter.length === 0 || vaultLevelFilter.includes(s.level)) &&
                        (!q || s.name.toLowerCase().includes(q) || (s.folder || "").toLowerCase().includes(q) || (s.username || "").toLowerCase().includes(q) || s.tags.some(t => t.toLowerCase().includes(q)))
                      );
                      const folderMap = new Map<string, Secret[]>();
                      filtered.forEach(s => {
                        const key = s.folder?.trim() || "__none__";
                        if (!folderMap.has(key)) folderMap.set(key, []);
                        folderMap.get(key)!.push(s);
                      });
                      const folderKeys = [...folderMap.keys()].sort((a, b) =>
                        a === "__none__" ? 1 : b === "__none__" ? -1 : a.localeCompare(b)
                      );
                      const colSpan = showLevelCol ? 7 : 6;
                      return folderKeys.map(folderKey => {
                        const folderSecrets = folderMap.get(folderKey)!;
                        const label = folderKey === "__none__" ? null : folderKey;
                        const isCollapsed = collapsedFolders.has(folderKey);
                        return (
                          <React.Fragment key={folderKey}>
                            {label !== null && (
                              <tr className="bg-zinc-950/60 select-none group/folder">
                                <td colSpan={colSpan} className="px-5 py-3.5">
                                  <div className="flex items-center justify-between">
                                    <button
                                      className="flex items-center gap-2.5 text-sm font-medium text-zinc-300 hover:text-white transition-colors"
                                      onClick={() => setCollapsedFolders(prev => {
                                        const next = new Set(prev);
                                        next.has(folderKey) ? next.delete(folderKey) : next.add(folderKey);
                                        return next;
                                      })}
                                    >
                                      {isCollapsed
                                        ? <Folder className="w-4 h-4 shrink-0 fill-amber-400 text-amber-500" />
                                        : <FolderOpen className="w-4 h-4 shrink-0 fill-amber-400 text-amber-500" />
                                      }
                                      <span>{folderKey}</span>
                                      <span className="text-zinc-600 text-xs font-normal">{folderSecrets.length} {folderSecrets.length === 1 ? "secret" : "secrets"}</span>
                                    </button>
                                    <button
                                      onClick={() => {
                                        setNewSecret(prev => ({ ...prev, folder: folderKey }));
                                        setIsAdding(true);
                                      }}
                                      className="opacity-0 group-hover/folder:opacity-100 flex items-center gap-1 text-xs text-zinc-500 hover:text-violet-400 transition-all px-2 py-1 rounded-lg hover:bg-zinc-900"
                                      title={`Add secret to ${folderKey}`}
                                    >
                                      <Plus className="w-3 h-3" /> Add
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            )}
                            {!isCollapsed && folderSecrets.map((secret) => {
                        const info = getLevelInfo(secret.level);
                        const isRevealed = revealedSecrets.has(secret.id);
                        const displayValue = isRevealed
                          ? (revealedValues[secret.id] ?? "••••••••••••••••")
                          : "••••••••••••••••";
                        
                        if (editingSecret === secret.id) {
                          return (
                            <tr key={secret.id} className="bg-zinc-800/20">
                              <td className="px-6 py-4">
                                <input 
                                  autoFocus
                                  className="w-full bg-zinc-950 border border-zinc-800 px-2 py-1 rounded text-white text-sm focus:outline-none focus:border-violet-600" 
                                  value={editForm.name} 
                                  onChange={e => setEditForm(prev => ({...prev, name: e.target.value}))} 
                                />
                              </td>
                              <td className="px-6 py-4">
                                <select 
                                  className="w-full bg-zinc-950 border border-zinc-800 px-2 py-1 rounded text-white text-sm focus:outline-none focus:border-violet-600"
                                  value={editForm.type}
                                  onChange={e => setEditForm(prev => ({...prev, type: e.target.value}))}
                                >
                                  <option value="email">Email</option>
                                  <option value="username">Username</option>
                                  <option value="national_id">National ID</option>
                                  <option value="password">Password</option>
                                  <option value="pin">PIN</option>
                                  <option value="passphrase">Passphrase</option>
                                  <option value="totp_seed">TOTP Seed</option>
                                  <option value="api_key">API Key</option>
                                  <option value="crypto_seed">Crypto Seed</option>
                                  <option value="nfc_card">NFC Card</option>
                                  <option value="note">Secure Note</option>
                                  <option value="custom">Custom</option>
                                </select>
                              </td>
                              <td className="px-6 py-4">
                                <span className="font-mono text-zinc-500 text-xs">•••••••• (unchanged)</span>
                              </td>
                              <td className="px-6 py-4">
                                <div className="flex flex-col gap-1.5">
                                  <input
                                    className="w-full bg-zinc-950 border border-zinc-800 px-2 py-1 rounded text-white text-sm focus:outline-none focus:border-violet-600"
                                    value={editForm.tags}
                                    placeholder="tags, comma separated"
                                    onChange={e => setEditForm(prev => ({...prev, tags: e.target.value}))}
                                  />
                                  <FolderInput
                                    value={editForm.folder}
                                    onChange={v => setEditForm(prev => ({...prev, folder: v}))}
                                    folders={[...new Set<string>(
                                      secrets
                                        .filter(s => s.level === secret.level && s.folder)
                                        .map(s => s.folder!)
                                    )]}
                                  />
                                </div>
                              </td>
                              <td className="px-6 py-4 text-right">
                                <div className="flex justify-end gap-2">
                                  <button onClick={() => setEditingSecret(null)} className="text-zinc-500 hover:text-white p-1 rounded hover:bg-zinc-800 transition-colors" title="Cancel"><X className="w-4 h-4" /></button>
                                  <button onClick={() => handleEditSave(secret.id)} className="text-violet-600 hover:text-violet-600 p-1 rounded hover:bg-violet-600/40 transition-colors" title="Save"><Check className="w-4 h-4" /></button>
                                </div>
                              </td>
                            </tr>
                          );
                        }

                        return (
                          <tr
                            key={secret.id}
                            className="hover:bg-zinc-900/40 transition-all duration-100 group"
                          >
                            <td
                              className="px-6 py-4 font-medium text-zinc-200 cursor-default select-none"
                              onDoubleClick={() => copyToClipboard(secret.name)}
                              title="Double-click to copy"
                            >
                              {secret.name}
                            </td>
                            <td className="px-6 py-4" onDoubleClick={() => setShowLevelCol(v => !v)}>
                              <div className="flex items-center gap-3">
                                {isRevealed && secret.secret_type === "totp_seed"
                                  ? <TotpCodeDisplay seed={revealedValues[secret.id] ?? ""} />
                                  : <span
                                      onDoubleClick={(e) => { e.stopPropagation(); copySecret(secret.id, secret.level, secret.encrypted_value); }}
                                      className={`font-mono text-xs select-none cursor-default ${isRevealed ? 'text-violet-600' : 'text-zinc-500 tracking-widest'}`}
                                      title="Double-click to copy"
                                    >{displayValue}</span>
                                }
                                <button
                                  onClick={() => toggleReveal(secret.id, secret.level, secret.encrypted_value)}
                                  onDoubleClick={e => e.stopPropagation()}
                                  className="text-zinc-500 hover:text-zinc-300 transition-colors"
                                  title={isRevealed ? "Hide value" : "Reveal value"}
                                >
                                  {isRevealed ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                              </div>
                            </td>
                            {showLevelCol && (
                              <td className="px-4 py-4">
                                <span className="px-2 py-0.5 rounded text-xs font-medium border border-zinc-700/60 text-zinc-400">
                                  lvl{secret.level}
                                </span>
                              </td>
                            )}
                            <td className="px-6 py-4">
                              <div className="flex flex-wrap gap-1.5">
                                {secret.tags.map((tag) => (
                                  <span key={tag} className="bg-zinc-950 border border-zinc-800 text-zinc-400 px-2 py-0.5 rounded text-xs">
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            </td>
                            <td className="px-6 py-4 text-right">
                              <div className="flex justify-end gap-1">
                                <button
                                  onClick={() => {
                                    setEditingSecret(secret.id);
                                    setEditForm({ name: secret.name, type: secret.secret_type || 'custom', tags: secret.tags.join(', '), url: secret.url || '', username: secret.username || '', folder: secret.folder || '' });
                                  }}
                                  className="text-zinc-500 hover:text-blue-400 opacity-0 group-hover:opacity-100 transition-all p-1"
                                  title="Edit Secret"
                                >
                                  <Pencil className="w-4 h-4" />
                                </button>
                                <button
                                  onClick={() => handleDeleteSecret(secret.id)}
                                  className="text-zinc-500 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all p-1"
                                  title="Delete Secret"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                          </React.Fragment>
                        );
                      });
                    })()}
                    {secrets.filter((s) => authLevel < 4 && s.level >= authLevel && (vaultLevelFilter.length === 0 || vaultLevelFilter.includes(s.level))).length === 0 && !isAdding && authLevel < 4 && (
                      <tr>
                        <td
                          colSpan={5}
                          className="px-6 py-16 text-center text-zinc-500"
                        >
                          <div className="flex flex-col items-center justify-center gap-3">
                            <Key className="w-8 h-8 text-zinc-700" />
                            <p>No secrets found at your current clearance lvl.</p>
                          </div>
                        </td>
                      </tr>
                    )}
                    {authLevel === 4 && !isAdding && (
                      <tr>
                        <td
                          colSpan={5}
                          className="px-6 py-16 text-center text-zinc-500"
                        >
                          <div className="flex flex-col items-center justify-center gap-3">
                            <div className="relative flex items-center justify-center w-8 h-8">
                              <Hexagon className="absolute w-8 h-8 text-zinc-700/40" strokeWidth={1.5} />
                              <Fingerprint className="absolute w-4 h-4 text-zinc-700" strokeWidth={2} />
                            </div>
                            <p>lvl is in standby. Scroll the lvl selector to view assets.</p>
                          </div>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </motion.div>
          )}

          {activeTab === "logs" && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="w-full space-y-6"
            >
              <div className="bg-zinc-950/50 border border-zinc-900 rounded-xl overflow-hidden shadow-2xl">
                <table className="w-full text-left text-sm">
                  <thead className="bg-black/60 text-zinc-600 text-[10px] uppercase tracking-widest border-b border-zinc-900">
                    <tr>
                      <th className="px-6 py-4 font-medium">Time</th>
                      <th className="px-6 py-4 font-medium">Action</th>
                      <th className="px-6 py-4 font-medium">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.filter(log => logsLevelFilter.length === 0 || logsLevelFilter.includes(log.user_level)).map((log) => {
                      const details = (() => {
                        try {
                          const d = JSON.parse(log.details);
                          if (log.action === "auth_success") return `Unlocked lvl${d.level}`;
                          if (log.action === "auth_failed") return `Failed attempt on lvl${d.level}`;
                          if (log.action === "auth_failed_totp") return `Wrong TOTP code on lvl${d.level}`;
                          if (log.action === "create_secret") return `Added "${d.name}"`;
                          if (log.action === "update_secret") return `Edited "${d.name}"`;
                          if (log.action === "delete_secret") return `Deleted secret ${d.id?.slice(0,8)}…`;
                          if (log.action === "setup_credential") return `Credential set for lvl${d.level}`;
                          if (log.action === "totp_enabled") return `TOTP enabled on lvl${d.level}`;
                          if (log.action === "totp_disabled") return `TOTP disabled on lvl${d.level}`;
                          if (log.action === "kem_key_updated") return `KEM key rotated for lvl${d.level}`;
                          return log.details;
                        } catch { return log.details; }
                      })();
                      return (
                        <tr key={log.id} className="hover:bg-zinc-900/40 transition-all duration-100">
                          <td className="px-6 py-4 text-zinc-400 font-mono text-xs">
                            {new Date(log.created_at).toLocaleString()}
                          </td>
                          <td className="px-6 py-4 text-zinc-200 font-medium">
                            {log.action.replace(/_/g, ' ')}
                          </td>
                          <td className="px-6 py-4 text-xs text-zinc-500">
                            {details}
                          </td>
                        </tr>
                      );
                    })}
                    {logs.length === 0 && (
                      <tr>
                        <td
                          colSpan={4}
                          className="px-6 py-12 text-center text-zinc-500"
                        >
                          No session logs found.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </motion.div>
          )}

          {activeTab === "docs" && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="w-full space-y-6"
            >
              <div className="flex items-start gap-4 bg-amber-500/10 border border-amber-500/20 p-4 rounded-xl mb-6 shadow-sm">
                <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-amber-500 font-medium mb-1">
                    Security Compliance Pack
                  </h4>
                  <p className="text-amber-500/80 text-sm">
                    These documents are required for Security compliance. In a
                    full deployment, these would be populated with your
                    organization's specific details.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {[
                  "01_Privacy_Governance_Framework.md",
                  "02_Data_Classification_Policy.md",
                  "03_Access_Control_Policy.md",
                  "04_Incident_Response_Plan.md",
                  "05_Data_Retention_Schedule.md",
                  "06_Third_Party_Risk_Management.md",
                  "07_Employee_Training_Log.md",
                  "08_Privacy_Impact_Assessment_Template.md",
                ].map((doc) => (
                  <div
                    key={doc}
                    className="bg-zinc-950 border border-zinc-800 p-5 rounded-xl hover:border-zinc-700 hover:bg-zinc-800/50 transition-all cursor-pointer group shadow-sm"
                  >
                    <div className="flex items-center gap-3 mb-3">
                      <div className="p-2 bg-zinc-950 rounded-lg group-hover:bg-violet-600/10 transition-colors">
                        <FileText className="w-5 h-5 text-zinc-500 group-hover:text-violet-600 transition-colors" />
                      </div>
                      <h3 className="text-sm font-medium text-zinc-200 truncate" title={doc}>
                        {doc}
                      </h3>
                    </div>
                    <p className="text-xs text-zinc-500 flex items-center gap-1">
                      <Activity className="w-3 h-3" /> Last updated: Today
                    </p>
                  </div>
                ))}
              </div>
            </motion.div>
          )}
        </main>
      </div>

      {/* Settings Panel */}
      <AnimatePresence>
        {showSettings && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowSettings(false)}
              className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40"
            />
            {/* Slide-over panel */}
            <motion.div
              initial={{ x: "100%" }}
              animate={{ x: 0 }}
              exit={{ x: "100%" }}
              transition={{ type: "spring", stiffness: 300, damping: 30 }}
              className="fixed right-0 top-0 h-full w-full max-w-xl bg-black border-l border-zinc-900 z-50 flex flex-col shadow-2xl"
            >
              {/* Header */}
              <div className="flex items-center justify-between px-8 py-6 border-b border-zinc-800">
                <div>
                  <h2 className="text-xl font-bold text-white tracking-tight">Settings</h2>
                  <p className="text-zinc-500 text-sm mt-0.5">Configure vault behaviour &amp; security policies</p>
                </div>
                <button
                  onClick={() => setShowSettings(false)}
                  className="p-1.5 rounded-lg text-zinc-500 hover:text-white hover:bg-zinc-800 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Tabs */}
              <div className="flex gap-1 px-8 pt-4 border-b border-zinc-800">
                {(["auth", "docs"] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => setSettingsTab(t)}
                    className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                      settingsTab === t
                        ? "text-white border-b-2 border-violet-600"
                        : "text-zinc-500 hover:text-zinc-300"
                    }`}
                  >
                    {t === "auth" ? "Authentication" : "Security Docs"}
                  </button>
                ))}
              </div>

              {/* Content */}
              <div className="flex-1 overflow-y-auto px-8 py-6 space-y-8">

                {settingsTab === "auth" && (
                  <>
                    {/* Section: Level Credentials */}
                    <section>
                      <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-4">Level Credentials</h3>
                      <p className="text-xs text-zinc-600 mb-3">
                        Set your own credentials to replace the dev defaults. lvl3: numeric PIN (min 6 digits). lvl0–lvl2: alphanumeric passphrase (min 6 chars, must contain letters + numbers).
                      </p>
                      <CredentialSetup authLevel={authLevel} sessionToken={sessionToken} />
                    </section>

                    {/* Section: Session TTL */}
                    <section>
                      <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-4">Session Expiry (TTL)</h3>
                      <div className="space-y-3">
                        {[
                          { level: 3, label: "lvl3 Session", options: ["1h", "8h", "24h", "Never"] },
                          { level: 2, label: "lvl2 Session", options: ["30m", "1h", "4h", "8h"] },
                          { level: 1, label: "lvl1 Session", options: ["15m", "30m", "1h", "2h"] },
                          { level: 0, label: "lvl0 Session", options: ["Never cached"] },
                        ].filter(({ level }) => authLevel <= level).map(({ level, label, options }) => (
                          <div key={level} className="flex items-center justify-between bg-zinc-950 border border-zinc-800 px-5 py-4 rounded-xl">
                            <div>
                              <p className="text-sm font-medium text-zinc-300">{label}</p>
                              <p className="text-xs text-zinc-500 mt-0.5">Token expires after unlock</p>
                            </div>
                            <select
                              value={sessionTtls[level] || options[0]}
                              disabled={level === 0}
                              onChange={async e => {
                                const ttl = e.target.value;
                                setSessionTtls(prev => ({ ...prev, [level]: ttl }));
                                await fetch(`/api/auth/session-ttl/${level}`, {
                                  method: "PUT",
                                  headers: { "Content-Type": "application/json", ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}) },
                                  body: JSON.stringify({ ttl }),
                                });
                              }}
                              className="bg-zinc-900 border border-zinc-700 text-sm text-zinc-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-violet-500 disabled:opacity-40 disabled:cursor-not-allowed"
                            >
                              {options.map(o => <option key={o}>{o}</option>)}
                            </select>
                          </div>
                        ))}
                      </div>
                    </section>

                    {/* Section: Auto-Lock */}
                    <section>
                      <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-4">Auto-Lock Triggers</h3>
                      <div className="space-y-3">
                        {[
                          { id: "lock-screen", label: "Lock on screen lock", desc: "Lock vault when OS screen locks", default: true },
                          { id: "lock-idle", label: "Lock on idle", desc: "Lock after system idle timeout", default: true },
                          { id: "lock-suspend", label: "Lock on suspend/sleep", desc: "Lock vault on system suspend", default: true },
                          { id: "lock-focus", label: "Lock on app focus loss", desc: "Lock lvl0 when window loses focus", default: false },
                        ].map(({ id, label, desc, default: def }) => (
                          <label key={id} className="flex items-center justify-between bg-zinc-950 border border-zinc-800 px-5 py-4 rounded-xl cursor-pointer group">
                            <div>
                              <p className="text-sm font-medium text-zinc-200">{label}</p>
                              <p className="text-xs text-zinc-500 mt-0.5">{desc}</p>
                            </div>
                            <div className={`w-10 h-6 rounded-full transition-colors flex items-center px-1 ${ def ? 'bg-violet-600' : 'bg-zinc-700'}`}>
                              <div className={`w-4 h-4 rounded-full bg-white transition-transform ${def ? 'translate-x-4' : 'translate-x-0'}`} />
                            </div>
                          </label>
                        ))}
                      </div>
                    </section>

                    {/* Section: Lockout Policy */}
                    <section>
                      <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-4">Lockout Policy</h3>
                      <div className="space-y-3">
                        <div className="flex items-center justify-between bg-zinc-950 border border-zinc-800 px-5 py-4 rounded-xl">
                          <div>
                            <p className="text-sm font-medium text-zinc-200">Failed attempt limit</p>
                            <p className="text-xs text-zinc-500 mt-0.5">Lock vault after N failed auth attempts</p>
                          </div>
                          <select defaultValue="5" className="bg-zinc-950 border border-zinc-700 text-sm text-zinc-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-violet-600">
                            {["3", "5", "10", "Unlimited"].map(o => <option key={o}>{o}</option>)}
                          </select>
                        </div>
                        <div className="flex items-center justify-between bg-zinc-950 border border-zinc-800 px-5 py-4 rounded-xl">
                          <div>
                            <p className="text-sm font-medium text-zinc-200">Lockout duration</p>
                            <p className="text-xs text-zinc-500 mt-0.5">How long to lock out after limit reached</p>
                          </div>
                          <select defaultValue="5m" className="bg-zinc-950 border border-zinc-700 text-sm text-zinc-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-violet-600">
                            {["1m", "5m", "15m", "1h", "Forever"].map(o => <option key={o}>{o}</option>)}
                          </select>
                        </div>
                        <div className="flex items-center justify-between bg-zinc-950 border border-zinc-800 px-5 py-4 rounded-xl">
                          <div>
                            <p className="text-sm font-medium text-zinc-200">Wipe on max failures</p>
                            <p className="text-xs text-zinc-500 mt-0.5">Nuke all cached session keys after repeated failures</p>
                          </div>
                          <div className="w-10 h-6 rounded-full bg-zinc-700 flex items-center px-1">
                            <div className="w-4 h-4 rounded-full bg-white" />
                          </div>
                        </div>
                      </div>
                    </section>

                    {/* Section: TOTP */}
                    <section>
                      <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-4">TOTP Authenticator (2FA)</h3>
                      <p className="text-xs text-zinc-600 mb-3">Enable TOTP for any level using Google Authenticator, Authy, or any RFC 6238-compatible app.</p>
                      <div className="space-y-3">
                        {[
                          { level: 3, label: "lvl3 — Everyday", color: "text-zinc-300" },
                          { level: 2, label: "lvl2 — Professional", color: "text-blue-400" },
                          { level: 1, label: "lvl1 — Personal", color: "text-amber-400" },
                          { level: 0, label: "lvl0 — Critical", color: "text-red-400" },
                        ].filter(({ level }) => authLevel <= level).map(({ level, label, color }) => (
                          <div key={level} className="bg-zinc-950 border border-zinc-800 px-5 py-4 rounded-xl">
                            <div className="flex items-center justify-between">
                              <div>
                                <p className={`text-sm font-medium ${color}`}>{label}</p>
                                <p className="text-xs text-zinc-500 mt-0.5">
                                  {totpStatus[level] ? "TOTP enabled — required on unlock" : "TOTP not configured"}
                                </p>
                              </div>
                              <div className="flex gap-2">
                                {totpStatus[level] ? (
                                  <button
                                    onClick={() => handleTotpDisable(level)}
                                    disabled={authLevel > level}
                                    className="text-xs text-red-400 hover:text-red-300 border border-red-900 hover:border-red-700 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                                  >
                                    Disable
                                  </button>
                                ) : (
                                  <button
                                    onClick={() => handleTotpSetup(level)}
                                    disabled={authLevel > level}
                                    className="text-xs text-violet-600 hover:text-violet-600 border border-violet-600 hover:border-violet-600 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                                  >
                                    Set Up
                                  </button>
                                )}
                              </div>
                            </div>

                            {/* TOTP Setup Panel */}
                            {totpSetup?.level === level && (
                              <div className="mt-4 pt-4 border-t border-zinc-800 space-y-4">
                                <p className="text-xs text-zinc-400">
                                  Scan the QR code in your authenticator app, or manually enter the secret key below.
                                  Then enter the 6-digit code to confirm.
                                </p>
                                <div className="bg-zinc-950 rounded-lg p-3 space-y-2">
                                  <p className="text-xs text-zinc-500 uppercase tracking-wider">Secret Key</p>
                                  <div className="flex items-center gap-2">
                                    <code className="text-violet-600 font-mono text-sm break-all flex-1">{totpSetup.secret}</code>
                                    <button
                                      onClick={() => copyToClipboard(totpSetup.secret)}
                                      className="text-zinc-500 hover:text-white transition-colors shrink-0"
                                      title="Copy secret"
                                    >
                                      <Copy className="w-4 h-4" />
                                    </button>
                                  </div>
                                  <p className="text-xs text-zinc-600 pt-1">
                                    Or{" "}
                                    <a href={totpSetup.uri} className="text-violet-600 hover:underline">
                                      open in authenticator app
                                    </a>
                                  </p>
                                </div>
                                <div className="flex gap-2">
                                  <input
                                    type="text"
                                    inputMode="numeric"
                                    maxLength={6}
                                    value={totpConfirmCode}
                                    onChange={e => { setTotpConfirmCode(e.target.value); setTotpConfirmError(""); }}
                                    placeholder="Enter 6-digit code"
                                    className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white font-mono tracking-[0.5em] focus:outline-none focus:border-violet-600 text-center"
                                  />
                                  <button
                                    onClick={handleTotpConfirm}
                                    disabled={totpConfirmCode.length !== 6}
                                    className="px-4 py-2 bg-violet-600 hover:bg-violet-600 disabled:opacity-40 text-white rounded-lg text-sm font-medium transition-colors"
                                  >
                                    Verify
                                  </button>
                                  <button
                                    onClick={() => setTotpSetup(null)}
                                    className="px-3 py-2 text-zinc-400 hover:text-white border border-zinc-800 rounded-lg text-sm transition-colors"
                                  >
                                    Cancel
                                  </button>
                                </div>
                                {totpConfirmError && (
                                  <p className="text-red-400 text-xs">{totpConfirmError}</p>
                                )}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </section>

                    {/* Section: Security Key */}
                    <section>
                      <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-4">Security Keys (3FA)</h3>
                      <div className="space-y-3">
                        <div className="bg-zinc-950 border border-zinc-800 px-5 py-4 rounded-xl">
                          <div className="flex items-center justify-between mb-3">
                            <p className="text-sm font-medium text-zinc-200">Registered keys</p>
                            <button className="text-xs text-violet-600 hover:text-violet-600 border border-violet-600 hover:border-violet-600 px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5">
                              <Key className="w-3.5 h-3.5" /> Register New
                            </button>
                          </div>
                          <div className="text-xs text-zinc-500 italic">No security keys registered yet.</div>
                        </div>
                        <div className="flex items-center justify-between bg-zinc-950 border border-zinc-800 px-5 py-4 rounded-xl">
                          <div>
                            <p className="text-sm font-medium text-zinc-200">Require key touch</p>
                            <p className="text-xs text-zinc-500 mt-0.5">Require physical key tap for each auth</p>
                          </div>
                          <div className="w-10 h-6 rounded-full bg-violet-600 flex items-center px-1">
                            <div className="w-4 h-4 rounded-full bg-white translate-x-4" />
                          </div>
                        </div>
                      </div>
                    </section>

                    {/* Section: Advanced */}
                    <section>
                      <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-4">Advanced</h3>
                      <div className="space-y-3">
                        {[
                          { id: "mem-lock", label: "mlock pinned memory", desc: "Prevent Lvl 0/1 keys from being swapped to disk", default: true },
                          { id: "zero-on-lock", label: "Zero memory on lock", desc: "Overwrite session keys in RAM when vault locks", default: true },
                          { id: "audit-reveal", label: "Log secret reveals", desc: "Write to session log whenever a secret value is revealed", default: false },
                          { id: "clipboard-clear", label: "Auto-clear clipboard", desc: "Clear clipboard 30s after copying a secret value", default: true },
                          { id: "anti-phish", label: "Anti-phishing protection", desc: "Warn when vault URL does not match registered domain", default: true },
                        ].map(({ id, label, desc, default: def }) => (
                          <label key={id} className="flex items-center justify-between bg-zinc-950 border border-zinc-800 px-5 py-4 rounded-xl cursor-pointer">
                            <div>
                              <p className="text-sm font-medium text-zinc-200">{label}</p>
                              <p className="text-xs text-zinc-500 mt-0.5">{desc}</p>
                            </div>
                            <div className={`w-10 h-6 rounded-full transition-colors flex items-center px-1 ${ def ? 'bg-violet-600' : 'bg-zinc-700'}`}>
                              <div className={`w-4 h-4 rounded-full bg-white transition-transform ${def ? 'translate-x-4' : 'translate-x-0'}`} />
                            </div>
                          </label>
                        ))}
                      </div>
                    </section>

                    {/* Section: Danger Zone */}
                    <section>
                      <h3 className="text-xs font-semibold text-red-500/70 uppercase tracking-widest mb-4">Danger Zone</h3>
                      <NukeVault />
                    </section>
                  </>
                )}

                {settingsTab === "docs" && (
                  <>
                    <div className="flex items-start gap-4 bg-amber-500/10 border border-amber-500/20 p-4 rounded-xl shadow-sm">
                      <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
                      <div>
                        <h4 className="text-amber-500 font-medium mb-1">Security Compliance Pack</h4>
                        <p className="text-amber-500/80 text-sm">These documents would be populated with your specific deployment details in production.</p>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 gap-3">
                      {[
                        "01_Privacy_Governance_Framework.md",
                        "02_Data_Classification_Policy.md",
                        "03_Access_Control_Policy.md",
                        "04_Incident_Response_Plan.md",
                        "05_Data_Retention_Schedule.md",
                        "06_Third_Party_Risk_Management.md",
                        "07_Employee_Training_Log.md",
                        "08_Privacy_Impact_Assessment_Template.md",
                      ].map((doc) => (
                        <div key={doc} className="flex items-center gap-4 bg-zinc-950 border border-zinc-800 px-5 py-4 rounded-xl hover:border-zinc-700 hover:bg-zinc-800/50 transition-all cursor-pointer group">
                          <div className="p-2 bg-zinc-950 rounded-lg group-hover:bg-violet-600/10 transition-colors shrink-0">
                            <FileText className="w-4 h-4 text-zinc-500 group-hover:text-violet-600 transition-colors" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-zinc-200 truncate">{doc}</p>
                            <p className="text-xs text-zinc-500 mt-0.5">Last updated: Today</p>
                          </div>
                          <Shield className="w-4 h-4 text-zinc-600 group-hover:text-violet-600 transition-colors shrink-0" />
                        </div>
                      ))}
                    </div>
                  </>
                )}

              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
