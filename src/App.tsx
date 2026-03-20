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
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Download,
  Upload,
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
import { encryptForLevel, decryptForLevel, generateKemKeyPair, hybridEncrypt, encryptAES, decryptAES } from "./lib/crypto";

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
          transition={{ type: "spring", stiffness: 320, damping: 38, mass: 0.5 }}
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
  configuredLevels: Record<number, boolean>;
  authInput: string;
  setAuthInput: (v: string) => void;
  totpInput: string;
  setTotpInput: (v: string) => void;
  authError: string;
  setAuthError: (v: string) => void;
  authLoading: boolean;
  handleAuth: (e?: React.FormEvent) => void;
  onClose: () => void;
  onSetupAuth: () => void;
}

function AuthModal({ authLevel, targetLevel, totpStatus, configuredLevels, authInput, setAuthInput, totpInput, setTotpInput, authError, setAuthError, authLoading, handleAuth, onClose, onSetupAuth }: AuthModalProps) {
  const [showPass, setShowPass] = useState(false);

  if (authLevel === 0) return null;

  const levelColor = targetLevel === 3 ? "bg-zinc-800 text-zinc-300"
    : targetLevel === 2 ? "bg-indigo-900/20 text-indigo-300"
    : targetLevel === 1 ? "bg-amber-900/15 text-amber-300"
    : "bg-rose-900/15 text-rose-300";

  const levelIcon = targetLevel === 3 ? <Lock className="w-10 h-10" />
    : targetLevel === 2 ? <Fingerprint className="w-10 h-10" />
    : targetLevel === 1 ? <Key className="w-10 h-10" />
    : <Shield className="w-10 h-10" />;

  const levelDesc = targetLevel === 3 ? "Enter your PIN to access the vault"
    : targetLevel === 2 ? "Enter your passphrase to continue"
    : targetLevel === 1 ? "Enter your credential to continue"
    : "Enter your master passphrase";

  const btnClass = targetLevel === 3 ? "bg-zinc-700 hover:bg-zinc-600"
    : targetLevel === 2 ? "bg-indigo-600 hover:bg-indigo-500"
    : targetLevel === 1 ? "bg-amber-600 hover:bg-amber-500"
    : "bg-rose-700 hover:bg-rose-600";

  return (
    <motion.div
      className="fixed inset-0 flex items-center justify-center z-50 p-4"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.25, ease: "easeInOut" }}
    >
      {/* Backdrop */}
      <motion.div
        className="absolute inset-0 bg-black/80 backdrop-blur-md"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
      />
      {/* Card */}
      <motion.div
        className="bg-zinc-950/90 backdrop-blur-xl border border-zinc-800/60 p-8 rounded-2xl w-full max-w-md shadow-2xl relative"
        initial={{ opacity: 0, scale: 0.97, y: 8 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.97, y: 8 }}
        transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
      >
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 rounded-lg text-zinc-500 hover:text-white hover:bg-zinc-800 transition-colors"
          title="Close"
        >
          <X className="w-4 h-4" />
        </button>
        <div className="flex justify-center mb-6">
          <motion.div
            className={`p-4 rounded-full ${levelColor}`}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.25, delay: 0.1, ease: "easeOut" }}
          >{levelIcon}</motion.div>
        </div>
        {targetLevel in configuredLevels && !configuredLevels[targetLevel] ? (
          <>
            <h2 className="text-2xl font-bold text-white text-center mb-2 tracking-tight">Not Configured</h2>
            <p className="text-zinc-400 text-center mb-2 text-sm">
              lvl{targetLevel} has no credential set up yet.
            </p>
            <p className="text-zinc-600 text-center mb-8 text-xs">
              Set up authentication to unlock this security level and store secrets here.
            </p>
            <button
              onClick={onSetupAuth}
              className={`w-full font-medium py-3 rounded-xl transition-colors flex items-center justify-center gap-2 text-white ${btnClass}`}
            >
              <Key className="w-4 h-4" /> Set Up Authentication
            </button>
          </>
        ) : (
          <>
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

          {authError && <p className="text-rose-300 text-sm text-center">{authError}</p>}

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
          </>
        )}
      </motion.div>
    </motion.div>
  );
}

// ---------- Nuke Vault Component ----------
function BackupRestore({ authLevel, sessionToken }: { authLevel: number; sessionToken: string | null }) {
  const [exportPassphrase, setExportPassphrase] = React.useState("");
  const [restoreBundle, setRestoreBundle]       = React.useState<string | null>(null);
  const [restorePassphrase, setRestorePassphrase] = React.useState("");
  const [confirmRestore, setConfirmRestore]     = React.useState(false);
  const [loading, setLoading]                   = React.useState<"export" | "restore" | null>(null);
  const [status, setStatus]                     = React.useState<{ type: "success" | "error"; msg: string } | null>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  const isUnlocked = authLevel <= 0;

  const handleExport = async () => {
    setLoading("export"); setStatus(null);
    try {
      const res  = await fetch("/api/vault/backup", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${sessionToken}` },
        body: JSON.stringify({ passphrase: exportPassphrase }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Backup failed");
      const blob = new Blob([data.bundle], { type: "application/octet-stream" });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href     = url;
      a.download = `lvls-backup-${new Date().toISOString().slice(0, 10)}.lvls`;
      a.click();
      URL.revokeObjectURL(url);
      setExportPassphrase("");
      setStatus({ type: "success", msg: "Backup downloaded." });
    } catch (e: any) {
      setStatus({ type: "error", msg: e.message });
    } finally { setLoading(null); }
  };

  const handleFileLoad = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setRestoreBundle((ev.target?.result as string).trim());
    reader.readAsText(file);
  };

  const handleRestore = async () => {
    setLoading("restore"); setStatus(null);
    try {
      const res  = await fetch("/api/vault/restore", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${sessionToken}` },
        body: JSON.stringify({ bundle: restoreBundle, passphrase: restorePassphrase }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Restore failed");
      setStatus({ type: "success", msg: `Restored: ${data.stats.secrets} secrets, ${data.stats.vaults} machine vaults.` });
      setRestoreBundle(null); setRestorePassphrase(""); setConfirmRestore(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    } catch (e: any) {
      setStatus({ type: "error", msg: e.message });
    } finally { setLoading(null); }
  };

  if (!isUnlocked) {
    return (
      <div className="flex items-center gap-3 bg-zinc-900/50 border border-zinc-800/80 px-4 py-3.5 rounded-xl">
        <Lock className="w-4 h-4 text-zinc-500 shrink-0" />
        <p className="text-xs text-zinc-500">Unlock <span className="text-zinc-300 font-medium">lvl0</span> to access backup &amp; restore.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Export */}
      <div className="bg-zinc-900/50 border border-zinc-800/80 rounded-xl p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Download className="w-4 h-4 text-violet-400 shrink-0" />
          <p className="text-sm font-medium text-zinc-200">Export encrypted backup</p>
        </div>
        <p className="text-xs text-zinc-500">All secrets, auth config, and machine vaults — AES-256-GCM encrypted. Store the passphrase separately; it cannot be recovered.</p>
        <input
          type="password"
          value={exportPassphrase}
          onChange={e => setExportPassphrase(e.target.value)}
          placeholder="Backup passphrase (min 12 chars)"
          className="w-full bg-zinc-800/60 border border-zinc-700/60 rounded-lg px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-violet-600/60"
        />
        <button
          onClick={handleExport}
          disabled={!!loading || exportPassphrase.length < 12}
          className="flex items-center gap-2 px-4 py-2 bg-violet-600 hover:bg-violet-700 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"
        >
          <Download className="w-3.5 h-3.5" />
          {loading === "export" ? "Encrypting…" : "Download backup"}
        </button>
      </div>

      {/* Restore */}
      <div className="bg-zinc-900/50 border border-zinc-800/80 rounded-xl p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Upload className="w-4 h-4 text-amber-400 shrink-0" />
          <p className="text-sm font-medium text-zinc-200">Restore from backup</p>
        </div>
        <p className="text-xs text-zinc-500">Overwrites all current vault data. Cannot be undone.</p>
        <input ref={fileInputRef} type="file" accept=".lvls" onChange={handleFileLoad}
          className="block w-full text-xs text-zinc-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-medium file:bg-zinc-800 file:text-zinc-300 hover:file:bg-zinc-700 cursor-pointer"
        />
        {restoreBundle && (
          <>
            <input
              type="password"
              value={restorePassphrase}
              onChange={e => setRestorePassphrase(e.target.value)}
              placeholder="Backup passphrase"
              className="w-full bg-zinc-800/60 border border-zinc-700/60 rounded-lg px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-amber-600/60"
            />
            {!confirmRestore ? (
              <button
                onClick={() => setConfirmRestore(true)}
                disabled={!restorePassphrase}
                className="flex items-center gap-2 px-4 py-2 bg-amber-700 hover:bg-amber-600 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"
              >
                <Upload className="w-3.5 h-3.5" />
                Restore vault
              </button>
            ) : (
              <div className="flex items-center gap-2">
                <button
                  onClick={handleRestore}
                  disabled={!!loading}
                  className="flex items-center gap-2 px-4 py-2 bg-rose-700 hover:bg-rose-600 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
                >
                  {loading === "restore" ? "Restoring…" : "Confirm overwrite"}
                </button>
                <button onClick={() => setConfirmRestore(false)} className="px-3 py-2 text-zinc-400 hover:text-white border border-zinc-800 rounded-lg text-sm transition-colors">
                  Cancel
                </button>
              </div>
            )}
          </>
        )}
      </div>

      {status && (
        <p className={`text-xs px-1 ${status.type === "success" ? "text-emerald-400" : "text-rose-400"}`}>{status.msg}</p>
      )}
    </div>
  );
}

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
      <div className="bg-rose-950/20 border border-rose-900/50 rounded-xl px-5 py-4 text-center">
        <p className="text-rose-300 font-medium text-sm">Vault wiped. Reload the page to start fresh.</p>
        <button onClick={() => window.location.reload()} className="mt-3 text-xs text-zinc-400 hover:text-white border border-zinc-700 px-3 py-1.5 rounded-lg transition-colors">
          Reload Now
        </button>
      </div>
    );
  }

  return (
    <div className="bg-rose-950/10 border border-rose-900/40 rounded-xl px-5 py-4 space-y-3">
      <div className="flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-medium text-rose-300">Nuke Vault</p>
          <p className="text-xs text-zinc-500 mt-0.5">
            Permanently deletes ALL secrets, credentials, logs, and KEM keys. This cannot be undone.
          </p>
        </div>
      </div>

      {phase === "idle" && (
        <button
          onClick={() => setPhase("confirm")}
          className="text-xs text-rose-300 border border-rose-900/50 hover:border-rose-700 hover:bg-rose-950/20 px-4 py-2 rounded-lg transition-colors"
        >
          Wipe Everything
        </button>
      )}

      {phase === "confirm" && (
        <div className="space-y-2">
          <p className="text-xs text-zinc-400">
            Type <span className="font-mono text-rose-300 font-bold">{CONFIRM_PHRASE}</span> to confirm:
          </p>
          <div className="flex gap-2">
            <input
              type="text"
              value={confirmText}
              onChange={e => setConfirmText(e.target.value)}
              className="flex-1 bg-zinc-950 border border-rose-900/40 rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-rose-500/50"
              placeholder={CONFIRM_PHRASE}
              autoFocus
            />
            <button
              onClick={nuke}
              disabled={confirmText !== CONFIRM_PHRASE}
              className="bg-rose-800 hover:bg-rose-700 disabled:opacity-30 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
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
function CredentialSetup({ authLevel, sessionToken, configuredLevels, onCredentialSaved }: {
  authLevel: number;
  sessionToken: string | null;
  configuredLevels: Record<number, boolean>;
  onCredentialSaved: (level: number) => void;
}) {
  const LEVELS = [
    { level: 3, label: "lvl3 — PIN", color: "text-zinc-300", borderColor: "border-zinc-700", hint: "Numeric digits only, min 6", inputMode: "numeric" as const, isPin: true },
    { level: 2, label: "lvl2 — Professional", color: "text-indigo-300", borderColor: "border-indigo-800/50", hint: "Alphanumeric, min 6 chars (letters + numbers)", inputMode: "text" as const, isPin: false },
    { level: 1, label: "lvl1 — Personal", color: "text-amber-300", borderColor: "border-amber-800/50", hint: "Alphanumeric, min 6 chars (letters + numbers)", inputMode: "text" as const, isPin: false },
    { level: 0, label: "lvl0 — Critical", color: "text-rose-300", borderColor: "border-rose-800/50", hint: "Alphanumeric, min 6 chars (letters + numbers)", inputMode: "text" as const, isPin: false },
  ];

  const [values, setValues] = React.useState<Record<number, { cred: string; confirm: string; saving: boolean; result: string }>>({
    0: { cred: "", confirm: "", saving: false, result: "" },
    1: { cred: "", confirm: "", saving: false, result: "" },
    2: { cred: "", confirm: "", saving: false, result: "" },
    3: { cred: "", confirm: "", saving: false, result: "" },
  });

  const statusLoaded = Object.keys(configuredLevels).length > 0;

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
        onCredentialSaved(level);
      } else {
        setResult(level, data.error || "Failed");
      }
    } catch {
      setResult(level, "Server unreachable");
    }
  };

  const setResult = (level: number, result: string) =>
    setValues(prev => ({ ...prev, [level]: { ...prev[level], saving: false, result } }));

  // Show unconfigured levels for everyone (onboarding), configured levels only if authenticated at that level
  const visibleLevels = LEVELS.filter(({ level }) =>
    !statusLoaded || !configuredLevels[level] || authLevel <= level
  );

  if (visibleLevels.length === 0) {
    return <p className="text-xs text-zinc-600">Unlock a level first to manage its credential.</p>;
  }

  return (
    <div className="space-y-3">
      {visibleLevels.map(({ level, label, color, borderColor, hint, inputMode, isPin }) => {
        const isNew = !statusLoaded || !configuredLevels[level];
        return (
        <details key={level} open={isNew} className={`bg-zinc-950 border ${borderColor} rounded-xl`}>
          <summary className="flex items-center justify-between px-5 py-4 cursor-pointer list-none">
            <div>
              <p className={`text-sm font-medium ${color}`}>{label}</p>
              <p className="text-xs text-zinc-600 mt-0.5">{hint}</p>
            </div>
            <span className="text-xs text-zinc-400 border border-zinc-700 px-3 py-1.5 rounded-lg">
              {isNew ? "Set Up ▾" : "Change ▾"}
            </span>
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
                placeholder={isPin ? "Min 6 digits" : "Min 6 characters"}
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
                placeholder="Repeat to confirm"
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
                <span className={`text-xs ${values[level].result.startsWith("✓") ? "text-violet-600" : "text-rose-300"}`}>
                  {values[level].result}
                </span>
              )}
            </div>
          </div>
        </details>
        );
      })}
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
      <span className={`font-mono text-sm font-bold tracking-[0.3em] ${urgent ? "text-rose-300" : "text-violet-600"}`}>
        {code.slice(0, 3)} {code.slice(3)}
      </span>
      <div className="flex items-center gap-1">
        <div className="w-14 h-1 bg-zinc-800 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-1000 ${urgent ? "bg-rose-400" : "bg-violet-600"}`}
            style={{ width: `${pct}%` }}
          />
        </div>
        <span className={`text-xs font-mono tabular-nums w-5 ${urgent ? "text-rose-300" : "text-zinc-500"}`}>{secsLeft}s</span>
      </div>
      <button onClick={() => copyToClipboard(code)} className="text-zinc-500 hover:text-zinc-300 transition-colors" title="Copy code">
        <Copy className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}

// ── Onboarding ────────────────────────────────────────────────────────────────
const ONBOARDING_LEVELS = [
  { level: 2, label: "lvl2 — Professional", color: "text-indigo-300", border: "border-indigo-800/40", desc: "API keys, work credentials, IAM roles", isPin: false },
  { level: 1, label: "lvl1 — Personal",     color: "text-amber-300",  border: "border-amber-800/40",  desc: "Finance, SSH keys, health, personal IDs", isPin: false },
  { level: 0, label: "lvl0 — Critical",     color: "text-rose-300",   border: "border-rose-800/40",   desc: "Seed phrases, master identity, break-glass", isPin: false },
];

function Onboarding({ onComplete }: { onComplete: (token: string) => void }) {
  const [step, setStep] = React.useState(0); // 0=welcome 1=pin 2=higher levels 3=done
  const [direction, setDirection] = React.useState(1);

  // Step 1 — PIN
  const [pin, setPin] = React.useState("");
  const [pinConfirm, setPinConfirm] = React.useState("");
  const [pinError, setPinError] = React.useState("");
  const [pinLoading, setPinLoading] = React.useState(false);
  const [vaultToken, setVaultToken] = React.useState("");

  // Step 2 — optional higher levels
  const [levelCreds, setLevelCreds] = React.useState<Record<number, { cred: string; confirm: string; skip: boolean; done: boolean; error: string }>>({
    2: { cred: "", confirm: "", skip: false, done: false, error: "" },
    1: { cred: "", confirm: "", skip: false, done: false, error: "" },
    0: { cred: "", confirm: "", skip: false, done: false, error: "" },
  });
  const [levelSaving, setLevelSaving] = React.useState<number | null>(null);

  const go = (next: number) => {
    setDirection(next > step ? 1 : -1);
    setStep(next);
  };

  const handleCreatePin = async () => {
    setPinError("");
    if (!/^\d+$/.test(pin)) return setPinError("PIN must be digits only");
    if (pin.length < 6) return setPinError("At least 6 digits required");
    if (pin !== pinConfirm) return setPinError("PINs don't match");
    setPinLoading(true);
    try {
      const res = await fetch("/api/auth/bootstrap", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: pin }),
      });
      const data = await res.json();
      if (!res.ok) return setPinError(data.error || "Setup failed");
      setVaultToken(data.token);
      go(2);
    } catch {
      setPinError("Cannot reach server");
    } finally {
      setPinLoading(false);
    }
  };

  const handleSaveLevel = async (level: number) => {
    const { cred, confirm } = levelCreds[level];
    if (!cred) return setLevelCreds(p => ({ ...p, [level]: { ...p[level], error: "Enter a passphrase" } }));
    if (cred.length < 6) return setLevelCreds(p => ({ ...p, [level]: { ...p[level], error: "At least 6 characters" } }));
    if (!/[a-zA-Z]/.test(cred) || !/[0-9]/.test(cred)) return setLevelCreds(p => ({ ...p, [level]: { ...p[level], error: "Mix of letters and numbers required" } }));
    if (cred !== confirm) return setLevelCreds(p => ({ ...p, [level]: { ...p[level], error: "Passphrases don't match" } }));
    setLevelSaving(level);
    setLevelCreds(p => ({ ...p, [level]: { ...p[level], error: "" } }));
    try {
      const res = await fetch("/api/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${vaultToken}` },
        body: JSON.stringify({ level, credential: cred, method: "passphrase" }),
      });
      const data = await res.json();
      if (!res.ok) return setLevelCreds(p => ({ ...p, [level]: { ...p[level], error: data.error || "Failed" } }));
      setLevelCreds(p => ({ ...p, [level]: { ...p[level], done: true } }));
    } catch {
      setLevelCreds(p => ({ ...p, [level]: { ...p[level], error: "Cannot reach server" } }));
    } finally {
      setLevelSaving(null);
    }
  };

  const allHigherLevelsDone = ONBOARDING_LEVELS.every(({ level }) => levelCreds[level].done || levelCreds[level].skip);

  const variants = {
    enter: (d: number) => ({ x: d > 0 ? 48 : -48, opacity: 0 }),
    center: { x: 0, opacity: 1 },
    exit: (d: number) => ({ x: d > 0 ? -48 : 48, opacity: 0 }),
  };

  const STEPS = 4;
  const steps = [
    // ── Step 0: Welcome ──────────────────────────────────────────────────────
    <div key="welcome" className="flex flex-col items-center text-center gap-6">
      <img src="/logo.png" alt="lvls" className="h-16 w-auto object-contain opacity-90" />
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight mb-2">Welcome to lvls</h1>
        <p className="text-zinc-400 text-sm leading-relaxed max-w-xs">
          Your local-first key vault. Four independent security levels,
          each with its own credential and encryption key.
          Nothing leaves your machine.
        </p>
      </div>
      <div className="w-full bg-zinc-900/60 border border-zinc-800/60 rounded-xl px-5 py-4 text-left space-y-2.5">
        {[
          { color: "bg-zinc-500", label: "lvl3", desc: "Everyday — social, Wi-Fi, subscriptions" },
          { color: "bg-indigo-500/70", label: "lvl2", desc: "Professional — API keys, IAM, work creds" },
          { color: "bg-amber-500/60", label: "lvl1", desc: "Personal — finance, SSH, health data" },
          { color: "bg-rose-500/60", label: "lvl0", desc: "Critical — seed phrases, master keys" },
        ].map(({ color, label, desc }) => (
          <div key={label} className="flex items-center gap-3">
            <span className={`w-2 h-2 rounded-full shrink-0 ${color}`} />
            <span className="text-xs font-mono text-zinc-300 w-8 shrink-0">{label}</span>
            <span className="text-xs text-zinc-500">{desc}</span>
          </div>
        ))}
      </div>
      <button
        onClick={() => go(1)}
        className="w-full bg-violet-700 hover:bg-violet-600 text-white font-medium py-3 rounded-xl transition-colors"
      >
        Begin Setup
      </button>
    </div>,

    // ── Step 1: Create PIN ────────────────────────────────────────────────────
    <div key="pin" className="flex flex-col gap-5">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <Lock className="w-4 h-4 text-zinc-400" />
          <h2 className="text-lg font-semibold text-white">Create your vault PIN</h2>
        </div>
        <p className="text-zinc-500 text-xs leading-relaxed">
          lvl3 is your entry point. This PIN unlocks everyday secrets and gives access to the rest of the vault. Min 6 digits.
        </p>
      </div>
      <div className="space-y-3">
        <input
          type="password"
          inputMode="numeric"
          placeholder="PIN (digits only, min 6)"
          value={pin}
          onChange={e => { setPin(e.target.value); setPinError(""); }}
          onKeyDown={e => e.key === "Enter" && handleCreatePin()}
          className="w-full bg-zinc-900 border border-zinc-700 rounded-xl px-4 py-3 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-violet-600 font-mono tracking-widest"
          autoFocus
        />
        <input
          type="password"
          inputMode="numeric"
          placeholder="Confirm PIN"
          value={pinConfirm}
          onChange={e => { setPinConfirm(e.target.value); setPinError(""); }}
          onKeyDown={e => e.key === "Enter" && handleCreatePin()}
          className="w-full bg-zinc-900 border border-zinc-700 rounded-xl px-4 py-3 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-violet-600 font-mono tracking-widest"
        />
        {pinError && <p className="text-rose-300 text-xs">{pinError}</p>}
      </div>
      <button
        onClick={handleCreatePin}
        disabled={pinLoading}
        className="w-full bg-violet-700 hover:bg-violet-600 disabled:opacity-40 text-white font-medium py-3 rounded-xl transition-colors"
      >
        {pinLoading ? "Setting up…" : "Create PIN & Continue"}
      </button>
    </div>,

    // ── Step 2: Optional higher levels ───────────────────────────────────────
    <div key="levels" className="flex flex-col gap-4">
      <div>
        <h2 className="text-lg font-semibold text-white mb-1">Secure your higher levels</h2>
        <p className="text-zinc-500 text-xs leading-relaxed">
          Optional — configure these now or later in Settings. Each level is fully independent.
        </p>
      </div>
      <div className="space-y-3">
        {ONBOARDING_LEVELS.map(({ level, label, color, border, desc }) => {
          const s = levelCreds[level];
          return (
            <div key={level} className={`border rounded-xl px-4 py-3.5 space-y-3 ${s.done ? "border-violet-800/40 bg-violet-950/10" : s.skip ? "border-zinc-800/40 opacity-50" : `${border} bg-zinc-900/30`}`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-sm font-medium ${color}`}>{label}</p>
                  <p className="text-xs text-zinc-600 mt-0.5">{desc}</p>
                </div>
                {s.done && <Check className="w-4 h-4 text-violet-400 shrink-0" />}
                {!s.done && (
                  <button
                    onClick={() => setLevelCreds(p => ({ ...p, [level]: { ...p[level], skip: !p[level].skip } }))}
                    className="text-xs text-zinc-600 hover:text-zinc-400 transition-colors"
                  >
                    {s.skip ? "Set up" : "Skip"}
                  </button>
                )}
              </div>
              {!s.done && !s.skip && (
                <div className="space-y-2">
                  <input
                    type="password"
                    placeholder="Passphrase (letters + numbers, min 6)"
                    value={s.cred}
                    onChange={e => setLevelCreds(p => ({ ...p, [level]: { ...p[level], cred: e.target.value, error: "" } }))}
                    className="w-full bg-zinc-950 border border-zinc-700/60 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-violet-600/60"
                  />
                  <input
                    type="password"
                    placeholder="Confirm passphrase"
                    value={s.confirm}
                    onChange={e => setLevelCreds(p => ({ ...p, [level]: { ...p[level], confirm: e.target.value, error: "" } }))}
                    className="w-full bg-zinc-950 border border-zinc-700/60 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-violet-600/60"
                  />
                  {s.error && <p className="text-rose-300 text-xs">{s.error}</p>}
                  <button
                    onClick={() => handleSaveLevel(level)}
                    disabled={levelSaving === level}
                    className="text-xs bg-zinc-800 hover:bg-zinc-700 disabled:opacity-40 text-zinc-200 px-4 py-1.5 rounded-lg transition-colors"
                  >
                    {levelSaving === level ? "Saving…" : "Save"}
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>
      <button
        onClick={() => go(3)}
        disabled={!allHigherLevelsDone}
        className="w-full bg-violet-700 hover:bg-violet-600 disabled:opacity-40 text-white font-medium py-3 rounded-xl transition-colors mt-1"
      >
        {allHigherLevelsDone ? "Continue" : "Set or skip all levels to continue"}
      </button>
    </div>,

    // ── Step 3: Done ─────────────────────────────────────────────────────────
    <div key="done" className="flex flex-col items-center text-center gap-6">
      <div className="w-16 h-16 rounded-full bg-violet-900/30 border border-violet-700/40 flex items-center justify-center">
        <Check className="w-8 h-8 text-violet-400" />
      </div>
      <div>
        <h2 className="text-2xl font-bold text-white mb-2">Vault ready</h2>
        <p className="text-zinc-400 text-sm leading-relaxed max-w-xs">
          Your credentials are encrypted and stored locally.
          {Object.values(levelCreds).some(l => l.done) && " Higher levels are active and sealed."}
          {Object.values(levelCreds).every(l => l.skip) && " You can configure higher levels anytime from Settings."}
        </p>
      </div>
      <div className="w-full bg-zinc-900/60 border border-zinc-800/60 rounded-xl px-5 py-3.5 text-left space-y-1.5">
        <p className="text-xs font-medium text-zinc-300 mb-2">Configured levels</p>
        {[
          { level: 3, label: "lvl3 — PIN", color: "text-zinc-300", active: true },
          ...ONBOARDING_LEVELS.map(l => ({ ...l, active: levelCreds[l.level].done })),
        ].map(({ level, label, color, active }) => (
          <div key={level} className="flex items-center gap-2.5">
            <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${active ? "bg-violet-500" : "bg-zinc-700"}`} />
            <span className={`text-xs font-mono ${active ? color : "text-zinc-600"}`}>{label}</span>
            <span className="text-xs text-zinc-600 ml-auto">{active ? "active" : "not set"}</span>
          </div>
        ))}
      </div>
      <button
        onClick={() => onComplete(vaultToken)}
        className="w-full bg-violet-700 hover:bg-violet-600 text-white font-medium py-3 rounded-xl transition-colors"
      >
        Enter Vault
      </button>
    </div>,
  ];

  return (
    <div className="min-h-screen bg-black flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Progress dots */}
        <div className="flex items-center justify-center gap-2 mb-8">
          {Array.from({ length: STEPS }).map((_, i) => (
            <span
              key={i}
              className={`rounded-full transition-all duration-300 ${i === step ? "w-5 h-1.5 bg-violet-500" : i < step ? "w-1.5 h-1.5 bg-violet-700" : "w-1.5 h-1.5 bg-zinc-700"}`}
            />
          ))}
        </div>

        {/* Step content */}
        <AnimatePresence mode="wait" custom={direction}>
          <motion.div
            key={step}
            custom={direction}
            variants={variants}
            initial="enter"
            animate="center"
            exit="exit"
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
          >
            {steps[step]}
          </motion.div>
        </AnimatePresence>

        {/* Back link */}
        {step > 0 && step < 3 && (
          <button
            onClick={() => go(step - 1)}
            className="mt-5 text-xs text-zinc-600 hover:text-zinc-400 transition-colors w-full text-center"
          >
            ← Back
          </button>
        )}
      </div>
    </div>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState<"vault" | "logs" | "machines">("vault");
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

  // Machine Vaults state
  interface MachineVault { id: string; name: string; description: string | null; ttl: number; totp_enabled: number; has_kem_key: number; created_at: string; secret_count?: number; }
  interface MachineSecret { id: string; name: string; classification: string; created_at: string; }
  const [machineVaults, setMachineVaults] = useState<MachineVault[]>([]);
  const [selectedVault, setSelectedVault] = useState<MachineVault | null>(null);
  const [vaultSecrets, setVaultSecrets] = useState<MachineSecret[]>([]);
  const [isAddingVault, setIsAddingVault] = useState(false);
  const [isAddingMachineSecret, setIsAddingMachineSecret] = useState(false);
  const [newVault, setNewVault] = useState({ name: "", description: "", ttl: "14400" });
  const [newMachineSecret, setNewMachineSecret] = useState({ name: "", value: "", classification: "cached" });
  const [pendingPrivateKey, setPendingPrivateKey] = useState<{ vaultName: string; privateKey: string } | null>(null);
  
  // Vault setup gate — null=loading, false=needs onboarding, true=configured
  const [isVaultSetup, setIsVaultSetup] = useState<boolean | null>(null);
  useEffect(() => {
    fetch("/api/auth/is-setup")
      .then(r => r.json())
      .then(d => setIsVaultSetup(d.configured))
      .catch(() => setIsVaultSetup(false));
  }, []);

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

  // Which levels have credentials configured
  const [configuredLevels, setConfiguredLevels] = useState<Record<number, boolean>>({});

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
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [searchOpen, setSearchOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const createRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!createOpen) return;
    const handler = (e: MouseEvent) => {
      if (createRef.current && !createRef.current.contains(e.target as Node)) setCreateOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [createOpen]);

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
      fetchMachineVaults();
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

  // Fetch auth status — which levels are configured, TOTP state, session TTLs
  useEffect(() => {
    if (!sessionToken) return;
    fetch("/api/auth/status", { headers: { Authorization: `Bearer ${sessionToken}` } })
      .then(r => r.json())
      .then(data => {
        if (data.configured) {
          const status: Record<number, boolean> = {};
          const ttls: Record<number, string> = {};
          const configured: Record<number, boolean> = { 0: false, 1: false, 2: false, 3: false };
          for (const [lvl, info] of Object.entries(data.configured as Record<string, any>)) {
            const l = parseInt(lvl);
            status[l] = info.totpEnabled;
            ttls[l] = info.sessionTtl || "24h";
            configured[l] = true;
          }
          setTotpStatus(status);
          setSessionTtls(prev => ({ ...prev, ...ttls }));
          setConfiguredLevels(configured);
        }
      })
      .catch(() => {});
  }, [sessionToken, showSettings]);

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

  const fetchMachineVaults = async () => {
    try {
      const res = await fetch("/api/machine/vaults", {
        headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
      });
      if (res.ok) setMachineVaults(await res.json());
    } catch (error) {
      console.error("Failed to fetch machine vaults", error);
    }
  };

  const fetchVaultSecrets = async (vaultId: string) => {
    try {
      const res = await fetch(`/api/machine/vaults/${vaultId}/secrets`, {
        headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
      });
      if (res.ok) setVaultSecrets(await res.json());
    } catch (error) {
      console.error("Failed to fetch vault secrets", error);
    }
  };

  const createMachineVault = async () => {
    if (!newVault.name) return;
    try {
      // 1. Generate ML-KEM-768 keypair first (fail early before creating vault)
      const kemPair = await generateKemKeyPair();

      // 2. Create the vault
      const res = await fetch("/api/machine/vaults", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}) },
        body: JSON.stringify({ name: newVault.name, description: newVault.description || null, ttl: parseInt(newVault.ttl) || 14400 }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(`Failed to create vault: ${err.error || res.statusText}`);
        return;
      }
      const vault = await res.json();

      // 3. Register public key with the vault
      const kemRes = await fetch(`/api/machine/vaults/${vault.id}/kem-key`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}) },
        body: JSON.stringify({ kem_public_key: kemPair.publicKey }),
      });
      if (!kemRes.ok) {
        alert("Vault created but KEM key registration failed. Check console.");
        console.error("KEM key registration failed:", await kemRes.text());
      }

      // 4. Show private key for download (one-time)
      setPendingPrivateKey({ vaultName: newVault.name, privateKey: kemPair.privateKey });
      setNewVault({ name: "", description: "", ttl: "14400" });
      setIsAddingVault(false);
      fetchMachineVaults();
    } catch (error) {
      console.error("Failed to create vault:", error);
      alert(`Vault creation error: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const deleteMachineVault = async (id: string) => {
    try {
      const res = await fetch(`/api/machine/vaults/${id}`, {
        method: "DELETE",
        headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
      });
      if (res.ok) {
        if (selectedVault?.id === id) { setSelectedVault(null); setVaultSecrets([]); }
        fetchMachineVaults();
      }
    } catch (error) {
      console.error("Failed to delete vault", error);
    }
  };

  const addMachineSecret = async () => {
    if (!selectedVault || !newMachineSecret.name || !newMachineSecret.value) return;
    try {
      let secretValue = newMachineSecret.value;

      if (newMachineSecret.classification === "blind") {
        // Blind: encrypt with ML-KEM in browser — server never sees plaintext
        const kemRes = await fetch(`/api/machine/vaults/${selectedVault.id}/kem-key`, {
          headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
        });
        if (!kemRes.ok) { alert("This vault has no ML-KEM public key registered. Re-create the vault to generate one."); return; }
        const { kem_public_key } = await kemRes.json();
        if (!kem_public_key) { alert("This vault has no ML-KEM public key registered. Re-create the vault to generate one."); return; }
        const encrypted = await hybridEncrypt(newMachineSecret.value, kem_public_key);
        secretValue = JSON.stringify(encrypted);
      }
      // Cached: send plaintext over TLS — server encrypts with AES-256-GCM and serves plaintext on lease

      const res = await fetch(`/api/machine/vaults/${selectedVault.id}/secrets`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}) },
        body: JSON.stringify({ name: newMachineSecret.name, encrypted_value: secretValue, classification: newMachineSecret.classification }),
      });
      if (res.ok) {
        setNewMachineSecret({ name: "", value: "", classification: "cached" });
        setIsAddingMachineSecret(false);
        fetchVaultSecrets(selectedVault.id);
      } else {
        const err = await res.json().catch(() => ({}));
        alert(err.error || "Failed to add secret");
      }
    } catch (error) {
      console.error("Failed to add secret", error);
      alert("Failed to add secret — check console for details");
    }
  };

  const savePrivateKeyToLvl2 = async () => {
    if (!pendingPrivateKey) return;
    if (authLevel > 2) {
      alert("Unlock Lvl 2 first — authenticate at Lvl 2 in the main vault, then come back to create the machine vault.");
      return;
    }
    const credential = sessionCredentials[2];
    if (!credential) {
      alert("Lvl 2 credential not in session. Re-authenticate at Lvl 2.");
      return;
    }
    try {
      let publicKeyB64: string | undefined;
      try {
        const kemRes = await fetch("/api/auth/kem-public-key/2", {
          headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
        });
        if (kemRes.ok) publicKeyB64 = (await kemRes.json()).publicKey;
      } catch { /* fall back to AES-only */ }

      const secretName = `${pendingPrivateKey.vaultName}-private-key`;
      const encryptedValue = await encryptForLevel(pendingPrivateKey.privateKey, 2, credential, publicKeyB64);

      const res = await fetch("/api/secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}) },
        body: JSON.stringify({
          id: crypto.randomUUID(),
          name: secretName,
          level: 2,
          secret_type: "custom",
          encrypted_value: encryptedValue,
          tags: ["kem-private-key", "vault-key"],
          expiry: null,
          url: null,
          username: null,
          folder: "Vault Keys",
        }),
      });
      if (res.ok) {
        alert(`Saved to Lvl 2 as "${secretName}" in folder "Vault Keys"`);
      } else {
        const err = await res.json().catch(() => ({}));
        alert(err.error || "Failed to save to Lvl 2");
      }
    } catch (error) {
      console.error("Failed to save private key to Lvl 2", error);
      alert("Failed to save — check console for details");
    }
  };

  const issueOfflineToken = async (vaultId: string) => {
    const machineId = prompt("Machine ID to issue offline token for:");
    if (!machineId?.trim()) return;
    const ttlHours = prompt("TTL in hours (default: 24):", "24");
    const ttlSeconds = Math.max(300, Math.min(604800, parseInt(ttlHours || "24", 10) * 3600));
    try {
      const res = await fetch(`/api/admin/machine/vaults/${vaultId}/offline-token`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}) },
        body: JSON.stringify({ machine_id: machineId.trim(), ttl_seconds: ttlSeconds }),
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`Failed: ${err.error}`);
        return;
      }
      const token = await res.json();
      // Download as JSON file
      const blob = new Blob([JSON.stringify(token, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `lvls-offline-token-${machineId.trim()}-${vaultId.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Failed to issue offline token", error);
      alert("Failed to issue offline token. Check console.");
    }
  };

  const deleteMachineSecret = async (secretId: string) => {
    if (!selectedVault) return;
    try {
      const res = await fetch(`/api/machine/vaults/${selectedVault.id}/secrets/${secretId}`, {
        method: "DELETE",
        headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {},
      });
      if (res.ok) fetchVaultSecrets(selectedVault.id);
    } catch (error) {
      console.error("Failed to delete secret", error);
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
      case 2: return { name: "Professional / Social", color: "text-indigo-300", bg: "bg-indigo-900/20", desc: "API keys, IAM roles, DAO voting, AV access" };
      case 1: return { name: "Personal / Infra", color: "text-amber-300", bg: "bg-amber-900/15", desc: "Financial APIs, HealthKit/BCI data, SSH, smart home admin" };
      case 0: return { name: "Critical / Private", color: "text-rose-300", bg: "bg-rose-900/15", desc: "Seed phrases, master identity hashes, break-glass keys" };
      default: return { name: "Unknown", color: "text-zinc-500", bg: "bg-zinc-800", desc: "" };
    }
  };

  // AuthModal is defined outside App (see below) to prevent re-animation on every keystroke

  // Loading splash
  if (isVaultSetup === null) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="w-1.5 h-1.5 rounded-full bg-violet-500 animate-pulse" />
      </div>
    );
  }

  // First-time onboarding
  if (isVaultSetup === false) {
    return (
      <Onboarding onComplete={(token) => {
        setSessionToken(token);
        setAuthLevel(3);
        setIsVaultSetup(true);
      }} />
    );
  }

  return (
    <div className="min-h-screen bg-black text-zinc-300 font-sans flex flex-col">
      <AnimatePresence>
        {showAuthModal && (
        <AuthModal
          authLevel={authLevel}
          targetLevel={pendingAuthLevel}
          totpStatus={totpStatus}
          configuredLevels={configuredLevels}
          authInput={authInput}
          setAuthInput={setAuthInput}
          totpInput={totpInput}
          setTotpInput={setTotpInput}
          authError={authError}
          setAuthError={setAuthError}
          authLoading={authLoading}
          handleAuth={handleAuth}
          onClose={() => { setShowAuthModal(false); setAuthInput(""); setAuthError(""); setTotpInput(""); }}
          onSetupAuth={() => { setShowAuthModal(false); setAuthInput(""); setAuthError(""); setTotpInput(""); setShowSettings(true); setSettingsTab("auth"); }}
        />
        )}
      </AnimatePresence>

      {/* Top ribbon — full width */}
      <header className="h-14 border-b border-zinc-800/50 relative flex items-center px-4 bg-black shrink-0 z-20">
        {/* Left: logo with spacing */}
        <button onClick={() => setSidebarOpen(o => !o)} className="shrink-0 flex items-center ml-12">
          <img src="/logo.png" alt="lvls" className="h-10 w-auto object-contain" />
        </button>
        <div className="flex-1" />
        {/* Right: search + settings + create */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1">
            <button onClick={() => setSearchOpen(o => !o)} className="p-1.5 text-zinc-400 hover:text-violet-300 hover:bg-violet-900/30 rounded-lg transition-colors">
              <Search className="w-4 h-4" />
            </button>
            <div className={`overflow-hidden transition-[width,opacity] duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] ${searchOpen ? "w-48 opacity-100" : "w-0 opacity-0"}`}>
              <input
                autoFocus={searchOpen}
                type="text"
                placeholder="Search…"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                onBlur={() => { if (!searchQuery) setSearchOpen(false); }}
                className="bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-1.5 text-sm text-zinc-300 placeholder:text-zinc-600 focus:outline-none focus:border-violet-700 w-48"
              />
            </div>
          </div>
          <button onClick={() => setShowSettings(true)} className="p-1.5 text-zinc-400 hover:text-violet-300 hover:bg-violet-900/30 rounded-lg transition-colors" title="Settings">
            <Settings className="w-4 h-4" />
          </button>
          <div className="relative" ref={createRef}>
            <button
              onClick={() => setCreateOpen(o => !o)}
              className="flex items-center gap-1.5 bg-violet-700 hover:bg-violet-600 active:bg-violet-800 text-white px-3 py-1.5 rounded-lg text-sm font-medium transition-colors select-none"
            >
              Create <Plus className="w-3.5 h-3.5" />
            </button>
            {createOpen && (
              <div className="absolute right-0 top-full mt-1.5 w-44 bg-zinc-900 border border-zinc-800 rounded-xl shadow-2xl z-50 overflow-hidden">
                <button
                  onClick={() => { setActiveTab("vault"); setIsAdding(true); setCreateOpen(false); }}
                  className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-zinc-300 hover:bg-violet-900/40 hover:text-violet-200 transition-colors"
                >
                  <Key className="w-3.5 h-3.5 text-violet-400" /> Secret
                </button>
                <div className="h-px bg-zinc-800 mx-3" />
                <button
                  onClick={() => { setActiveTab("machines"); fetchMachineVaults(); setTimeout(() => setIsAddingVault(true), 100); setCreateOpen(false); }}
                  className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-zinc-300 hover:bg-violet-900/40 hover:text-violet-200 transition-colors"
                >
                  <Hexagon className="w-3.5 h-3.5 text-violet-400" /> Vault
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Body: sidebar + main content */}
      <div className="flex flex-1 overflow-hidden">

      {/* Sidebar */}
      <div data-sidebar className={`${sidebarOpen ? "w-56" : "w-14"} shrink-0 bg-black flex flex-col z-10 transition-[width] duration-[350ms] ease-[cubic-bezier(0.16,1,0.3,1)]`}>
        <nav className="flex-1 px-2 py-4 space-y-1 overflow-hidden">
          <button
            onClick={() => setActiveTab("vault")}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150 ${activeTab === "vault" ? "bg-violet-900/40 text-violet-200 border border-violet-700/50" : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900/60"}`}
          >
            <Key className="w-4 h-4 shrink-0" />
            <span className={`whitespace-nowrap transition-[opacity,transform] duration-[250ms] ease-[cubic-bezier(0.16,1,0.3,1)] ${sidebarOpen ? "opacity-100 translate-x-0" : "opacity-0 -translate-x-2 pointer-events-none"}`}>Secrets</span>
          </button>
          <button
            onClick={() => { setActiveTab("machines"); fetchMachineVaults(); }}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150 ${activeTab === "machines" ? "bg-violet-900/40 text-violet-200 border border-violet-700/50" : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900/60"}`}
          >
            <Hexagon className="w-4 h-4 shrink-0" />
            <span className={`whitespace-nowrap transition-[opacity,transform] duration-[250ms] ease-[cubic-bezier(0.16,1,0.3,1)] ${sidebarOpen ? "opacity-100 translate-x-0" : "opacity-0 -translate-x-2 pointer-events-none"}`}>Machine Vaults</span>
          </button>
          <button
            onClick={() => setActiveTab("logs")}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150 ${activeTab === "logs" ? "bg-violet-900/40 text-violet-200 border border-violet-700/50" : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900/60"}`}
          >
            <Activity className="w-4 h-4 shrink-0" />
            <span className={`whitespace-nowrap transition-[opacity,transform] duration-[250ms] ease-[cubic-bezier(0.16,1,0.3,1)] ${sidebarOpen ? "opacity-100 translate-x-0" : "opacity-0 -translate-x-2 pointer-events-none"}`}>Session Logs</span>
          </button>
        </nav>

        <div className="px-3 py-3 border-t border-zinc-800 flex flex-col gap-2">

          <div className="flex items-center justify-between">
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
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <main className="flex-1 overflow-y-auto p-6 w-full">
          {activeTab === "vault" && (
            <motion.div
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.25, ease: "easeOut" }}
              className="w-full space-y-6"
            >
              {isAdding && (
                <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-6 mb-6 shadow-xl">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-white font-medium">Add New Secret</h3>
                    <button onClick={() => setIsAdding(false)} className="p-1.5 text-zinc-500 hover:text-white hover:bg-zinc-800 rounded-lg transition-all"><X className="w-4 h-4" /></button>
                  </div>
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
                <table className="w-full text-left text-base">
                  <thead className="bg-black/60 text-zinc-400 text-xs uppercase tracking-widest border-b border-zinc-900">
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
                                  className="text-zinc-500 hover:text-indigo-300 opacity-0 group-hover:opacity-100 transition-all p-1"
                                  title="Edit Secret"
                                >
                                  <Pencil className="w-4 h-4" />
                                </button>
                                <button
                                  onClick={() => handleDeleteSecret(secret.id)}
                                  className="text-zinc-500 hover:text-rose-300 opacity-0 group-hover:opacity-100 transition-all p-1"
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
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.25, ease: "easeOut" }}
              className="w-full space-y-6"
            >
              <div className="bg-zinc-950/50 border border-zinc-900 rounded-xl overflow-hidden shadow-2xl">
                <table className="w-full text-left text-base">
                  <thead className="bg-black/60 text-zinc-400 text-xs uppercase tracking-widest border-b border-zinc-900">
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

          {activeTab === "machines" && (
            <motion.div
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.25, ease: "easeOut" }}
              className="w-full space-y-6"
            >
              {/* Private Key Download Modal */}
              {pendingPrivateKey && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50">
                  <div className="bg-zinc-950 border border-zinc-800 rounded-2xl p-8 max-w-lg w-full mx-4 shadow-2xl">
                    <div className="flex items-center gap-3 mb-4">
                      <div className="p-2 bg-amber-500/10 rounded-lg">
                        <AlertTriangle className="w-5 h-5 text-amber-500" />
                      </div>
                      <h3 className="text-lg font-semibold text-white">Save Private Key</h3>
                    </div>
                    <p className="text-sm text-zinc-400 mb-2">
                      Vault <span className="text-white font-medium">{pendingPrivateKey.vaultName}</span> created with ML-KEM-768 encryption.
                    </p>
                    <p className="text-sm text-amber-400 mb-4">
                      This private key is shown once. Download it now. The service that reads from this vault needs this key to decrypt secrets.
                    </p>
                    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-3 mb-6 max-h-24 overflow-y-auto">
                      <code className="text-xs text-zinc-500 break-all font-mono">{pendingPrivateKey.privateKey.slice(0, 80)}...</code>
                    </div>
                    <div className="flex flex-col gap-3">
                      <button
                        onClick={savePrivateKeyToLvl2}
                        className="w-full bg-emerald-700 hover:bg-emerald-600 text-white px-4 py-2.5 rounded-lg text-sm font-medium transition-all flex items-center justify-center gap-2"
                      >
                        <Shield className="w-4 h-4" /> Save to Lvl 2 — Professional
                      </button>
                      <div className="flex gap-3">
                        <button
                          onClick={() => {
                            const blob = new Blob([pendingPrivateKey.privateKey], { type: "text/plain" });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement("a");
                            a.href = url;
                            a.download = `${pendingPrivateKey.vaultName}.kem.key`;
                            a.click();
                            URL.revokeObjectURL(url);
                          }}
                          className="flex-1 bg-violet-600 hover:bg-violet-500 text-white px-4 py-2.5 rounded-lg text-sm font-medium transition-all flex items-center justify-center gap-2"
                        >
                          <Key className="w-4 h-4" /> Download Key
                        </button>
                        <button
                          onClick={() => { copyToClipboard(pendingPrivateKey.privateKey); }}
                          className="px-4 py-2.5 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 rounded-lg text-sm font-medium transition-all flex items-center gap-2 border border-zinc-800"
                        >
                          <Copy className="w-4 h-4" /> Copy
                        </button>
                        <button
                          onClick={() => setPendingPrivateKey(null)}
                          className="px-4 py-2.5 text-zinc-500 hover:text-zinc-300 rounded-lg text-sm transition-all"
                        >
                          Done
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {!selectedVault ? (
                <>

                  {isAddingVault && (
                    <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-6 shadow-xl">
                      <div className="flex items-center justify-between mb-4">
                        <span className="text-white font-medium text-sm">New Vault</span>
                        <button onClick={() => { setIsAddingVault(false); setNewVault({ name: "", description: "", ttl: "14400" }); }} className="p-1.5 text-zinc-500 hover:text-white hover:bg-zinc-800 rounded-lg transition-all"><X className="w-4 h-4" /></button>
                      </div>
                      <div className="space-y-4">
                        <div>
                          <label className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Name</label>
                          <input
                            type="text"
                            placeholder="e.g. database, api-gateway, proxy"
                            value={newVault.name}
                            onChange={e => setNewVault(prev => ({ ...prev, name: e.target.value.replace(/[^a-zA-Z0-9_-]/g, '') }))}
                            className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-700 mt-1"
                          />
                        </div>
                        <div>
                          <label className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Description</label>
                          <input
                            type="text"
                            placeholder="What service uses this vault?"
                            value={newVault.description}
                            onChange={e => setNewVault(prev => ({ ...prev, description: e.target.value }))}
                            className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-700 mt-1"
                          />
                        </div>
                        <div>
                          <label className="text-xs text-zinc-500 uppercase tracking-wider font-medium">TTL (seconds)</label>
                          <input
                            type="number"
                            value={newVault.ttl}
                            onChange={e => setNewVault(prev => ({ ...prev, ttl: e.target.value }))}
                            className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-zinc-700 mt-1"
                          />
                          <p className="text-xs text-zinc-600 mt-1">{Math.floor(parseInt(newVault.ttl || "0") / 3600)}h {Math.floor((parseInt(newVault.ttl || "0") % 3600) / 60)}m</p>
                        </div>
                        <div className="flex gap-3 pt-2">
                          <button onClick={createMachineVault} className="bg-violet-600 hover:bg-violet-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-all">Create</button>
                          <button onClick={() => { setIsAddingVault(false); setNewVault({ name: "", description: "", ttl: "14400" }); }} className="text-zinc-500 hover:text-zinc-300 px-4 py-2 rounded-lg text-sm transition-all">Cancel</button>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="bg-zinc-950/50 border border-zinc-900 rounded-xl overflow-hidden shadow-2xl">
                    <table className="w-full text-left text-base">
                      <thead className="bg-black/60 text-zinc-400 text-xs uppercase tracking-widest border-b border-zinc-900">
                        <tr>
                          <th className="px-6 py-4 font-medium">Vault</th>
                          <th className="px-6 py-4 font-medium">TTL</th>
                          <th className="px-6 py-4 font-medium">TOTP</th>
                          <th className="px-6 py-4 font-medium">KEM</th>
                          <th className="px-6 py-4 font-medium">Created</th>
                          <th className="px-6 py-4 font-medium"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {machineVaults.map(vault => (
                          <tr
                            key={vault.id}
                            onClick={() => { setSelectedVault(vault); fetchVaultSecrets(vault.id); }}
                            className="hover:bg-zinc-900/40 transition-all duration-100 cursor-pointer border-b border-zinc-900/50"
                          >
                            <td className="px-6 py-4">
                              <div className="text-zinc-200 font-medium">{vault.name}</div>
                              {vault.description && <div className="text-xs text-zinc-600 mt-0.5">{vault.description}</div>}
                            </td>
                            <td className="px-6 py-4 text-zinc-400 font-mono text-xs">{Math.floor(vault.ttl / 3600)}h {Math.floor((vault.ttl % 3600) / 60)}m</td>
                            <td className="px-6 py-4">
                              <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${vault.totp_enabled ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-zinc-800 text-zinc-500 border border-zinc-700"}`}>
                                {vault.totp_enabled ? "Active" : "Off"}
                              </span>
                            </td>
                            <td className="px-6 py-4">
                              <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${vault.has_kem_key ? "bg-violet-500/10 text-violet-400 border border-violet-500/20" : "bg-zinc-800 text-zinc-500 border border-zinc-700"}`}>
                                {vault.has_kem_key ? "Set" : "None"}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-zinc-500 text-xs">{new Date(vault.created_at).toLocaleDateString()}</td>
                            <td className="px-6 py-4">
                              <button
                                onClick={(e) => { e.stopPropagation(); deleteMachineVault(vault.id); }}
                                className="p-1.5 text-zinc-600 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-all"
                                title="Delete vault"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </td>
                          </tr>
                        ))}
                        {machineVaults.length === 0 && !isAddingVault && (
                          <tr>
                            <td colSpan={6} className="px-6 py-16 text-center text-zinc-500">
                              <div className="flex flex-col items-center justify-center gap-3">
                                <Hexagon className="w-8 h-8 text-zinc-700" />
                                <p>No machine vaults. Create one to give a service programmatic secret access.</p>
                              </div>
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </>
              ) : (
                <>
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => { setSelectedVault(null); setVaultSecrets([]); setIsAddingMachineSecret(false); }}
                      className="p-2 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-900 rounded-lg transition-all"
                    >
                      <X className="w-4 h-4" />
                    </button>
                    <div>
                      <h2 className="text-lg font-semibold text-white">{selectedVault.name}</h2>
                      {selectedVault.description && <p className="text-xs text-zinc-500">{selectedVault.description}</p>}
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4">
                      <p className="text-xs text-zinc-600 uppercase tracking-widest font-medium">TTL</p>
                      <p className="text-zinc-200 font-mono text-sm mt-1">{Math.floor(selectedVault.ttl / 3600)}h {Math.floor((selectedVault.ttl % 3600) / 60)}m</p>
                    </div>
                    <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4">
                      <p className="text-xs text-zinc-600 uppercase tracking-widest font-medium">TOTP</p>
                      <p className={`text-sm font-medium mt-1 ${selectedVault.totp_enabled ? "text-emerald-400" : "text-zinc-500"}`}>
                        {selectedVault.totp_enabled ? "Active" : "Not configured"}
                      </p>
                    </div>
                    <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-4">
                      <p className="text-xs text-zinc-600 uppercase tracking-widest font-medium">KEM Key</p>
                      <p className={`text-sm font-medium mt-1 ${selectedVault.has_kem_key ? "text-violet-400" : "text-zinc-500"}`}>
                        {selectedVault.has_kem_key ? "Registered" : "Not set"}
                      </p>
                    </div>
                  </div>

                  <div className="flex justify-between items-center">
                    <h3 className="text-sm font-medium text-zinc-400">Secrets</h3>
                    <div className="flex gap-2">
                      <button
                        onClick={() => issueOfflineToken(selectedVault.id)}
                        className="bg-zinc-800 hover:bg-zinc-700 text-zinc-300 px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5"
                        title="Issue an offline token for a machine — encrypts vault secrets with the machine's ML-KEM public key"
                      >
                        Offline Token
                      </button>
                      <button
                        onClick={() => setIsAddingMachineSecret(true)}
                        className="bg-violet-600 hover:bg-violet-500 text-white px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5"
                      >
                        <Plus className="w-3.5 h-3.5" /> Add Secret
                      </button>
                    </div>
                  </div>

                  {isAddingMachineSecret && (
                    <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-5 shadow-xl">
                      <div className="flex items-center justify-between mb-3">
                        <span className="text-white font-medium text-sm">Add Secret</span>
                        <button onClick={() => { setIsAddingMachineSecret(false); setNewMachineSecret({ name: "", value: "", classification: "cached" }); }} className="p-1.5 text-zinc-500 hover:text-white hover:bg-zinc-800 rounded-lg transition-all"><X className="w-4 h-4" /></button>
                      </div>
                      <div className="space-y-3">
                        <div>
                          <label className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Key</label>
                          <input
                            type="text"
                            placeholder="e.g. DATABASE_URL, API_KEY"
                            value={newMachineSecret.name}
                            onChange={e => setNewMachineSecret(prev => ({ ...prev, name: e.target.value }))}
                            className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-700 mt-1"
                          />
                        </div>
                        <div>
                          <label className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Value</label>
                          <input
                            type="password"
                            placeholder="Secret value"
                            value={newMachineSecret.value}
                            onChange={e => setNewMachineSecret(prev => ({ ...prev, value: e.target.value }))}
                            className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-700 mt-1 font-mono"
                          />
                        </div>
                        <div>
                          <label className="text-xs text-zinc-500 uppercase tracking-wider font-medium">Classification</label>
                          <div className="flex gap-2 mt-1">
                            <button
                              onClick={() => setNewMachineSecret(prev => ({ ...prev, classification: "cached" }))}
                              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all border ${newMachineSecret.classification === "cached" ? "bg-emerald-950 border-emerald-700 text-emerald-300" : "bg-zinc-900 border-zinc-800 text-zinc-500 hover:text-zinc-300"}`}
                            >
                              Cached — AES, may cache locally
                            </button>
                            <button
                              onClick={() => setNewMachineSecret(prev => ({ ...prev, classification: "blind" }))}
                              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all border ${newMachineSecret.classification === "blind" ? "bg-rose-950 border-rose-700 text-rose-300" : "bg-zinc-900 border-zinc-800 text-zinc-500 hover:text-zinc-300"}`}
                            >
                              Blind — ML-KEM only, never cached
                            </button>
                          </div>
                        </div>
                        <div className="flex gap-3 pt-1">
                          <button onClick={addMachineSecret} className="bg-violet-600 hover:bg-violet-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-all">Add</button>
                          <button onClick={() => { setIsAddingMachineSecret(false); setNewMachineSecret({ name: "", value: "", classification: "cached" }); }} className="text-zinc-500 hover:text-zinc-300 px-4 py-2 rounded-lg text-sm transition-all">Cancel</button>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="bg-zinc-950/50 border border-zinc-900 rounded-xl overflow-hidden shadow-2xl">
                    <table className="w-full text-left text-base">
                      <thead className="bg-black/60 text-zinc-400 text-xs uppercase tracking-widest border-b border-zinc-900">
                        <tr>
                          <th className="px-6 py-4 font-medium">Key</th>
                          <th className="px-6 py-4 font-medium">Class</th>
                          <th className="px-6 py-4 font-medium">Added</th>
                          <th className="px-6 py-4 font-medium"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {vaultSecrets.map(secret => (
                          <tr key={secret.id} className="hover:bg-zinc-900/40 transition-all duration-100 border-b border-zinc-900/50">
                            <td className="px-6 py-4 text-zinc-200 font-mono text-xs">{secret.name}</td>
                            <td className="px-6 py-4">
                              <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${secret.classification === "blind" ? "bg-rose-950 text-rose-400 border border-rose-800" : "bg-emerald-950 text-emerald-400 border border-emerald-900"}`}>
                                {secret.classification === "blind" ? "blind" : "cached"}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-zinc-500 text-xs">{new Date(secret.created_at).toLocaleDateString()}</td>
                            <td className="px-6 py-4">
                              <button
                                onClick={() => deleteMachineSecret(secret.id)}
                                className="p-1.5 text-zinc-600 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-all"
                                title="Delete secret"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </td>
                          </tr>
                        ))}
                        {vaultSecrets.length === 0 && !isAddingMachineSecret && (
                          <tr>
                            <td colSpan={3} className="px-6 py-12 text-center text-zinc-500">
                              <div className="flex flex-col items-center justify-center gap-3">
                                <Key className="w-6 h-6 text-zinc-700" />
                                <p>No secrets in this vault yet.</p>
                              </div>
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </motion.div>
          )}

          {activeTab === "docs" && (
            <motion.div
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.25, ease: "easeOut" }}
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
      </div> {/* end body wrapper */}

      {/* Settings Modal */}
      <AnimatePresence>
        {showSettings && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowSettings(false)}
              className="fixed inset-0 bg-black/70 backdrop-blur-md z-40"
            />
            {/* Centered modal */}
            <div className="fixed inset-0 flex items-center justify-center z-50 p-6 pointer-events-none">
            <motion.div
              initial={{ opacity: 0, scale: 0.97, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.97, y: 10 }}
              transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
              className="bg-zinc-950 border border-zinc-800/70 rounded-2xl w-full max-w-2xl max-h-[88vh] flex flex-col shadow-2xl pointer-events-auto"
            >
              {/* Header */}
              <div className="flex items-center justify-between px-7 py-5 border-b border-zinc-800/60 shrink-0">
                <div>
                  <h2 className="text-lg font-bold text-white tracking-tight">Settings</h2>
                  <p className="text-zinc-500 text-xs mt-0.5">Vault security &amp; authentication</p>
                </div>
                <button
                  onClick={() => setShowSettings(false)}
                  className="p-1.5 rounded-lg text-zinc-500 hover:text-white hover:bg-zinc-800 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Tabs */}
              <div className="flex gap-1 px-7 pt-3 border-b border-zinc-800/60 shrink-0">
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
                    {t === "auth" ? "Security" : "About"}
                  </button>
                ))}
              </div>

              {/* Content */}
              <div className="flex-1 overflow-y-auto px-7 py-5 space-y-7">

                {settingsTab === "auth" && (
                  <>
                    {/* Section: Credentials */}
                    <section>
                      <h3 className="text-sm font-semibold text-zinc-200 mb-1">Credentials</h3>
                      <p className="text-xs text-zinc-500 mb-4">
                        Each level has its own credential. lvl3 uses a numeric PIN. lvl0–2 use a passphrase (letters + numbers, min 6 characters).
                      </p>
                      <CredentialSetup
                        authLevel={authLevel}
                        sessionToken={sessionToken}
                        configuredLevels={configuredLevels}
                        onCredentialSaved={(level) => setConfiguredLevels(prev => ({ ...prev, [level]: true }))}
                      />
                    </section>

                    {/* Section: Session Duration */}
                    <section className="pt-6 border-t border-zinc-800/60">
                      <h3 className="text-sm font-semibold text-zinc-200 mb-1">Session Duration</h3>
                      <p className="text-xs text-zinc-500 mb-4">How long you stay authenticated after unlocking a level. Higher levels expire sooner by default.</p>
                      <div className="space-y-2">
                        {[
                          { level: 3, label: "Level 3", sublabel: "Everyday access", options: ["1h", "8h", "24h", "Never"] },
                          { level: 2, label: "Level 2", sublabel: "Professional", options: ["30m", "1h", "4h", "8h"] },
                          { level: 1, label: "Level 1", sublabel: "Personal", options: ["15m", "30m", "1h", "2h"] },
                          { level: 0, label: "Level 0", sublabel: "Critical — never cached", options: ["Never cached"] },
                        ].filter(({ level }) => authLevel <= level).map(({ level, label, sublabel, options }) => (
                          <div key={level} className="flex items-center justify-between bg-zinc-900/50 border border-zinc-800/80 px-4 py-3.5 rounded-xl">
                            <div>
                              <p className="text-sm font-medium text-zinc-200">{label}</p>
                              <p className="text-xs text-zinc-500 mt-0.5">{sublabel}</p>
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

                    {/* Section: Two-Factor Authentication */}
                    <section className="pt-6 border-t border-zinc-800/60">
                      <h3 className="text-sm font-semibold text-zinc-200 mb-1">Two-Factor Authentication</h3>
                      <p className="text-xs text-zinc-500 mb-4">Require a one-time code at unlock. Works with any TOTP app — Google Authenticator, Authy, 1Password, etc.</p>
                      <div className="space-y-2">
                        {[
                          { level: 3, label: "Level 3", color: "text-zinc-300" },
                          { level: 2, label: "Level 2", color: "text-indigo-300" },
                          { level: 1, label: "Level 1", color: "text-amber-300" },
                          { level: 0, label: "Level 0", color: "text-rose-300" },
                        ].filter(({ level }) => authLevel <= level).map(({ level, label, color }) => (
                          <div key={level} className="bg-zinc-900/50 border border-zinc-800/80 px-4 py-3.5 rounded-xl">
                            <div className="flex items-center justify-between">
                              <div>
                                <p className={`text-sm font-medium ${color}`}>{label}</p>
                                <p className="text-xs text-zinc-500 mt-0.5">
                                  {totpStatus[level] ? "Active — required at every unlock" : "Not enabled"}
                                </p>
                              </div>
                              <div className="flex gap-2">
                                {totpStatus[level] ? (
                                  <button
                                    onClick={() => handleTotpDisable(level)}
                                    disabled={authLevel > level}
                                    className="text-xs text-rose-300 hover:text-rose-200 border border-rose-900/40 hover:border-rose-700/60 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                                  >
                                    Disable
                                  </button>
                                ) : (
                                  <button
                                    onClick={() => handleTotpSetup(level)}
                                    disabled={authLevel > level}
                                    className="text-xs text-violet-400 hover:text-violet-300 border border-violet-800 hover:border-violet-600 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                                  >
                                    Enable
                                  </button>
                                )}
                              </div>
                            </div>

                            {/* TOTP Setup Panel */}
                            {totpSetup?.level === level && (
                              <div className="mt-4 pt-4 border-t border-zinc-800 space-y-4">
                                <p className="text-xs text-zinc-400">
                                  Add the key below to your authenticator app, then enter the 6-digit code it generates to confirm.
                                </p>
                                <div className="bg-zinc-950 rounded-lg p-3 space-y-2">
                                  <p className="text-xs text-zinc-500 font-medium">Setup Key</p>
                                  <div className="flex items-center gap-2">
                                    <code className="text-violet-400 font-mono text-sm break-all flex-1">{totpSetup.secret}</code>
                                    <button
                                      onClick={() => copyToClipboard(totpSetup.secret)}
                                      className="text-zinc-500 hover:text-white transition-colors shrink-0"
                                      title="Copy key"
                                    >
                                      <Copy className="w-4 h-4" />
                                    </button>
                                  </div>
                                  <a href={totpSetup.uri} className="text-xs text-violet-400 hover:text-violet-300 hover:underline block pt-1">
                                    Open in authenticator app
                                  </a>
                                </div>
                                <div className="flex gap-2">
                                  <input
                                    type="text"
                                    inputMode="numeric"
                                    maxLength={6}
                                    value={totpConfirmCode}
                                    onChange={e => { setTotpConfirmCode(e.target.value); setTotpConfirmError(""); }}
                                    placeholder="000 000"
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
                                  <p className="text-rose-300 text-xs">{totpConfirmError}</p>
                                )}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </section>

                    {/* Section: Privacy */}
                    <section className="pt-6 border-t border-zinc-800/60">
                      <h3 className="text-sm font-semibold text-zinc-200 mb-1">Privacy</h3>
                      <p className="text-xs text-zinc-500 mb-4">Controls how the vault handles sensitive data in memory and the clipboard.</p>
                      <div className="space-y-2">
                        {[
                          { id: "mem-lock", label: "Memory protection", desc: "Keep decrypted keys in locked memory — never swapped to disk", default: true },
                          { id: "zero-on-lock", label: "Wipe on lock", desc: "Securely clear session keys from memory when the vault locks", default: true },
                          { id: "clipboard-clear", label: "Clear clipboard automatically", desc: "Wipe the clipboard 30 seconds after copying a secret", default: true },
                          { id: "audit-reveal", label: "Log when secrets are revealed", desc: "Record in the session log each time a secret value is shown", default: false },
                        ].map(({ id, label, desc, default: def }) => (
                          <label key={id} className="flex items-center justify-between bg-zinc-900/50 border border-zinc-800/80 px-4 py-3.5 rounded-xl cursor-pointer">
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

                    {/* Section: Backup & Restore */}
                    <section className="pt-6 border-t border-zinc-800/60">
                      <h3 className="text-sm font-semibold text-zinc-200 mb-1">Backup &amp; Restore</h3>
                      <p className="text-xs text-zinc-500 mb-4">Encrypted export of all vault data. Requires lvl0. The backup passphrase is independent of your vault credentials.</p>
                      <BackupRestore authLevel={authLevel} sessionToken={sessionToken} />
                    </section>

                    {/* Section: Danger Zone */}
                    <section className="pt-6 border-t border-zinc-800/60">
                      <h3 className="text-sm font-semibold text-rose-300 mb-1">Danger Zone</h3>
                      <p className="text-xs text-zinc-500 mb-4">Irreversible actions. This cannot be undone.</p>
                      <NukeVault />
                    </section>
                  </>
                )}

                {settingsTab === "docs" && (
                  <>
                    <section>
                      <h3 className="text-sm font-semibold text-zinc-200 mb-1">About lvls</h3>
                      <p className="text-xs text-zinc-500 mb-4">Self-hosted key vault with four security clearance levels. Secrets are encrypted client-side before leaving your browser.</p>
                      <div className="space-y-2">
                        {[
                          { label: "Encryption", value: "ML-KEM-768 (post-quantum) + AES-256-GCM" },
                          { label: "Password hashing", value: "Argon2id — memory-hard, brute-force resistant" },
                          { label: "Sessions", value: "JWT — HMAC-signed, per-level TTL, revocable" },
                          { label: "Transport", value: "HTTPS — TLS with HSTS enforced" },
                          { label: "2FA", value: "TOTP (RFC 6238) — replay attack protected" },
                          { label: "Rate limiting", value: "Per-IP, DB-persisted, survives restarts" },
                        ].map(({ label, value }) => (
                          <div key={label} className="flex items-start gap-4 bg-zinc-900/50 border border-zinc-800/80 px-4 py-3 rounded-xl">
                            <p className="text-xs font-medium text-zinc-400 w-36 shrink-0 pt-0.5">{label}</p>
                            <p className="text-xs text-zinc-300">{value}</p>
                          </div>
                        ))}
                      </div>
                    </section>
                  </>
                )}

              </div>
            </motion.div>
            </div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
