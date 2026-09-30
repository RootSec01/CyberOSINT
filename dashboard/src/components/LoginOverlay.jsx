import { useState } from "react";
import { useAuth } from "../lib/AuthContext.jsx";

function LoginOverlay() {
  const { signIn } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await signIn(username.trim(), password);
    } catch {
      setError("Invalid username or password.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-900/95 backdrop-blur-sm">
      <form
        onSubmit={onSubmit}
        className="w-[360px] rounded-2xl border border-edge bg-ink-800 p-7 shadow-2xl"
      >
        <div className="flex items-center gap-2.5 mb-6">
          <div className="h-9 w-9 rounded-lg bg-signal/10 border border-signal/30 flex items-center justify-center">
            <span className="text-signal text-sm">◆</span>
          </div>
          <div>
            <div className="font-display font-600 text-[15px] leading-none text-mist-100">
              CyberOSINT
            </div>
            <div className="text-[10px] uppercase tracking-[0.18em] text-mist-300 mt-1">
              Sign in to continue
            </div>
          </div>
        </div>

        <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">
          Username
        </label>
        <input
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoFocus
          autoComplete="username"
          className="w-full mb-4 rounded-lg border border-edge bg-ink-900 px-3 py-2 text-[13px] text-mist-100 outline-none focus:border-signal/50"
        />

        <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">
          Password
        </label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
          className="w-full mb-5 rounded-lg border border-edge bg-ink-900 px-3 py-2 text-[13px] text-mist-100 outline-none focus:border-signal/50"
        />

        {error && (
          <div className="mb-4 rounded-lg border border-alert-crit/40 bg-alert-crit/10 px-3 py-2 text-[12px] text-alert-crit">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={busy || !username || !password}
          className="w-full rounded-lg bg-signal/90 hover:bg-signal px-3 py-2.5 text-[13px] font-600 text-ink-900 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}

export default LoginOverlay;
