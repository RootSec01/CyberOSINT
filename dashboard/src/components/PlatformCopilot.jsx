import { useCallback, useEffect, useRef, useState } from "react";
import { askPlatformCopilot } from "../lib/api.js";

// Privacy-mode badge (mirrors the per-asset Copilot panel).
const COPILOT_MODE = {
  offline: { icon: "🔒", label: "Offline" },
  redacted: { icon: "🛡", label: "Redacted" },
  local: { icon: "🏠", label: "Local AI" },
};

function SparkIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3v3m0 12v3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1M3 12h3m12 0h3M5.6 18.4l2.1-2.1m8.6-8.6 2.1-2.1" />
    </svg>
  );
}

// A single portfolio-wide answer turn.
function Turn({ role, text }) {
  const mine = role === "user";
  return (
    <div className={`flex ${mine ? "justify-end" : "justify-start"}`}>
      <div className={`max-w-[85%] text-[12.5px] leading-relaxed rounded-lg px-3 py-2 whitespace-pre-wrap ${
        mine ? "bg-signal/15 border border-signal/30 text-mist-100"
             : "bg-ink-900/60 border border-edge text-mist-100"
      }`}>
        {text}
      </div>
    </div>
  );
}

function PlatformCopilot() {
  const [open, setOpen] = useState(false);
  const [turns, setTurns] = useState([]);          // {role, text}
  const [suggestions, setSuggestions] = useState([]);
  const [mode, setMode] = useState(null);
  const [fallback, setFallback] = useState(false);
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState("");
  const [loadedOnce, setLoadedOnce] = useState(false);
  const scrollRef = useRef(null);

  const ask = useCallback((question) => {
    setBusy(true);
    if (question) setTurns((t) => [...t, { role: "user", text: question }]);
    askPlatformCopilot(question)
      .then((r) => {
        setTurns((t) => [...t, { role: "ai", text: r.answer || "(no answer)" }]);
        setSuggestions(Array.isArray(r.suggestions) ? r.suggestions : []);
        setMode(r.mode || null);
        setFallback(Boolean(r.fallback));
      })
      .catch((e) =>
        setTurns((t) => [...t, { role: "ai", text: "Copilot unavailable: " + (e.message || "error") }]))
      .finally(() => setBusy(false));
  }, []);

  // First open triggers the portfolio briefing once.
  useEffect(() => {
    if (open && !loadedOnce) {
      setLoadedOnce(true);
      ask("");
    }
  }, [open, loadedOnce, ask]);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [turns, busy]);

  function submit(e) {
    e.preventDefault();
    const question = q.trim();
    if (!question || busy) return;
    setQ("");
    ask(question);
  }

  const meta = COPILOT_MODE[mode] || null;

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        title="Platform Copilot"
        className="flex items-center gap-1.5 h-[28px] px-2.5 rounded-md border border-signal/40 text-signal hover:bg-signal/10 transition-colors"
      >
        <SparkIcon />
        <span className="text-[11px] font-600">Copilot</span>
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-40 bg-black/40" onClick={() => setOpen(false)} />
          <aside className="fixed top-0 right-0 z-50 h-full w-full sm:w-[420px] bg-ink-800 border-l border-edge shadow-2xl flex flex-col">
            <div className="flex items-center justify-between px-4 py-3 border-b border-edge">
              <div className="flex items-center gap-2">
                <span className="text-signal"><SparkIcon /></span>
                <span className="text-[13px] font-600 text-mist-100">Platform Copilot</span>
                {meta && (
                  <span className="text-[10px] px-2 py-0.5 rounded-md border border-edge text-mist-300">
                    {meta.icon} {meta.label}{fallback ? " · local briefing" : ""}
                  </span>
                )}
              </div>
              <button onClick={() => setOpen(false)}
                className="text-mist-300 hover:text-mist-100 text-[18px] leading-none px-1">×</button>
            </div>

            <p className="px-4 pt-3 text-[11px] text-mist-300">
              Grounded across all your assets, open alerts and recent changes — never invents findings.
            </p>

            <div ref={scrollRef} className="flex-1 overflow-auto px-4 py-3 space-y-2.5">
              {turns.map((t, i) => <Turn key={i} role={t.role} text={t.text} />)}
              {busy && (
                <div className="text-[12px] text-mist-300">Analysing your portfolio…</div>
              )}
            </div>

            {suggestions.length > 0 && (
              <div className="flex flex-wrap gap-1.5 px-4 pb-2">
                {suggestions.map((sug, i) => (
                  <button key={i} onClick={() => ask(sug)} disabled={busy}
                    className="text-[11px] px-2.5 py-1 rounded-full border border-edge text-mist-200 hover:text-mist-100 hover:bg-ink-700/50 transition-colors disabled:opacity-50">
                    {sug}
                  </button>
                ))}
              </div>
            )}

            <form onSubmit={submit} className="flex gap-2 px-4 py-3 border-t border-edge">
              <input value={q} onChange={(e) => setQ(e.target.value)}
                placeholder="Ask across your whole portfolio…"
                className="flex-1 text-[12px] px-3 py-2 rounded-lg bg-ink-900/70 border border-edge text-mist-100 placeholder:text-mist-300/60 focus:border-signal/50 outline-none" />
              <button type="submit" disabled={busy || !q.trim()}
                className="text-[12px] px-3 py-2 rounded-lg border border-signal/40 text-signal hover:bg-signal/10 transition-colors disabled:opacity-50">
                {busy ? "…" : "Ask"}
              </button>
            </form>
          </aside>
        </>
      )}
    </>
  );
}

export default PlatformCopilot;
