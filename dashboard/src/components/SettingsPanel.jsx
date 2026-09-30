import { useEffect, useState } from "react";
import { getSettings, updateSettings } from "../lib/api.js";

const MODES = [
  { id: "offline", icon: "🔒", title: "Private / Offline",
    desc: "Everything runs locally. No data ever leaves the platform.",
    boundary: "Nothing leaves your platform.",
    accent: "border-signal/60 bg-signal/10 text-signal" },
  { id: "redacted", icon: "🛡", title: "AI Assisted (Redacted)",
    desc: "Findings are sent after stripping IPs, hosts, emails, keys & tokens.",
    boundary: "Only redacted findings leave your platform.",
    accent: "border-alert-med/60 bg-alert-med/10 text-alert-med" },
  { id: "local", icon: "🏠", title: "Enterprise Local AI",
    desc: "Sent to an LLM inside your own network (Ollama / vLLM).",
    boundary: "Data stays within your network.",
    accent: "border-alert-low/60 bg-alert-low/10 text-alert-low" },
];

const PROVIDERS = [
  { id: "openai", label: "OpenAI" },
  { id: "anthropic", label: "Anthropic" },
  { id: "custom", label: "Custom" },
];

function SettingsPanel({ open, onClose }) {
  const [s, setS] = useState(null);
  const [saved, setSaved] = useState(false);
  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");

  useEffect(() => {
    if (!open) return;
    getSettings()
      .then((r) => {
        setS(r);
        setBaseUrl(r?.ai_base_url || "");
        setModel(r?.ai_model || "");
      })
      .catch(() => {});
  }, [open]);

  async function patch(fields) {
    try {
      const r = await updateSettings(fields);
      if (r && !r.detail) {
        setS(r);
        setSaved(true);
        setTimeout(() => setSaved(false), 1400);
      }
    } catch { /* ignore */ }
  }

  if (!open) return null;
  const mode = s?.ai_mode || "offline";
  const provider = s?.ai_provider || "openai";
  const keys = s?.keys_present || {};
  const active = MODES.find((m) => m.id === mode) || MODES[0];
  const showProvider = mode === "redacted";
  const showEndpoint = mode === "local" || (mode === "redacted" && provider === "custom");
  const keyMissing = mode === "redacted" && (provider === "openai" || provider === "anthropic")
    && keys[provider] === false;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-lg max-h-[88vh] overflow-auto rounded-2xl border border-edge bg-ink-800 shadow-2xl">
        {/* header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-edge">
          <div>
            <div className="font-display font-600 text-[15px] text-mist-100">AI Privacy &amp; Engine</div>
            <div className="text-[11px] text-mist-300 mt-0.5">Scan → Redact → Findings → AI</div>
          </div>
          <div className="flex items-center gap-2">
            {saved && <span className="text-[11px] text-signal">saved ✓</span>}
            <button onClick={onClose}
              className="h-7 w-7 rounded-md border border-edge text-mist-300 hover:text-mist-100 hover:bg-ink-600/50">✕</button>
          </div>
        </div>

        <div className="p-5 space-y-5">
          {/* mode cards */}
          <div className="space-y-2.5">
            {MODES.map((m) => {
              const on = m.id === mode;
              return (
                <button key={m.id} onClick={() => patch({ ai_mode: m.id })}
                  className={`w-full text-left rounded-xl border px-4 py-3 transition-all ${
                    on ? m.accent + " ring-1 ring-inset ring-current/20"
                       : "border-edge bg-ink-900/40 hover:bg-ink-700/40 text-mist-200"}`}>
                  <div className="flex items-start gap-3">
                    <span className="text-[18px] leading-none mt-0.5">{m.icon}</span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-[13px] font-600">{m.title}</span>
                        {on && <span className="text-[10px] px-1.5 py-0.5 rounded-full border border-current/40">active</span>}
                      </div>
                      <div className={`text-[11px] mt-1 ${on ? "opacity-90" : "text-mist-300"}`}>{m.desc}</div>
                    </div>
                    <span className={`mt-1 h-3.5 w-3.5 rounded-full border-2 shrink-0 ${on ? "border-current bg-current/30" : "border-mist-300/40"}`} />
                  </div>
                </button>
              );
            })}
          </div>

          {/* provider (redacted only) */}
          {showProvider && (
            <div>
              <div className="text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-2">Provider</div>
              <div className="flex gap-2">
                {PROVIDERS.map((p) => (
                  <button key={p.id} onClick={() => patch({ ai_provider: p.id })}
                    className={`flex-1 text-[12px] px-3 py-2 rounded-lg border transition-colors ${
                      provider === p.id ? "border-signal/50 bg-signal/10 text-signal"
                                        : "border-edge text-mist-200 hover:bg-ink-700/50"}`}>
                    {p.label}
                  </button>
                ))}
              </div>
              {keyMissing && (
                <div className="mt-2 text-[11px] px-3 py-2 rounded-lg border border-alert-med/40 bg-alert-med/10 text-alert-med">
                  No {provider} key configured on the server — Copilot will use the local briefing until a key is set. (Keys live in the environment, never the database.)
                </div>
              )}
            </div>
          )}

          {/* endpoint / model (local or custom) */}
          {showEndpoint && (
            <div className="space-y-2">
              <div className="text-[11px] uppercase tracking-[0.14em] text-mist-300">Endpoint</div>
              <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}
                onBlur={() => patch({ ai_base_url: baseUrl })}
                placeholder="http://localhost:11434/v1  (Ollama / vLLM)"
                className="w-full text-[12px] font-mono px-3 py-2 rounded-lg bg-ink-900/60 border border-edge text-mist-100 placeholder:text-mist-300/60 focus:border-signal/50 outline-none" />
              <input value={model} onChange={(e) => setModel(e.target.value)}
                onBlur={() => patch({ ai_model: model })}
                placeholder="model (e.g. llama3, mistral)"
                className="w-full text-[12px] font-mono px-3 py-2 rounded-lg bg-ink-900/60 border border-edge text-mist-100 placeholder:text-mist-300/60 focus:border-signal/50 outline-none" />
            </div>
          )}

          {/* data boundary strip */}
          <div className="flex items-center gap-2 text-[11px] px-3 py-2.5 rounded-lg border border-edge bg-ink-900/50">
            <span className="text-[14px]">{active.icon}</span>
            <span className="text-mist-200">Data boundary:</span>
            <span className="text-mist-100 font-500">{active.boundary}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default SettingsPanel;
