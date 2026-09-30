import { useEffect, useState, useCallback } from "react";
import { Link, useSearchParams } from "react-router-dom";
import Topbar from "../components/Topbar.jsx";
import { listAssets, createAsset, deleteAsset, toggleAsset, scanAssetNow, getDrift, askCopilot } from "../lib/api.js";

const KIND_TONE = {
  domain: "text-low border-alert-low/30",
  ip: "text-signal border-signal/30",
  mcp: "text-alert-high border-alert-high/30",
};
const RISK_TONE = {
  Critical: "text-alert-crit border-alert-crit/40",
  High: "text-alert-high border-alert-high/40",
  Medium: "text-alert-med border-alert-med/40",
  Low: "text-alert-low border-alert-low/40",
};
const CHANGE_LABEL = {
  tool_appeared: "New dangerous tool exposed",
  tool_disappeared: "Dangerous tool removed",
  tool_capability_changed: "Tool capability changed",
  cve_appeared: "New vulnerability",
  cve_resolved: "Vulnerability resolved",
  service_appeared: "New service exposed",
  service_disappeared: "Service closed",
  risk_changed: "Risk level",
  severity_changed: "Severity",
  auth_changed: "Authentication posture",
  manifest_fingerprint_changed: "Manifest checksum changed",
  manifest_visibility_changed: "Manifest evidence coverage changed",
  manifest_version_changed: "Fingerprint format updated",
  description_changed: "Tool description changed",
  schema_changed: "Input schema changed",
  output_schema_changed: "Output schema changed",
  annotations_changed: "Tool annotations changed",
  tool_metadata_changed: "Tool metadata changed",
  server_info_changed: "Server metadata changed",
  protocol_changed: "Protocol changed",
  unclassified_manifest_change: "Manifest change needs review",
};

function timeAgo(iso) {
  if (!iso) return "";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const s = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} hr ago`;
  const d = Math.floor(h / 24);
  return `${d} day${d > 1 ? "s" : ""} ago`;
}

export function driftVerdict(changes) {
  const hasCrit = changes.some((c) => c.tone === "crit");
  const hasGood = changes.some((c) => c.tone === "good");
  const hasUncertain = changes.some((c) => c.tone === "warn");
  if (hasCrit)
    return { label: "Exposure increased", icon: "▲",
             cls: "text-alert-crit border-alert-crit/50 bg-alert-crit/10" };
  if (hasGood)
    return { label: hasUncertain ? "Exposure reduced · review other changes" : "Exposure reduced", icon: "▼",
             cls: "text-signal border-signal/50 bg-signal/10" };
  if (hasUncertain)
    return { label: "Change needs review", icon: "◆",
             cls: "text-alert-med border-alert-med/50 bg-alert-med/10" };
  return { label: "Configuration changed", icon: "◆",
           cls: "text-alert-med border-alert-med/50 bg-alert-med/10" };
}

function DriftGroup({ title, items, dotCls }) {
  if (!items.length) return null;
  return (
    <div>
      <div className="text-[11px] text-mist-300 mb-1 flex items-center gap-1.5">
        <span className={`h-1.5 w-1.5 rounded-full ${dotCls}`} /> {title}
      </div>
      <ul className="space-y-1">
        {items.map((ch, i) => (
          <li key={i} className="text-[12px] text-mist-100">
            <span className="text-mist-300">
              {CHANGE_LABEL[ch.kind] || ch.kind.replace(/_/g, " ")}:
            </span>{" "}
            <span className="font-mono">{ch.detail}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function DriftCard({ data, asset }) {
  if (!data.available) {
    return (
      <div className="rounded-lg border border-edge bg-ink-900/60 px-3 py-2.5 text-[12px] text-mist-300">
        {data.reason || "No drift available."} Run a second scan to compare.
      </div>
    );
  }
  if (data.change_count === 0) {
    return (
      <div className={`rounded-lg border px-3 py-2.5 text-[12px] flex items-center gap-2 ${data.comparison_limits?.length ? "border-alert-med/30 bg-alert-med/5 text-alert-med" : "border-signal/30 bg-signal/5 text-signal"}`}>
        <span>—</span> {data.summary || "No tracked changes"}
        {data.previous_run?.at ? ` (${timeAgo(data.previous_run.at)})` : ""}
      </div>
    );
  }
  const v = driftVerdict(data.changes);
  const transition = data.changes.find(
    (c) => c.kind === "severity_changed" || c.kind === "risk_changed");
  const crit = data.changes.filter((c) => c.tone === "crit");
  const good = data.changes.filter((c) => c.tone === "good");
  const other = data.changes.filter(
    (c) => c.tone !== "crit" && c.tone !== "good");
  return (
    <div className="rounded-lg border border-edge bg-ink-900/60 overflow-hidden">
      <div className={`flex items-center justify-between px-3 py-2 border-b border-edge ${v.cls}`}>
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-[13px] leading-none">{v.icon}</span>
          <span className="text-[13px] font-600">{v.label}</span>
          {transition && (
            <span className="font-mono text-[12px] opacity-90 truncate">· {transition.detail}</span>
          )}
        </div>
        <span className="text-[11px] text-mist-300 shrink-0">
          vs previous scan{data.previous_run?.at ? ` · ${timeAgo(data.previous_run.at)}` : ""}
        </span>
      </div>
      <div className="px-3 py-2.5 space-y-3">
        <DriftGroup title="More exposed now" items={crit} dotCls="bg-alert-crit" />
        <DriftGroup title="Improved" items={good} dotCls="bg-signal" />
        <DriftGroup title="Other changes" items={other} dotCls="bg-mist-300" />
        {data.comparison_limits?.length > 0 && (
          <div className="text-[11px] text-alert-med border-t border-edge pt-2">
            {data.comparison_limits.join(" ")}
          </div>
        )}
      </div>
      {asset.kind === "mcp" && (
        <div className="px-3 py-2 border-t border-edge flex items-center justify-between">
          <span className="text-[11px] text-mist-300">Recorded for monitoring</span>
          <Link to="/safe-proof"
            className="text-[11px] px-2.5 py-1 rounded-md border border-signal/40 text-signal hover:bg-signal/10 transition-colors">
            Open Safe Proof →
          </Link>
        </div>
      )}
    </div>
  );
}

const COPILOT_MODE = {
  offline: { icon: "🔒", label: "Offline" },
  redacted: { icon: "🛡", label: "Redacted" },
  local: { icon: "🏠", label: "Local AI" },
};

function CopilotPanel({ assetId }) {
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState("");

  const ask = useCallback((question) => {
    setBusy(true);
    askCopilot(assetId, question)
      .then((r) => setData(r))
      .catch((e) => setData({ answer: "Copilot unavailable: " + (e.message || "error"), suggestions: [] }))
      .finally(() => setBusy(false));
  }, [assetId]);

  useEffect(() => { ask(""); }, [ask]);   // initial briefing

  function submit(e) {
    e.preventDefault();
    const question = q.trim();
    if (!question) return;
    setQ("");
    ask(question);
  }

  const meta = COPILOT_MODE[data?.mode] || null;

  return (
    <div className="rounded-lg border border-edge bg-ink-900/60 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 border-b border-edge">
        <span className="text-[12px] font-600 text-mist-100">🤖 Copilot</span>
        {meta && (
          <span className="text-[10px] px-2 py-0.5 rounded-md border border-edge text-mist-300">
            {meta.icon} {meta.label}{data?.fallback ? " · local briefing" : ""}
          </span>
        )}
      </div>

      <div className="px-3 py-3">
        {busy && !data ? (
          <div className="text-[12px] text-mist-300">Analysing evidence…</div>
        ) : (
          <div className="text-[12.5px] text-mist-100 whitespace-pre-wrap leading-relaxed">
            {data?.answer}
          </div>
        )}

        {data?.suggestions?.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mt-3">
            {data.suggestions.map((sug, i) => (
              <button key={i} onClick={() => ask(sug)} disabled={busy}
                className="text-[11px] px-2.5 py-1 rounded-full border border-edge text-mist-200 hover:text-mist-100 hover:bg-ink-700/50 transition-colors disabled:opacity-50">
                {sug}
              </button>
            ))}
          </div>
        )}
      </div>

      <form onSubmit={submit} className="flex gap-2 px-3 py-2 border-t border-edge">
        <input value={q} onChange={(e) => setQ(e.target.value)}
          placeholder="Ask about this asset…"
          className="flex-1 text-[12px] px-3 py-1.5 rounded-lg bg-ink-800/70 border border-edge text-mist-100 placeholder:text-mist-300/60 focus:border-signal/50 outline-none" />
        <button type="submit" disabled={busy || !q.trim()}
          className="text-[12px] px-3 py-1.5 rounded-lg border border-signal/40 text-signal hover:bg-signal/10 transition-colors disabled:opacity-50">
          {busy ? "…" : "Ask"}
        </button>
      </form>
    </div>
  );
}

function Assets() {
  const [assets, setAssets] = useState([]);
  const [value, setValue] = useState("");
  const [kind, setKind] = useState("domain");
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [scanningId, setScanningId] = useState(null);
  const [driftOpen, setDriftOpen] = useState(null);
  const [driftData, setDriftData] = useState(null);
  const [driftBusy, setDriftBusy] = useState(false);
  const [searchParams] = useSearchParams();
  const [copilotOpen, setCopilotOpen] = useState(null);

  const refresh = useCallback(() => {
    listAssets().then((r) => setAssets(Array.isArray(r) ? r : [])).catch(() => {});
  }, []);
  useEffect(() => { refresh(); }, [refresh]);

  // Deep link from an alert: /assets?open=<assetId> auto-opens that drift card.
  useEffect(() => {
    const openId = searchParams.get("open");
    if (!openId || assets.length === 0) return;
    const a = assets.find((x) => String(x.id) === String(openId));
    if (a && driftOpen !== a.id) showDrift(a);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams, assets]);

  async function add(e) {
    e.preventDefault();
    if (!value.trim()) return;
    setBusy(true); setError("");
    try {
      const r = await createAsset(value.trim(), kind, label.trim());
      if (r.detail) throw new Error(r.detail);
      setValue(""); setLabel(""); refresh();
    } catch (err) { setError(err.message || "Could not add asset"); }
    finally { setBusy(false); }
  }
  async function remove(id) { await deleteAsset(id).catch(() => {}); refresh(); }
  async function flip(a) { await toggleAsset(a.id, !a.monitoring).catch(() => {}); refresh(); }
  async function scan(a) {
    setScanningId(a.id); setError("");
    try {
      const r = await scanAssetNow(a.id);
      if (r && r.error) throw new Error(r.error);
      await refresh();
      if (driftOpen === a.id) setDriftData(await getDrift(a.id));
      window.dispatchEvent(new Event("alerts:updated"));
    } catch (err) { setError(err.message || "Scan failed"); }
    finally { setScanningId(null); }
  }
  async function showDrift(a) {
    if (driftOpen === a.id) { setDriftOpen(null); setDriftData(null); return; }
    setDriftOpen(a.id); setDriftData(null); setDriftBusy(true);
    try {
      setDriftData(await getDrift(a.id));
    } catch (err) {
      setDriftData({ available: false, reason: err.message || "Could not load drift" });
    } finally { setDriftBusy(false); }
  }

  return (
    <div className="flex-1 flex flex-col min-w-0">
      <Topbar title="Assets" subtitle="Your monitored attack surface — targets tracked and re-checked over time" />
      <div className="flex-1 overflow-auto p-6 space-y-6">
        <form onSubmit={add} className="panel p-4 grid grid-cols-1 md:grid-cols-[1fr_140px_1fr_auto] gap-3 items-end">
          <div>
            <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">Target</label>
            <input value={value} onChange={(e) => setValue(e.target.value)} placeholder="acme.com or 8.8.8.8"
              className="w-full rounded-lg border border-edge bg-ink-800 px-3 py-2 text-[13px] font-mono text-mist-100 focus:outline-none focus:border-signal/50" />
          </div>
          <div>
            <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">Type</label>
            <select value={kind} onChange={(e) => setKind(e.target.value)}
              className="w-full rounded-lg border border-edge bg-ink-800 px-3 py-2 text-[13px] text-mist-100 focus:outline-none focus:border-signal/50">
              <option value="domain">Domain</option><option value="ip">IP</option><option value="mcp">MCP host</option>
            </select>
          </div>
          <div>
            <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">Label (optional)</label>
            <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Production API"
              className="w-full rounded-lg border border-edge bg-ink-800 px-3 py-2 text-[13px] text-mist-100 focus:outline-none focus:border-signal/50" />
          </div>
          <button type="submit" disabled={busy}
            className="rounded-lg bg-signal/90 hover:bg-signal text-ink-900 font-600 text-[13px] px-6 py-2.5 transition-colors disabled:opacity-50">
            {busy ? "Adding…" : "Add asset"}
          </button>
        </form>

        {error && <div className="rounded-lg border border-alert-crit/40 bg-alert-crit/10 px-3 py-2 text-[12px] text-alert-crit">{error}</div>}

        <div className="panel p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-display font-600 text-[13px] text-mist-100">Monitored assets</h3>
            <span className="text-[11px] font-mono text-mist-300">{assets.length}</span>
          </div>
          {assets.length === 0 ? (
            <p className="text-[13px] text-mist-300 leading-relaxed max-w-md">
              No assets yet. Add a target above to start tracking it. Assets are the
              foundation for scheduled monitoring and drift detection.
            </p>
          ) : (
            <div className="space-y-2">
              {assets.map((a) => (
                <div key={a.id} className="space-y-2">
                  <div className="flex items-center justify-between rounded-lg border border-edge bg-ink-800/50 px-3 py-2.5">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[13px] text-mist-100 truncate">{a.value}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border ${KIND_TONE[a.kind] || "border-edge text-mist-300"}`}>{a.kind}</span>
                        {a.last_risk_level && (
                          <span className={`text-[10px] px-1.5 py-0.5 rounded border ${RISK_TONE[a.last_risk_level] || "border-edge text-mist-300"}`}>{a.last_risk_level}</span>
                        )}
                      </div>
                      <div className="text-[11px] text-mist-300 mt-0.5">
                        {a.label ? a.label + " · " : ""}{a.last_scanned_at ? "last scan " + new Date(a.last_scanned_at).toLocaleString() : "never scanned"}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button onClick={() => flip(a)}
                        className={`text-[11px] px-2.5 py-1 rounded-md border transition-colors ${a.monitoring ? "border-signal/40 text-signal bg-signal/10" : "border-edge text-mist-300"}`}>
                        {a.monitoring ? "● monitoring" : "○ paused"}
                      </button>
                      <button onClick={() => scan(a)} disabled={scanningId === a.id}
                        className="text-[11px] px-2.5 py-1 rounded-md border border-signal/40 text-signal hover:bg-signal/10 transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                        {scanningId === a.id ? "Scanning…" : "Scan now"}
                      </button>
                      <button onClick={() => showDrift(a)}
                        className={`text-[11px] px-2.5 py-1 rounded-md border transition-colors ${driftOpen === a.id ? "border-signal/50 text-signal bg-signal/10" : "border-edge text-mist-200 hover:text-mist-100 hover:bg-ink-600/50"}`}>
                        {driftBusy && driftOpen === a.id ? "…" : "Changes"}
                      </button>
                      <button onClick={() => setCopilotOpen(copilotOpen === a.id ? null : a.id)}
                        className={`text-[11px] px-2.5 py-1 rounded-md border transition-colors ${copilotOpen === a.id ? "border-signal/50 text-signal bg-signal/10" : "border-edge text-mist-200 hover:text-mist-100 hover:bg-ink-600/50"}`}>
                        🤖 Copilot
                      </button>
                      {a.kind === "mcp" && (
                        <Link to="/safe-proof" className="text-[11px] px-2.5 py-1 rounded-md border border-edge text-mist-200 hover:text-mist-100 hover:bg-ink-600/50">Safe Proof</Link>
                      )}
                      <button onClick={() => remove(a.id)} className="text-[11px] px-2.5 py-1 rounded-md border border-alert-crit/30 text-alert-crit hover:bg-alert-crit/10 transition-colors">Remove</button>
                    </div>
                  </div>
                  {driftOpen === a.id && driftData && (
                    <DriftCard data={driftData} asset={a} />
                  )}
                  {copilotOpen === a.id && <CopilotPanel assetId={a.id} />}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default Assets;
