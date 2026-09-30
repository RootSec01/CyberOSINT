import { useState } from "react";
import Topbar from "../components/Topbar.jsx";
import { runMcpScan, verifyDirect } from "../lib/api.js";
import { useIntel } from "../lib/intelStore.jsx";

const FLAG_META = {
  command_exec: { label: "command exec", tone: "bg-alert-crit/15 text-alert-crit border-alert-crit/30" },
  db_write: { label: "db write", tone: "bg-alert-high/15 text-alert-high border-alert-high/30" },
  secrets: { label: "secrets", tone: "bg-alert-high/15 text-alert-high border-alert-high/30" },
  filesystem: { label: "filesystem", tone: "bg-alert-med/15 text-alert-med border-alert-med/30" },
  network: { label: "network", tone: "bg-alert-low/15 text-alert-low border-alert-low/30" },
};

function scoreTone(score) {
  if (score >= 7) return "#F87171";
  if (score >= 4) return "#FB923C";
  if (score >= 1.5) return "#FBBF24";
  return "#38BDF8";
}

const TABS = [
  { id: "discover", label: "Discover" },
  { id: "direct", label: "Direct verify" },
];

function ShadowAI() {
  const [tab, setTab] = useState("discover");

  return (
    <div className="flex-1 flex flex-col min-w-0">
      <Topbar
        title="Shadow AI"
        subtitle="Discover exposed Model Context Protocol servers and assess their exposure"
      />
      <div className="flex-1 overflow-auto p-6 space-y-6">
        <div className="flex gap-1 border-b border-edge">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={[
                "px-4 py-2.5 text-[13px] font-500 border-b-2 -mb-px transition-colors",
                tab === t.id
                  ? "border-signal text-mist-100"
                  : "border-transparent text-mist-300 hover:text-mist-100",
              ].join(" ")}
            >
              {t.label}
            </button>
          ))}
        </div>

        {tab === "discover" ? <DiscoverPanel /> : <DirectVerifyPanel />}
      </div>
    </div>
  );
}

function DiscoverPanel() {
  const { recordMcpScan } = useIntel();
  const [target, setTarget] = useState("");
  const [type, setType] = useState("domain");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [selected, setSelected] = useState(null);

  async function submit(e) {
    e.preventDefault();
    if (!target.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    setSelected(null);
    try {
      const data = await runMcpScan(target.trim(), type, true);
      if (data.error) throw new Error(data.error);
      setResult(data);
      recordMcpScan(data);
      if (data.servers?.length) setSelected(0);
    } catch (err) {
      setError(err.message || "MCP scan failed");
    } finally {
      setLoading(false);
    }
  }

  const servers = result?.servers || [];
  const summary = result?.summary;

  return (
    <div className="space-y-6">
      <form onSubmit={submit} className="panel p-4 flex flex-col md:flex-row md:items-end gap-3">
        <div className="flex-1">
          <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">
            Target
          </label>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="example.com"
            className="w-full rounded-lg border border-edge bg-ink-800 px-3 py-2 text-[13px] font-mono text-mist-100 placeholder:text-mist-300/50 focus:outline-none focus:border-signal/50"
          />
        </div>
        <div className="w-full md:w-40">
          <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">
            Type
          </label>
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="w-full rounded-lg border border-edge bg-ink-800 px-3 py-2 text-[13px] text-mist-100 focus:outline-none focus:border-signal/50"
          >
            <option value="domain">Domain</option>
            <option value="ip">IP address</option>
          </select>
        </div>
        <button
          type="submit"
          disabled={loading}
          className="rounded-lg bg-signal/90 hover:bg-signal text-ink-900 font-600 text-[13px] px-6 py-2.5 transition-colors disabled:opacity-50"
        >
          {loading ? "Discovering…" : "Discover"}
        </button>
      </form>

      {error && <ErrorBox text={error} />}
      {loading && <LoadingState text="scanning for exposed agents…" />}

      {result && !loading && (
        <>
          <ExposureHeader summary={summary} label={result.target} />
          {servers.length === 0 ? (
            <div className="panel p-8">
              <h3 className="font-display font-600 text-mist-100 text-[15px]">
                No exposed MCP servers found
              </h3>
              <p className="text-[13px] text-mist-300 mt-1.5 leading-relaxed max-w-md">
                Passive discovery across Shodan, Censys, and Certificate
                Transparency surfaced no MCP endpoints for this target. This
                is the expected result for a well-secured surface.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-[1fr_1.2fr] gap-5">
              <ServerList servers={servers} selected={selected} onSelect={setSelected} />
              <ServerDetail server={servers[selected]} />
            </div>
          )}
        </>
      )}

      {!result && !loading && !error && (
        <EmptyState
          glyph="⬡"
          title="Discover exposed AI agents"
          text="Passive discovery locates Model Context Protocol servers tied to a target across Shodan, Censys, and Certificate Transparency. Authorized hosts are then verified through the standard MCP handshake to enumerate the tools they expose — no tool is ever invoked."
        />
      )}
    </div>
  );
}

function DirectVerifyPanel() {
  const { recordMcpScan } = useIntel();
  const [host, setHost] = useState("");
  const [port, setPort] = useState(443);
  const [useTls, setUseTls] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  async function submit(e) {
    e.preventDefault();
    if (!host.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await verifyDirect(host.trim(), Number(port), useTls);
      if (data.error) throw new Error(data.error);
      setResult(data);
      if (data.authorized) {
        recordMcpScan({
          target: `${host}:${port}`,
          summary: {
            total: 1,
            unauthenticated: data.server.auth_required === false ? 1 : 0,
            with_dangerous_tools: data.server.tools.some((t) =>
              t.risk_flags.some((f) => ["command_exec", "db_write"].includes(f))
            )
              ? 1
              : 0,
          },
        });
      }
    } catch (err) {
      setError(err.message || "Verification failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={submit} className="panel p-4 flex flex-col md:flex-row md:items-end gap-3">
        <div className="flex-1">
          <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">
            Host
          </label>
          <input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="127.0.0.1"
            className="w-full rounded-lg border border-edge bg-ink-800 px-3 py-2 text-[13px] font-mono text-mist-100 placeholder:text-mist-300/50 focus:outline-none focus:border-signal/50"
          />
        </div>
        <div className="w-full md:w-28">
          <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">
            Port
          </label>
          <input
            type="number"
            value={port}
            onChange={(e) => setPort(e.target.value)}
            className="w-full rounded-lg border border-edge bg-ink-800 px-3 py-2 text-[13px] font-mono text-mist-100 focus:outline-none focus:border-signal/50"
          />
        </div>
        <label className="flex items-center gap-2 text-[12px] text-mist-200 pb-2.5 select-none cursor-pointer">
          <input
            type="checkbox"
            checked={useTls}
            onChange={(e) => setUseTls(e.target.checked)}
            className="accent-signal"
          />
          TLS
        </label>
        <button
          type="submit"
          disabled={loading}
          className="rounded-lg bg-signal/90 hover:bg-signal text-ink-900 font-600 text-[13px] px-6 py-2.5 transition-colors disabled:opacity-50"
        >
          {loading ? "Verifying…" : "Verify"}
        </button>
      </form>

      <p className="text-[11px] text-mist-300 -mt-3">
        Requires an active authorization grant for this host. Issue one from
        the Authorization page first.
      </p>

      {error && <ErrorBox text={error} />}
      {loading && <LoadingState text="performing MCP handshake…" />}

      {result && !loading && !result.authorized && (
        <div className="panel p-6">
          <div className="text-[13px] text-alert-crit">
            Not authorized: {result.reason}
          </div>
          <p className="text-[12px] text-mist-300 mt-1.5">
            Grant this host from the Authorization page, then retry.
          </p>
        </div>
      )}

      {result && !loading && result.authorized && (
        <ServerDetail server={result.server} />
      )}

      {!result && !loading && !error && (
        <EmptyState
          glyph="⊹"
          title="Verify a known endpoint directly"
          text="When you already know a candidate MCP address — from an inventory, a client report, or local testing — verify it directly without running passive discovery first."
        />
      )}
    </div>
  );
}

function ExposureHeader({ summary, label }) {
  if (!summary) return null;
  const cells = [
    { label: "MCP servers", value: summary.total, tone: "text-mist-100" },
    { label: "Unauthenticated", value: summary.unauthenticated, tone: "text-alert-crit" },
    { label: "Dangerous tools", value: summary.with_dangerous_tools, tone: "text-alert-high" },
  ];
  return (
    <div className="panel p-5">
      <div className="text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-3">
        Exposure summary · <span className="font-mono">{label}</span>
      </div>
      <div className="grid grid-cols-3 gap-4">
        {cells.map((c) => (
          <div key={c.label}>
            <div className={`font-display font-700 text-3xl ${c.tone}`}>{c.value}</div>
            <div className="text-[11px] text-mist-300 mt-1">{c.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ServerList({ servers, selected, onSelect }) {
  return (
    <div className="panel p-2 h-fit">
      <div className="space-y-1">
        {servers.map((s, i) => {
          const active = i === selected;
          const tone = scoreTone(s.exposure_score);
          return (
            <button
              key={i}
              onClick={() => onSelect(i)}
              className={[
                "w-full text-left rounded-lg px-3 py-2.5 border transition-colors",
                active
                  ? "bg-ink-600/70 border-signal/25"
                  : "bg-transparent border-transparent hover:bg-ink-600/40",
              ].join(" ")}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[12px] text-mist-100 truncate">
                  {s.host}:{s.port}
                </span>
                <span
                  className="text-[11px] font-mono font-600 px-1.5 py-0.5 rounded"
                  style={{ color: tone, backgroundColor: `${tone}1a` }}
                >
                  {s.exposure_score.toFixed(1)}
                </span>
              </div>
              <div className="flex items-center gap-2 mt-1.5">
                {s.auth_required === false && (
                  <span className="text-[10px] text-alert-crit flex items-center gap-1">
                    <span className="h-1.5 w-1.5 rounded-full bg-alert-crit" />
                    unauthenticated
                  </span>
                )}
                {s.auth_required === true && (
                  <span className="text-[10px] text-mist-300 flex items-center gap-1">
                    <span className="h-1.5 w-1.5 rounded-full bg-signal" />
                    protected
                  </span>
                )}
                {s.auth_required === null && (
                  <span className="text-[10px] text-mist-300">unverified</span>
                )}
                <span className="text-[10px] text-mist-300 font-mono">
                  {s.tools.length} tool{s.tools.length === 1 ? "" : "s"}
                </span>
              </div>
              <div className="mt-1.5 h-1 rounded-full bg-ink-500 overflow-hidden">
                <div
                  className="h-full rounded-full"
                  style={{ width: `${Math.min(s.exposure_score * 10, 100)}%`, backgroundColor: tone }}
                />
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function ServerDetail({ server }) {
  if (!server) return null;

  const dangerous = server.tools.filter((t) =>
    t.risk_flags.some((f) => ["command_exec", "db_write", "secrets"].includes(f))
  );

  return (
    <div className="panel p-5 space-y-5">
      <div>
        <div className="flex items-center justify-between gap-3">
          <span className="font-mono text-[14px] text-mist-100 break-all">
            {server.endpoint}
          </span>
          <span
            className="text-[13px] font-mono font-600 px-2 py-1 rounded flex-shrink-0"
            style={{
              color: scoreTone(server.exposure_score),
              backgroundColor: `${scoreTone(server.exposure_score)}1a`,
            }}
          >
            {server.exposure_score.toFixed(1)} / 10
          </span>
        </div>
        <div className="flex flex-wrap gap-2 mt-2 text-[11px]">
          <Meta label="transport" value={server.transport} />
          <Meta
            label="auth"
            value={
              server.auth_required === false
                ? "none"
                : server.auth_required === true
                ? "required"
                : "unknown"
            }
          />
          <Meta label="confidence" value={server.confidence} />
          <Meta label="via" value={(server.discovered_via || []).join(", ") || "—"} />
        </div>
      </div>

      {server.auth_required === false && dangerous.length > 0 && (
        <div className="rounded-lg border border-alert-crit/40 bg-alert-crit/10 p-3">
          <div className="text-[12px] font-600 text-alert-crit mb-1">
            Why this is critical
          </div>
          <p className="text-[12px] text-mist-200 leading-relaxed">
            This server accepts requests without authentication and advertises{" "}
            {dangerous.length} high-privilege tool
            {dangerous.length === 1 ? "" : "s"}. An unauthenticated caller could
            reach {dangerous.map((t) => t.name).slice(0, 3).join(", ")}
            {dangerous.length > 3 ? ", and more" : ""} directly.
          </p>
        </div>
      )}

      <div>
        <div className="text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-2">
          Advertised tools ({server.tools.length})
        </div>
        {server.tools.length === 0 ? (
          <div className="text-[12px] text-mist-300">
            {server.verified
              ? "No tools advertised, or the server requires authentication to list them."
              : "Not verified — verification requires an authorization grant for this host."}
          </div>
        ) : (
          <div className="space-y-2">
            {server.tools.map((t, i) => (
              <div key={i} className="rounded-lg border border-edge bg-ink-800/50 px-3 py-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[12px] text-mist-100">{t.name}</span>
                  <div className="flex flex-wrap gap-1 justify-end">
                    {t.risk_flags.map((f) => {
                      const meta = FLAG_META[f] || {
                        label: f,
                        tone: "bg-ink-600 text-mist-300 border-edge",
                      };
                      return (
                        <span
                          key={f}
                          className={`text-[9px] uppercase tracking-wide px-1.5 py-0.5 rounded border ${meta.tone}`}
                        >
                          {meta.label}
                        </span>
                      );
                    })}
                  </div>
                </div>
                {t.description && (
                  <p className="text-[11px] text-mist-300 mt-1 leading-snug">
                    {t.description}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {server.notes?.length > 0 && (
        <div className="text-[11px] text-mist-300 font-mono space-y-0.5">
          {server.notes.map((n, i) => (
            <div key={i}>· {n}</div>
          ))}
        </div>
      )}
    </div>
  );
}

function Meta({ label, value }) {
  return (
    <span className="rounded-md bg-ink-600/60 border border-edge px-2 py-1">
      <span className="text-mist-300">{label} </span>
      <span className="font-mono text-mist-100">{value}</span>
    </span>
  );
}

function ErrorBox({ text }) {
  return (
    <div className="rounded-lg border border-alert-crit/40 bg-alert-crit/10 px-3 py-2 text-[12px] text-alert-crit">
      {text}
    </div>
  );
}

function LoadingState({ text }) {
  return (
    <div className="panel p-8 flex items-center justify-center">
      <div className="flex flex-col items-center gap-3">
        <div className="h-10 w-10 rounded-full border-2 border-edge border-t-signal animate-spin" />
        <div className="text-[12px] font-mono text-mist-300">{text}</div>
      </div>
    </div>
  );
}

function EmptyState({ glyph, title, text }) {
  return (
    <div className="panel p-8">
      <div className="max-w-md">
        <div className="h-9 w-9 rounded-lg border border-signal/30 bg-signal/10 flex items-center justify-center mb-3">
          <span className="text-signal">{glyph}</span>
        </div>
        <h2 className="font-display font-600 text-mist-100 text-[15px]">{title}</h2>
        <p className="text-[13px] text-mist-300 mt-1.5 leading-relaxed">{text}</p>
      </div>
    </div>
  );
}

export default ShadowAI;
