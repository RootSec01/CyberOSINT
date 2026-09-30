import { useState } from "react";
import Topbar from "../components/Topbar.jsx";
import SafeProofReport from "../components/SafeProofReport.jsx";
import LiveAttackGraph from "../components/LiveAttackGraph.jsx";

function SafeProof() {
  const [host, setHost] = useState("127.0.0.1");
  const [port, setPort] = useState(9500);
  const [useTls, setUseTls] = useState(false);
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState("");
  const [proof, setProof] = useState(null);
  // a run key forces the graph (and its EventSource) to remount per scan
  const [runKey, setRunKey] = useState(0);

  function submit(e) {
    e.preventDefault();
    if (!host.trim()) return;
    setError("");
    setProof(null);
    setStreaming(true);
    setRunKey((k) => k + 1);
  }

  function onDone(result) {
    if (result && result.is_mcp === false) {
      setError("No MCP server verified at this target.");
      setStreaming(false);
      return;
    }
    setProof(result);
  }

  function onError(message) {
    setError(message || "Scan failed");
    setStreaming(false);
  }

  return (
    <div className="flex-1 flex flex-col min-w-0">
      <Topbar
        title="Safe Proof"
        subtitle="Watch the attack map build live — then read the verified certificate. No data touched, no dangerous tool invoked."
      />
      <div className="flex-1 overflow-auto p-6 space-y-6">
        <form
          onSubmit={submit}
          className="panel p-4 flex flex-col md:flex-row md:items-end gap-3"
        >
          <div className="flex-1">
            <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">
              Host
            </label>
            <input
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="127.0.0.1"
              className="w-full rounded-lg border border-edge bg-ink-800 px-3 py-2 text-[13px] font-mono text-mist-100 focus:outline-none focus:border-signal/50"
            />
          </div>
          <div className="w-full md:w-32">
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
          <label className="flex items-center gap-2 text-[12px] text-mist-200 pb-2.5">
            <input
              type="checkbox"
              checked={useTls}
              onChange={(e) => setUseTls(e.target.checked)}
            />
            TLS
          </label>
          <button
            type="submit"
            disabled={streaming && !proof && !error}
            className="rounded-lg bg-signal/90 hover:bg-signal text-ink-900 font-600 text-[13px] px-6 py-2.5 transition-colors disabled:opacity-50"
          >
            {streaming && !proof && !error ? "Scanning…" : "Run Safe Proof"}
          </button>
        </form>

        {error && (
          <div className="rounded-lg border border-alert-crit/40 bg-alert-crit/10 px-3 py-2 text-[12px] text-alert-crit">
            {error}
          </div>
        )}

        {streaming && (
          <LiveAttackGraph
            key={runKey}
            host={host.trim()}
            port={Number(port)}
            useTls={useTls}
            onDone={onDone}
            onError={onError}
          />
        )}

        {proof && <SafeProofReport proof={proof} />}

        {!streaming && !proof && !error && (
          <div className="panel p-8 max-w-lg">
            <div className="h-9 w-9 rounded-lg border border-signal/30 bg-signal/10 flex items-center justify-center mb-3">
              <span className="text-signal">🛡</span>
            </div>
            <h3 className="font-display font-600 text-mist-100 text-[15px]">
              Watch a verified attack unfold — safely
            </h3>
            <p className="text-[13px] text-mist-300 mt-1.5 leading-relaxed">
              Point Safe Proof at a verified MCP endpoint. The graph draws the
              discovery and attack path node-by-node as it happens, mapped to
              MITRE ATT&CK — then a full certificate is produced. Dangerous tools
              are never invoked. Try your lab server on 127.0.0.1:9500.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default SafeProof;
