import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getAlerts } from "../lib/api.js";
import Topbar from "../components/Topbar.jsx";
import RiskGauge from "../components/RiskGauge.jsx";
import { useIntel } from "../lib/intelStore.jsx";

function StatCard({ label, value, unit, tone = "mist" }) {
  const toneMap = {
    signal: "text-signal",
    crit: "text-alert-crit",
    mist: "text-mist-100",
  };
  return (
    <div className="panel p-4">
      <div className="text-[11px] uppercase tracking-[0.14em] text-mist-300">
        {label}
      </div>
      <div className="mt-2 flex items-baseline gap-1.5">
        <span className={`font-display font-600 text-3xl ${toneMap[tone]}`}>
          {value}
        </span>
        {unit && <span className="text-[12px] text-mist-300">{unit}</span>}
      </div>
    </div>
  );
}

const RISK_TONE = {
  Critical: "text-alert-crit border-alert-crit/40",
  High: "text-alert-high border-alert-high/40",
  Medium: "text-alert-med border-alert-med/40",
  Low: "text-alert-low border-alert-low/40",
};

function Overview() {
  const { lastScan, lastMcpScan, history, openRun } = useIntel();

  const cvssMax = lastScan?.risk?.cvss_max;
  const composite =
    typeof cvssMax === "number"
      ? Math.max(cvssMax, lastMcpScan?.servers?.[0]?.exposure_score || 0)
      : lastMcpScan?.servers?.[0]?.exposure_score;

  const serviceCount = lastScan?.services?.length ?? "—";
  const mcpCount = lastMcpScan?.summary?.total ?? "—";
  const unauth = lastMcpScan?.summary?.unauthenticated ?? 0;
  const [alertCount, setAlertCount] = useState(null);
  useEffect(() => {
    let active = true;
    const refresh = () => getAlerts()
      .then((result) => { if (active) setAlertCount(result.unread ?? 0); })
      .catch(() => { if (active) setAlertCount(null); });
    refresh();
    const timer = setInterval(refresh, 30000);
    window.addEventListener("alerts:updated", refresh);
    return () => {
      active = false;
      clearInterval(timer);
      window.removeEventListener("alerts:updated", refresh);
    };
  }, []);

  const hasAnyData = Boolean(lastScan || lastMcpScan);

  return (
    <div className="flex-1 flex flex-col min-w-0">
      <Topbar
        title="Overview"
        subtitle="Unified attack surface across traditional and agentic exposure"
      />
      <div className="flex-1 overflow-auto p-6 space-y-6">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="Traditional surface"
            value={serviceCount}
            unit="services"
          />
          <StatCard label="Shadow AI" value={mcpCount} unit="servers" />
          <StatCard
            label="Unauthenticated MCP"
            value={lastMcpScan ? unauth : "—"}
            tone={unauth > 0 ? "crit" : "mist"}
          />
          <StatCard label="Unread alerts" value={alertCount ?? "—"} />
        </div>

        {!hasAnyData ? (
          <div className="panel p-8">
            <div className="max-w-md">
              <div className="h-9 w-9 rounded-lg border border-signal/30 bg-signal/10 flex items-center justify-center mb-3">
                <span className="text-signal">◈</span>
              </div>
              <h2 className="font-display font-600 text-mist-100 text-[15px]">
                No target selected
              </h2>
              <p className="text-[13px] text-mist-300 mt-1.5 leading-relaxed">
                Run a surface scan to map exposed services, correlate known
                vulnerabilities, and detect exposed Model Context Protocol
                servers in one pass. Past scans appear below.
              </p>
              <div className="flex gap-3 mt-4">
                <Link
                  to="/scan"
                  className="rounded-lg bg-signal/90 hover:bg-signal text-ink-900 font-600 text-[12px] px-4 py-2 transition-colors"
                >
                  Run a surface scan
                </Link>
                <Link
                  to="/shadow-ai"
                  className="rounded-lg border border-edge text-mist-100 hover:bg-ink-600/50 font-600 text-[12px] px-4 py-2 transition-colors"
                >
                  Discover Shadow AI
                </Link>
              </div>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-[auto_1fr] gap-6">
            <div className="panel p-6 flex flex-col items-center justify-center gap-2">
              <RiskGauge
                score={composite}
                level={lastScan?.risk?.level || (unauth > 0 ? "Critical" : "Unknown")}
              />
              <span className="text-[11px] text-mist-300">composite risk</span>
            </div>

            <div className="space-y-4">
              {lastScan && (
                <div className="panel p-4">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="font-display font-600 text-[13px] text-mist-100">
                      Last surface scan
                    </h3>
                    <Link
                      to="/scan"
                      className="text-[11px] text-signal hover:underline"
                    >
                      view details →
                    </Link>
                  </div>
                  <div className="font-mono text-[13px] text-mist-100">
                    {lastScan.target?.value}
                  </div>
                  <div className="text-[12px] text-mist-300 mt-1">
                    {lastScan.services?.length || 0} services ·{" "}
                    {lastScan.vulnerability_count || 0} CVEs mapped
                  </div>
                </div>
              )}

              {lastMcpScan && (
                <div className="panel p-4">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="font-display font-600 text-[13px] text-mist-100">
                      Last Shadow AI discovery
                    </h3>
                    <Link
                      to="/shadow-ai"
                      className="text-[11px] text-signal hover:underline"
                    >
                      view details →
                    </Link>
                  </div>
                  <div className="font-mono text-[13px] text-mist-100">
                    {lastMcpScan.target}
                  </div>
                  <div className="text-[12px] text-mist-300 mt-1">
                    {lastMcpScan.summary?.total || 0} MCP servers ·{" "}
                    {lastMcpScan.summary?.unauthenticated || 0} unauthenticated ·{" "}
                    {lastMcpScan.summary?.with_dangerous_tools || 0} with
                    dangerous tools
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {history.length > 0 && (
          <div className="panel p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-display font-600 text-[13px] text-mist-100">
                Scan history
              </h3>
              <span className="text-[11px] font-mono text-mist-300">
                {history.length}
              </span>
            </div>
            <div className="space-y-2">
              {history.map((r) => {
                const tone = RISK_TONE[r.risk_level] || "text-mist-200 border-edge";
                return (
                  <button
                    key={r.id}
                    onClick={() => openRun(r.id)}
                    className="w-full flex items-center justify-between rounded-lg border border-edge bg-ink-800/50 px-3 py-2 hover:bg-ink-600/40 transition-colors text-left"
                  >
                    <div className="min-w-0">
                      <div className="font-mono text-[13px] text-mist-100 truncate">
                        {r.target_value}
                      </div>
                      <div className="text-[11px] text-mist-300 mt-0.5">
                        {r.target_type} ·{" "}
                        {r.created_at
                          ? new Date(r.created_at).toLocaleString()
                          : ""}
                      </div>
                    </div>
                    <span
                      className={`shrink-0 ml-3 text-[11px] px-2 py-1 rounded-md border ${tone}`}
                    >
                      {r.risk_level || "—"}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Overview;
