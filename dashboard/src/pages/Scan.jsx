import { useState } from "react";
import Topbar from "../components/Topbar.jsx";
import RiskGauge from "../components/RiskGauge.jsx";
import { runScan } from "../lib/api.js";
import { useIntel } from "../lib/intelStore.jsx";

const TARGET_TYPES = [
  { value: "ip", label: "IP address" },
  { value: "domain", label: "Domain" },
  { value: "cidr", label: "CIDR" },
  { value: "asn", label: "ASN" },
  { value: "org", label: "Organization" },
];

const SEV_TONE = {
  CRITICAL: "text-alert-crit",
  HIGH: "text-alert-high",
  MEDIUM: "text-alert-med",
  LOW: "text-alert-low",
};

function severityTone(sev) {
  return SEV_TONE[String(sev || "").toUpperCase()] || "text-mist-300";
}

function Scan() {
  const { recordScan } = useIntel();
  const [type, setType] = useState("domain");
  const [value, setValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  async function submit(e) {
    e.preventDefault();
    if (!value.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await runScan(type, value.trim());
      if (data.error) throw new Error(data.error);
      setResult(data);
      recordScan(data);
    } catch (err) {
      setError(err.message || "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex-1 flex flex-col min-w-0">
      <Topbar
        title="Surface scan"
        subtitle="Map exposed services, correlate vulnerabilities, assess risk"
      />
      <div className="flex-1 overflow-auto p-6">
        <div className="grid grid-cols-1 xl:grid-cols-[320px_1fr] gap-6">
          <form onSubmit={submit} className="panel p-4 h-fit space-y-4">
            <div>
              <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">
                Target type
              </label>
              <select
                value={type}
                onChange={(e) => setType(e.target.value)}
                className="w-full rounded-lg border border-edge bg-ink-800 px-3 py-2 text-[13px] text-mist-100 focus:outline-none focus:border-signal/50"
              >
                {TARGET_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">
                Target
              </label>
              <input
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder="example.com"
                className="w-full rounded-lg border border-edge bg-ink-800 px-3 py-2 text-[13px] font-mono text-mist-100 placeholder:text-mist-300/50 focus:outline-none focus:border-signal/50"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-signal/90 hover:bg-signal text-ink-900 font-600 text-[13px] py-2.5 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? "Scanning…" : "Run scan"}
            </button>

            {error && (
              <div className="rounded-lg border border-alert-crit/40 bg-alert-crit/10 px-3 py-2 text-[12px] text-alert-crit">
                {error}
              </div>
            )}
          </form>

          <div className="min-w-0">
            {!result && !loading && <EmptyState />}
            {loading && <LoadingState />}
            {result && <Results data={result} tone={severityTone} />}
          </div>
        </div>
      </div>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="panel p-8 h-full flex items-center">
      <div className="max-w-sm">
        <div className="h-9 w-9 rounded-lg border border-signal/30 bg-signal/10 flex items-center justify-center mb-3">
          <span className="text-signal">⊹</span>
        </div>
        <h2 className="font-display font-600 text-mist-100 text-[15px]">
          Ready to scan
        </h2>
        <p className="text-[13px] text-mist-300 mt-1.5 leading-relaxed">
          Enter a target to pull exposed services from Shodan and Censys, map
          them to known CVEs, and compute an overall risk level. Active checks
          run only against authorized hosts.
        </p>
      </div>
    </div>
  );
}

function LoadingState() {
  return (
    <div className="panel p-8 h-full flex items-center justify-center">
      <div className="flex flex-col items-center gap-3">
        <div className="h-10 w-10 rounded-full border-2 border-edge border-t-signal animate-spin" />
        <div className="text-[12px] font-mono text-mist-300">
          aggregating intelligence…
        </div>
      </div>
    </div>
  );
}

function Results({ data, tone }) {
  const services = data.services || [];
  const vulns = data.vulnerabilities || [];
  const ai = data.ai || {};
  const ti = data.threat_intel || {};
  const active = data.active_checks || {};

  return (
    <div className="space-y-5">
      <div className="panel p-5 flex flex-col md:flex-row md:items-center gap-6">
        <RiskGauge score={data.risk?.cvss_max} level={data.risk?.level || "Unknown"} />
        <div className="flex-1 min-w-0">
          <div className="text-[11px] uppercase tracking-[0.14em] text-mist-300">
            Target
          </div>
          <div className="font-mono text-[15px] text-mist-100 mt-1 break-all">
            {data.target?.value}
          </div>
          <div className="text-[12px] text-mist-300 mt-0.5">
            {data.target?.resolved_ip && (
              <span className="font-mono">{data.target.resolved_ip}</span>
            )}
            {data.target?.resolved_ip && " · "}
            {data.run_id}
          </div>
          <div className="flex flex-wrap gap-2 mt-3">
            <Stat label="Services" value={services.length} />
            <Stat label="CVEs" value={data.vulnerability_count} />
            <Stat
              label="Active checks"
              value={active.authorized ? "authorized" : "not authorized"}
            />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Panel title="Discovered services" count={services.length}>
          {services.length ? (
            <table className="w-full text-[12px]">
              <thead>
                <tr className="text-mist-300 text-left">
                  <th className="font-500 pb-1.5 pr-2">Port</th>
                  <th className="font-500 pb-1.5 pr-2">Service</th>
                  <th className="font-500 pb-1.5">Version</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {services.map((s, i) => (
                  <tr key={i} className="border-t border-edge/50">
                    <td className="py-1.5 pr-2 text-mist-100">{s.port}</td>
                    <td className="py-1.5 pr-2 text-mist-200">{s.service}</td>
                    <td className="py-1.5 text-mist-300">{s.version || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty text="No services discovered from Shodan data." />
          )}
        </Panel>

        <Panel title="Top CVEs" count={vulns.length}>
          {vulns.length ? (
            <ul className="space-y-2.5">
              {vulns.map((v, i) => {
                const cve = v.cve_id || v.id || "UNKNOWN";
                const score = v.score ?? v.cvss_score;
                const ewrs = v.risk?.ewrs;
                const exploited = v.risk?.known_exploited;
                return (
                  <li key={i} className="text-[12px] border-b border-edge/40 pb-2 last:border-0 last:pb-0">
                    <div className="flex items-center flex-wrap gap-x-2 gap-y-1">
                      <a
                        href={v.url || `https://nvd.nist.gov/vuln/detail/${cve}`}
                        target="_blank"
                        rel="noreferrer"
                        className="font-mono text-signal hover:underline underline-offset-2"
                      >
                        {cve}
                      </a>
                      {exploited && (
                        <span className="text-[9px] uppercase tracking-wide px-1.5 py-0.5 rounded border bg-alert-crit/15 text-alert-crit border-alert-crit/30 font-600">
                          actively exploited
                        </span>
                      )}
                      <span className={tone(v.severity)}>
                        {v.severity || "Unknown"}
                        {typeof score === "number" ? ` · CVSS ${score.toFixed(1)}` : ""}
                      </span>
                      {typeof ewrs === "number" && (
                        <span className="font-mono text-[11px] text-mist-100 bg-ink-600/60 border border-edge rounded px-1.5 py-0.5">
                          EWRS {ewrs.toFixed(1)}
                        </span>
                      )}
                      {v.port && (
                        <span className="text-mist-300 font-mono">
                          :{v.port} {v.service}
                        </span>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          ) : (
            <Empty text="No CVEs mapped from NVD for the discovered services." />
          )}
        </Panel>
      </div>

      <Panel title="AI assessment & remediation">
        {ai.severity && (
          <div className="text-[12px] mb-2">
            <span className="text-mist-300">Severity: </span>
            <span className={tone(ai.severity)}>{ai.severity}</span>
          </div>
        )}
        {ai.strategy && (
          <p className="text-[13px] text-mist-200 leading-relaxed mb-3">
            {ai.strategy}
          </p>
        )}
        {ai.remediation?.length > 0 && (
          <ul className="space-y-1.5">
            {ai.remediation.map((r, i) => (
              <li key={i} className="text-[12px] text-mist-200 flex gap-2">
                <span className="text-signal mt-0.5">→</span>
                <span>{r}</span>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {(ti.public_feeds?.length > 0 || ti.darkweb?.length > 0) && (
        <Panel title="Threat intelligence">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-[12px]">
            {ti.public_feeds?.length > 0 && (
              <div>
                <div className="text-signal font-500 mb-1.5">Public feeds</div>
                <ul className="space-y-1 font-mono text-mist-200">
                  {ti.public_feeds.slice(0, 5).map((f, i) => (
                    <li key={i}>{f.indicator || f.ip || f.domain}</li>
                  ))}
                </ul>
              </div>
            )}
            {ti.darkweb?.length > 0 && (
              <div>
                <div className="text-alert-high font-500 mb-1.5">Dark-web indicators</div>
                <ul className="space-y-1 font-mono text-mist-200">
                  {ti.darkweb.slice(0, 5).map((f, i) => (
                    <li key={i}>{f.indicator || f.ip || f.domain}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </Panel>
      )}

      {data.simulation_used && (
        <div className="rounded-lg border border-alert-med/40 bg-alert-med/10 p-3 text-[12px] text-alert-med" role="status">
          Demo data used. Sample indicators and fallback addresses are not verified evidence for this target.
        </div>
      )}
      <div className="text-[11px] text-mist-300 font-mono">
        sources: {(data.sources || []).join(", ") || "none"}
        {Object.entries(data.source_provenance || {}).map(([key, description]) => (
          <div key={key}>{key}: {description}</div>
        ))}
      </div>
    </div>
  );
}

function Panel({ title, count, children }) {
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-display font-600 text-[13px] text-mist-100">{title}</h3>
        {count !== undefined && (
          <span className="text-[11px] font-mono text-mist-300">{count}</span>
        )}
      </div>
      {children}
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div className="rounded-lg bg-ink-600/60 border border-edge px-3 py-1.5">
      <span className="text-[10px] uppercase tracking-wide text-mist-300">{label} </span>
      <span className="text-[12px] font-mono text-mist-100">{value}</span>
    </div>
  );
}

function Empty({ text }) {
  return <div className="text-[12px] text-mist-300">{text}</div>;
}

export default Scan;
