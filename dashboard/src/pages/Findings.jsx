import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../lib/api.js";
import { FINDING_STATUS, plural, when, windowParams } from "../lib/format.js";
import { useTeam } from "../lib/Team.jsx";
import When, { ANY_TIME } from "../components/When.jsx";
import { Empty, Problem, Severity, Status, useAction, useLoad } from "../components/ui.jsx";

function Detail({ finding, onChanged }) {
  const { can, nameOf } = useTeam();
  const navigate = useNavigate();
  const [note, setNote] = useState("");
  const action = useAction();
  useEffect(() => { setNote(""); action.clear(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [finding.reference]);

  const setStatus = async (status) => {
    if (await action.run(() => api.post(`/api/findings/${finding.reference}/status`, { status, note }))) { setNote(""); onChanged(); }
  };
  const openCase = async () => {
    const created = await action.run(() => api.post("/api/cases", { finding: finding.reference, note }));
    if (created) navigate(`/cases/${created.reference}`);
  };
  const resolved = finding.status === "resolved";
  const meta = [["Server", <Link to={`/servers/${finding.asset_id}`}>{finding.asset}</Link>], ["Tool", finding.tool || "server"],
    ["First seen", `${when(finding.first_seen_at)} · ${finding.first_scan}`], ["Last seen", `${when(finding.last_seen_at)} · ${finding.last_scan}`],
    ["Evidence", finding.evidence_level], ["Verification", finding.verification_status || "—"],
    ["OWASP MCP", (finding.owasp_mcp || "—").split(":")[0]], ["MITRE", finding.technique_id || "—"],
    ["Status set by", `${nameOf(finding.status_by)} · ${when(finding.status_at)}`],
    ["Confidence", finding.confidence != null ? `${Math.round(finding.confidence * 100)}%` : "—"]];

  return (
    <section className="card selected" aria-label="Selected finding">
      <div className="row">
        <span className="ref">{finding.reference}</span><Severity level={finding.severity} />
        <h2 className="grow" style={{ fontSize: 16 }}>{finding.title}</h2>
        <Status value={finding.status} labels={FINDING_STATUS} badge />
      </div>
      <dl className="metas">{meta.map(([name, value]) => <div key={name}><dt>{name}</dt><dd className="mono">{value}</dd></div>)}</dl>
      {finding.status_note && <p><span className="muted">Status note: </span>{finding.status_note}</p>}
      <div className="stack tight"><span className="small muted">Observed</span>{finding.observed_facts.map((fact) => <span key={fact}>{fact}</span>)}</div>
      <span className="muted">{finding.inference}</span>
      <span style={{ color: "var(--brand)" }}>{finding.recommendation}</span>
      {can("work") && !resolved && (
        <>
          <label className="stack tight small muted">Reason (needed to accept a risk or to open a case)
            <input className="input" style={{ color: "var(--text)" }} value={note} onChange={(event) => setNote(event.target.value)} />
          </label>
          <div className="row">
            {finding.status !== "acknowledged" && <button type="button" className="btn" disabled={action.busy} onClick={() => setStatus("acknowledged")}>Acknowledge</button>}
            {finding.status !== "risk_accepted" && <button type="button" className="btn" disabled={action.busy} onClick={() => setStatus("risk_accepted")}>Accept risk</button>}
            {finding.status !== "open" && <button type="button" className="btn" disabled={action.busy} onClick={() => setStatus("open")}>Reopen</button>}
            {finding.case ? <Link className="btn primary" style={{ display: "flex", alignItems: "center" }} to={`/cases/${finding.case}`}>Open {finding.case}</Link>
              : <button type="button" className="btn primary" disabled={action.busy} onClick={openCase}>Open a case</button>}
          </div>
        </>
      )}
      {resolved && <p className="note">Resolved by a scan that no longer sees it. It reopens by itself if a later scan sees it again.</p>}
      {!resolved && finding.case && !can("work") && <Link className="ref" to={`/cases/${finding.case}`}>{finding.case}</Link>}
      <Problem error={action.error} />
    </section>
  );
}

export default function Findings() {
  const [params, setParams] = useSearchParams();
  const { members } = useTeam();
  const [filters, setFilters] = useState({ severity: "", status: "open", evidence: "", asset_id: params.get("server") || "", changed_by: "", q: "", seen: "first" });
  const [period, setPeriod] = useState(ANY_TIME);
  const picked = params.get("ref");
  const query = { ...filters, ...windowParams(period), status: picked ? "" : filters.status };
  const { data, error, loading, reload } = useLoad(() => api.get("/api/findings", query), [JSON.stringify(query)]);
  const servers = useLoad(() => api.get("/api/inventory"), []);
  const chosen = useLoad(() => (picked ? api.get(`/api/findings/${picked}`) : Promise.resolve(null)), [picked]);
  const set = (patch) => setFilters({ ...filters, ...patch });
  const pick = (reference) => setParams(reference ? { ref: reference } : {});
  const rows = data ? data.findings : [];

  return (
    <main className="page">
      <h1>Findings</h1>
      <div className="panel filters">
        <label>Search<input className="input" type="search" placeholder="Title, tool, FND-" value={filters.q} onChange={(event) => set({ q: event.target.value })} /></label>
        <label>Status
          <select className="input" value={filters.status} onChange={(event) => set({ status: event.target.value })}>
            <option value="">Any</option>{Object.entries(FINDING_STATUS).map(([id, label]) => <option key={id} value={id}>{label}</option>)}
          </select></label>
        <label>Severity
          <select className="input" value={filters.severity} onChange={(event) => set({ severity: event.target.value })}>
            <option value="">Any</option>{["Critical", "High", "Medium", "Low"].map((level) => <option key={level}>{level}</option>)}
          </select></label>
        <label>Evidence
          <select className="input" value={filters.evidence} onChange={(event) => set({ evidence: event.target.value })}>
            <option value="">Any</option><option value="OBSERVED">Observed</option><option value="INFERRED">Inferred</option><option value="DEMONSTRATED">Demonstrated</option>
          </select></label>
        <label>Server
          <select className="input" value={filters.asset_id} onChange={(event) => set({ asset_id: event.target.value })}>
            <option value="">All servers</option>{(servers.data ? servers.data.servers : []).map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select></label>
        <label>Status set by
          <select className="input" value={filters.changed_by} onChange={(event) => set({ changed_by: event.target.value })}>
            <option value="">Anyone</option><option value="raqeeb">Raqeeb</option>{members.map((m) => <option key={m.id} value={m.username}>{m.display_name}</option>)}
          </select></label>
        <label>Date applies to
          <select className="input" value={filters.seen} onChange={(event) => set({ seen: event.target.value })}>
            <option value="first">First seen</option><option value="last">Last seen</option><option value="status">Status change</option>
          </select></label>
        <When value={period} onChange={setPeriod} />
        {picked && <button type="button" className="btn" onClick={() => pick(null)}>Clear selection</button>}
      </div>
      {chosen.data && <Detail finding={chosen.data} onChanged={() => { chosen.reload(); reload(); }} />}
      <Problem error={error || chosen.error} />
      <div className="panel scroll">
        <table className="grid" style={{ minWidth: 1240 }}>
          <thead><tr><th>Finding</th><th>Severity</th><th>Title</th><th>Server</th><th>Tool</th><th>Evidence</th><th>Status</th><th>First seen</th><th>Case</th></tr></thead>
          <tbody>
            {rows.map((f) => (
              <tr key={f.reference} className={`click${f.reference === picked ? " picked" : ""}`} onClick={() => pick(f.reference)}>
                <td><button type="button" className="link ref">{f.reference}</button></td><td><Severity level={f.severity} /></td><td>{f.title}</td>
                <td style={{ fontWeight: 500 }}>{f.asset}</td><td className="mono wrap-any">{f.tool || "server"}</td>
                <td className="mono small">{f.evidence_level}</td><td><Status value={f.status} labels={FINDING_STATUS} /></td>
                <td className="mono">{when(f.first_seen_at)}</td><td className="mono muted">{f.case || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!loading && !rows.length && <Empty title="No findings match">Change the filters, or scan a server to record its findings.</Empty>}
      </div>
      <p className="note">{data ? `${rows.length} of ${plural(data.total, "finding")}.` : ""} Select a row to read its evidence and change its status.</p>
    </main>
  );
}
