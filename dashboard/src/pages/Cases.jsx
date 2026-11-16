import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api.js";
import { CASE_STATUS, CLOSURES, RULES, plural, when, windowParams } from "../lib/format.js";
import { useTeam } from "../lib/Team.jsx";
import When, { ANY_TIME } from "../components/When.jsx";
import { Empty, Problem, Severity, Status, useLoad } from "../components/ui.jsx";

export default function Cases() {
  const navigate = useNavigate();
  const { members, nameOf } = useTeam();
  const [filters, setFilters] = useState({ status: "", severity: "", rule: "", owner: "", opened_by: "", closure: "", q: "", seen: "opened" });
  const [period, setPeriod] = useState(ANY_TIME);
  const query = { ...filters, ...windowParams(period) };
  const { data, error, loading } = useLoad(() => api.get("/api/cases", query), [JSON.stringify(query)]);
  const set = (patch) => setFilters({ ...filters, ...patch });
  const rows = data ? data.cases : [];

  return (
    <main className="page">
      <h1>Cases</h1>
      <div className="panel filters">
        <label>Search<input className="input" type="search" placeholder="Title, server, CASE-" value={filters.q} onChange={(event) => set({ q: event.target.value })} /></label>
        <label>Status
          <select className="input" value={filters.status} onChange={(event) => set({ status: event.target.value })}>
            <option value="">Any</option>{Object.entries(CASE_STATUS).map(([id, label]) => <option key={id} value={id}>{label}</option>)}
          </select></label>
        <label>Severity
          <select className="input" value={filters.severity} onChange={(event) => set({ severity: event.target.value })}>
            <option value="">Any</option>{["Critical", "High", "Medium", "Low"].map((level) => <option key={level}>{level}</option>)}
          </select></label>
        <label>Opened because
          <select className="input" value={filters.rule} onChange={(event) => set({ rule: event.target.value })}>
            <option value="">Any reason</option>{Object.entries(RULES).map(([id, label]) => <option key={id} value={id}>{label}</option>)}
          </select></label>
        <label>Owner
          <select className="input" value={filters.owner} onChange={(event) => set({ owner: event.target.value })}>
            <option value="">Anyone</option><option value="none">Unassigned</option>{members.map((m) => <option key={m.id} value={m.username}>{m.display_name}</option>)}
          </select></label>
        <label>Opened by
          <select className="input" value={filters.opened_by} onChange={(event) => set({ opened_by: event.target.value })}>
            <option value="">Anyone</option><option value="raqeeb">Raqeeb</option>{members.map((m) => <option key={m.id} value={m.username}>{m.display_name}</option>)}
          </select></label>
        <label>Closed as
          <select className="input" value={filters.closure} onChange={(event) => set({ closure: event.target.value })}>
            <option value="">Any</option>{Object.entries(CLOSURES).map(([id, label]) => <option key={id} value={id}>{label}</option>)}
          </select></label>
        <label>Date applies to
          <select className="input" value={filters.seen} onChange={(event) => set({ seen: event.target.value })}>
            <option value="opened">Opened</option><option value="closed">Closed</option>
          </select></label>
        <When value={period} onChange={setPeriod} />
      </div>
      <Problem error={error} />
      <div className="panel scroll">
        <table className="grid" style={{ minWidth: 1180 }}>
          <thead><tr><th>Case</th><th>Title</th><th>Server</th><th>Severity</th><th>Status</th><th>Owner</th><th>Opened by</th><th>Opened</th><th className="num">Findings</th></tr></thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.reference} className="click" onClick={() => navigate(`/cases/${c.reference}`)}>
                <td><button type="button" className="link ref">{c.reference}</button></td><td style={{ fontWeight: 600 }}>{c.title}</td><td>{c.asset}</td>
                <td><Severity level={c.severity} /></td><td><Status value={c.status} labels={CASE_STATUS} /></td>
                <td>{c.owner_name || <span className="muted">Unassigned</span>}</td><td>{nameOf(c.opened_by)}</td>
                <td className="mono">{when(c.opened_at)}</td><td className="num mono">{c.finding_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!loading && !rows.length && <Empty title="No cases match">Raqeeb opens a case when declared tools differ from a published release, or when a command execution tool is listed without authentication. Any finding can also be turned into a case.</Empty>}
      </div>
      <p className="note">{data ? `${rows.length} of ${plural(data.total, "case")}.` : ""}</p>
    </main>
  );
}
