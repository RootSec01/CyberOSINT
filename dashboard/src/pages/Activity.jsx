import { useState } from "react";
import { api } from "../lib/api.js";
import { ACTIONS, actionLabel, plural, when, windowParams } from "../lib/format.js";
import { useTeam } from "../lib/Team.jsx";
import When, { ANY_TIME } from "../components/When.jsx";
import { Empty, Problem, useLoad } from "../components/ui.jsx";

const readable = (detail) => (detail || "").split(";").filter(Boolean).map((part) => part.replace("=", ": ")).join(" · ");

export default function Activity() {
  const { members, nameOf, me } = useTeam();
  const [filters, setFilters] = useState({ operator: "", action: "", q: "" });
  const [period, setPeriod] = useState(ANY_TIME);
  const query = { ...filters, ...windowParams(period), limit: 200 };
  const { data, error, loading } = useLoad(() => api.get("/api/audit", query), [JSON.stringify(query)]);
  const set = (patch) => setFilters({ ...filters, ...patch });
  const rows = data ? data.entries : [];

  return (
    <main className="page">
      <h1>Activity</h1>
      <div className="panel filters">
        <label>Search<input className="input" type="search" placeholder="Reference or detail" value={filters.q} onChange={(event) => set({ q: event.target.value })} /></label>
        <label>Person
          <select className="input" value={filters.operator} onChange={(event) => set({ operator: event.target.value })}>
            <option value="">Anyone</option>{members.map((m) => <option key={m.id} value={m.username}>{m.display_name}</option>)}
          </select></label>
        <label>Action
          <select className="input" value={filters.action} onChange={(event) => set({ action: event.target.value })}>
            <option value="">Any action</option>{Object.entries(ACTIONS).map(([id, label]) => <option key={id} value={id}>{label}</option>)}
          </select></label>
        <When value={period} onChange={setPeriod} />
      </div>
      <Problem error={error} />
      <div className="panel scroll">
        <table className="grid" style={{ minWidth: 900 }}>
          <thead><tr><th>Time</th><th>Person</th><th>Action</th><th>Detail</th><th>Result</th></tr></thead>
          <tbody>
            {rows.map((entry, index) => (
              <tr key={entry.ts + index}><td className="mono">{when(entry.ts)}</td><td>{nameOf(entry.operator)}</td>
                <td style={{ fontWeight: 500 }}>{actionLabel(entry.action)}</td><td className="mono small wrap-any">{readable(entry.detail)}</td>
                <td className="muted">{(entry.decision || "").replace(/_/g, " ")}</td></tr>
            ))}
          </tbody>
        </table>
        {!loading && !rows.length && <Empty title="Nothing recorded for these filters">Every change to a finding, case, member or setting is written here with who made it.</Empty>}
      </div>
      <p className="note">{data ? `${rows.length} of ${plural(data.total, "entry").replace("entrys", "entries")}.` : ""} {me && me.role === "owner" ? "" : "You see your own actions; an administrator sees everyone's."}</p>
    </main>
  );
}
