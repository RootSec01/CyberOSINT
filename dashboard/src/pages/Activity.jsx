import { useState } from "react";
import { api } from "../lib/api.js";
import { ACTIONS, actionLabel, plural, when, windowParams } from "../lib/format.js";
import { useTeam } from "../lib/Team.jsx";
import When, { ANY_TIME } from "../components/When.jsx";
import { Empty, Problem, useLoad } from "../components/ui.jsx";

const readable = (detail) => (detail || "").split(";").filter((part) => part && !/^(ip|agent)=/.test(part))
  .map((part) => part.replace("=", ": ")).join(" · ");
const agentOf = (detail) => ((detail || "").split(";").find((part) => part.startsWith("agent=")) || "").slice(6);

const SIGN_INS = [
  ["signed_in", "Sign-ins", ""],
  ["sign_in_failed", "Refused", "crit"],
  ["sign_in_blocked", "Blocked", "crit"],
  ["visitor_entered", "Visitors", ""],
];

function Doorway({ onPick }) {
  const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const { data } = useLoad(() => Promise.all(SIGN_INS.map(([action]) => api.get("/api/audit", { action, since, limit: 1 }))), []);
  return (
    <div className="panel" style={{ padding: "16px 20px" }}>
      <p className="muted small" style={{ marginTop: 0 }}>Sign-in attempts on this installation, last 24 hours</p>
      <div style={{ display: "flex", gap: 28, flexWrap: "wrap" }}>
        {SIGN_INS.map(([action, label, tone], index) => {
          const count = data ? data[index].total : null;
          return (
            <button key={action} type="button" className="link" style={{ textAlign: "left" }} onClick={() => onPick(action)}>
              <span style={{ display: "block", fontSize: 26, fontWeight: 600, color: tone && count ? "var(--crit)" : undefined }}>{count ?? "–"}</span>
              <span className="muted small">{label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function DemoVisitors() {
  const { data } = useLoad(() => api.get("/api/showcase/visits", { hours: 24 }), []);
  if (!data || !data.available) return null;
  return (
    <div className="panel" style={{ padding: "16px 20px" }}>
      <p className="muted small" style={{ marginTop: 0 }}>
        Demo visitors, last 24 hours: <strong>{data.total}</strong> {data.total === 1 ? "visit" : "visits"} from <strong>{data.addresses}</strong> {data.addresses === 1 ? "address" : "addresses"}
      </p>
      {data.visits.length > 0 && (
        <div className="scroll" style={{ maxHeight: 260 }}>
          <table className="grid">
            <thead><tr><th>Time</th><th>Address</th><th>Browser</th></tr></thead>
            <tbody>
              {data.visits.map((visit, index) => (
                <tr key={visit.ts + index}><td className="mono">{when(visit.ts)}</td><td className="mono">{visit.ip}</td><td className="small muted wrap-any">{visit.agent}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

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
      {me && me.platform_admin && <Doorway onPick={(action) => set({ action })} />}
      {me && me.platform_admin && <DemoVisitors />}
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
        <table className="grid" style={{ minWidth: 1000 }}>
          <thead><tr><th>Time</th><th>Person</th><th>Action</th><th>Detail</th><th>Address</th><th>Result</th></tr></thead>
          <tbody>
            {rows.map((entry, index) => (
              <tr key={entry.ts + index}><td className="mono">{when(entry.ts)}</td><td>{nameOf(entry.operator)}</td>
                <td style={{ fontWeight: 500 }}>{actionLabel(entry.action)}</td><td className="mono small wrap-any">{readable(entry.detail)}</td>
                <td className="mono small" title={agentOf(entry.detail)}>{entry.ip || ""}</td>
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
