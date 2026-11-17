import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api.js";
import { describeChange, plural, shortRelease, when } from "../lib/format.js";
import { useTeam } from "../lib/Team.jsx";
import { Empty, Pills, Problem, Severity, Verdict, useAction, useLoad } from "../components/ui.jsx";

const WEEK = 7 * 24 * 3600 * 1000;
const TESTS = {
  all: () => true,
  deviation: (s) => s.scan && s.scan.verdict === "deviation",
  open: (s) => s.scan && s.scan.outcome === "read",
  cases: (s) => s.open_cases > 0,
  changed: (s) => s.last_change && Date.now() - new Date(s.last_change.at).getTime() < WEEK,
  unread: (s) => !s.scan || s.scan.outcome !== "read",
};
const LABELS = [["all", "All"], ["deviation", "Deviation"], ["open", "No authentication"], ["cases", "Open cases"],
  ["changed", "Changed in 7 days"], ["unread", "Not read"]];

function AddServer({ onAdded, onCancel }) {
  const [endpoint, setEndpoint] = useState("");
  const [label, setLabel] = useState("");
  const action = useAction();
  const submit = async (event) => {
    event.preventDefault();
    const created = await action.run(() => api.post("/api/assets", { kind: "mcp", value: endpoint.trim(), label: label.trim() }));
    if (created) onAdded(created);
  };
  return (
    <form className="card" onSubmit={submit}>
      <div className="row">
        <label className="stack tight grow">Endpoint
          <input className="input mono" autoFocus placeholder="host:port" value={endpoint} onChange={(event) => setEndpoint(event.target.value)} />
        </label>
        <label className="stack tight grow">Name
          <input className="input" placeholder="Optional" value={label} onChange={(event) => setLabel(event.target.value)} />
        </label>
      </div>
      <div className="row">
        <button className="btn primary" type="submit" disabled={action.busy || !endpoint.trim()}
          title="Only targets inside the authorized scope are scanned.">Add</button>
        <button className="btn" type="button" onClick={onCancel}>Cancel</button>
      </div>
      <Problem error={action.error} />
    </form>
  );
}

export default function Inventory() {
  const { data, error, loading, reload } = useLoad(() => api.get("/api/inventory"), []);
  const { can } = useTeam();
  const navigate = useNavigate();
  const [filter, setFilter] = useState("all");
  const [text, setText] = useState("");
  const [adding, setAdding] = useState(false);

  const servers = data ? data.servers : [];
  const needle = text.trim().toLowerCase();
  const rows = servers.filter(TESTS[filter]).filter((s) => !needle
    || `${s.label} ${s.endpoint} ${s.scan ? s.scan.release || "" : ""}`.toLowerCase().includes(needle))
    .sort((a, b) => Number(TESTS.deviation(b)) - Number(TESTS.deviation(a)) || b.open_cases - a.open_cases || a.label.localeCompare(b.label));

  return (
    <main className="page">
      <div className="row">
        <h1 className="grow">Inventory</h1>
        <input className="input" type="search" aria-label="Filter servers" style={{ minWidth: 280 }}
          placeholder="Filter by name, endpoint or package" value={text} onChange={(event) => setText(event.target.value)} />
        {can("work") && <button className="btn primary" type="button" onClick={() => setAdding(!adding)}>Add server</button>}
      </div>
      {adding && <AddServer onCancel={() => setAdding(false)} onAdded={(created) => { setAdding(false); navigate(`/servers/${created.id}`); }} />}
      <Pills label="Quick filters" value={filter} onChange={setFilter}
        options={LABELS.map(([id, label]) => ({ id, label, count: servers.filter(TESTS[id]).length }))} />
      <Problem error={error} />
      <div className="panel scroll">
        <table className="grid" style={{ minWidth: 1180 }}>
          <thead>
            <tr><th>Server</th><th>Provenance</th><th className="num">Tools</th><th className="num">Flagged</th>
              <th>Severity</th><th className="num">Open cases</th><th>Last change</th><th>Last scan</th></tr>
          </thead>
          <tbody>
            {rows.map((s) => {
              const read = s.scan && s.scan.outcome === "read";
              return (
                <tr key={s.id} className={`click${TESTS.deviation(s) ? " alarm" : ""}`} onClick={() => navigate(`/servers/${s.id}`)}>
                  <td><button type="button" className="link" style={{ fontWeight: 600, color: "var(--text)" }}>{s.label}</button> <span className="mono small muted">{s.endpoint !== s.label ? s.endpoint : ""}</span></td>
                  <td><Verdict scan={s.scan} /> <span className="mono small muted">{read ? shortRelease(s.scan.release) : ""}</span></td>
                  <td className="num mono">{read ? s.scan.tool_count : "—"}</td>
                  <td className="num mono">{read ? s.flagged_tools : "—"}</td>
                  <td><Severity level={read ? s.scan.severity : null} /></td>
                  <td className="num mono">{s.open_cases || "—"}</td>
                  <td className="muted">{s.last_change ? `${when(s.last_change.at)} · ${describeChange(s.last_change)}` : (read ? "No change recorded" : "—")}</td>
                  <td className="mono">{s.scan ? when(s.scan.started_at) : "Never"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!loading && !servers.length && <Empty title="No servers yet">Add an MCP server by its endpoint, then run a scan. A scan reads the handshake and the tool list only.</Empty>}
        {!loading && servers.length > 0 && !rows.length && <Empty title="Nothing matches">No server matches this filter.</Empty>}
      </div>
      <p className="note" title="A scan reads the handshake and the tool list only; no tool is called.">{rows.length} of {plural(servers.length, "server")}</p>
    </main>
  );
}
