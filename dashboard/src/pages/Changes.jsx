import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api.js";
import { plural, shortRelease, when, windowParams } from "../lib/format.js";
import When, { ANY_TIME } from "../components/When.jsx";
import { Empty, Problem, VerdictWord, useLoad } from "../components/ui.jsx";

const names = (list) => (list && list.length ? list.slice(0, 4).join(", ") + (list.length > 4 ? ` +${list.length - 4}` : "") : "");

export default function Changes() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState({ kind: "", asset_id: "", q: "" });
  const [period, setPeriod] = useState(ANY_TIME);
  const query = { ...filters, ...windowParams(period) };
  const { data, error, loading } = useLoad(() => api.get("/api/changes", query), [JSON.stringify(query)]);
  const servers = useLoad(() => api.get("/api/inventory"), []);
  const set = (patch) => setFilters({ ...filters, ...patch });
  const rows = data ? data.changes : [];

  return (
    <main className="page">
      <h1>Changes</h1>
      <div className="panel filters">
        <label>Search<input className="input" type="search" placeholder="Tool, server, SCN-" value={filters.q} onChange={(event) => set({ q: event.target.value })} /></label>
        <label>Compared with
          <select className="input" value={filters.kind} onChange={(event) => set({ kind: event.target.value })}>
            <option value="">Either</option><option value="between_scans">Previous scan</option><option value="against_release">Published release</option>
          </select></label>
        <label>Server
          <select className="input" value={filters.asset_id} onChange={(event) => set({ asset_id: event.target.value })}>
            <option value="">All servers</option>{(servers.data ? servers.data.servers : []).map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select></label>
        <When value={period} onChange={setPeriod} />
      </div>
      <Problem error={error} />
      <div className="panel scroll">
        <table className="grid" style={{ minWidth: 1180 }}>
          <thead><tr><th>Time</th><th>Server</th><th>Compared with</th><th className="num">Added</th><th className="num">Removed</th><th className="num">Redefined</th><th>Tools</th><th>Provenance after</th><th>Scan</th></tr></thead>
          <tbody>
            {rows.map((c) => {
              const release = c.kind === "against_release";
              return (
                <tr key={c.scan + c.kind} className={`click${release ? " alarm" : ""}`} onClick={() => navigate(`/servers/${c.asset_id}/${release ? "tools" : "scans"}`)}>
                  <td className="mono">{when(c.at)}</td><td><button type="button" className="link" style={{ fontWeight: 600, color: "var(--text)" }}>{c.asset}</button></td>
                  <td>{release ? "Published release" : "Previous scan"} <span className="mono small muted">{release ? shortRelease(c.release) : c.previous_scan}</span></td>
                  <td className="num mono">{c.added ? c.added.length : "—"}</td><td className="num mono">{c.removed ? c.removed.length : "—"}</td>
                  <td className="num mono">{c.redefined ? c.redefined.length : "—"}</td>
                  <td className="mono small muted wrap-any">{[names(c.redefined), names(c.added), names(c.removed)].filter(Boolean).join(" · ") || (release ? "See the Tools tab" : "")}</td>
                  <td><VerdictWord verdict={c.verdict} /> <span className="mono small muted">{shortRelease(c.release)}</span></td>
                  <td className="ref">{c.scan}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!loading && !rows.length && <Empty title="No changes recorded">A change is recorded when a scan reads different declarations than the scan before it, or when a first scan differs from the published release.</Empty>}
      </div>
      <p className="note">{data ? plural(data.total, "change") : ""}</p>
    </main>
  );
}
