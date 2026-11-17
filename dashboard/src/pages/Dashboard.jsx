import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../lib/api.js";
import { CASE_STATUS, actionLabel, describeChange, when } from "../lib/format.js";
import { useTeam } from "../lib/Team.jsx";
import { Empty, Problem, Severity, Status, Verdict, useAction, useLoad } from "../components/ui.jsx";

const SEVERITIES = ["Critical", "High", "Medium", "Low"];

function Tile({ to, label, value, sub, tone }) {
  return (
    <Link className="card tile" to={to}>
      <span className="small muted">{label}</span>
      <strong className={`big${tone ? ` tone-${tone}` : ""}`}>{value}</strong>
      <span className="small muted">{sub}</span>
    </Link>
  );
}

function Briefing() {
  const [brief, setBrief] = useState(null);
  const action = useAction();
  const write = async () => {
    const result = await action.run(() => api.post("/api/overview/briefing"));
    if (result) setBrief(result);
  };
  return (
    <section className="card" aria-label="Briefing"
      title="Composed from the rows already in the database. Nothing leaves the platform.">
      <div className="row">
        <h2 className="grow">Copilot briefing</h2>
        <button type="button" className="btn" disabled={action.busy} onClick={write}>
          {brief ? "Write again" : "Write a briefing"}
        </button>
      </div>
      {brief && <p style={{ whiteSpace: "pre-wrap", margin: 0 }}>{brief.text}</p>}
      {!brief && <span className="muted">A written summary of servers, findings, cases and changes, with the next steps.</span>}
      <Problem error={action.error} />
    </section>
  );
}

export default function Dashboard() {
  const { data, error, reload } = useLoad(() => api.get("/api/overview"), []);
  const { nameOf } = useTeam();
  const navigate = useNavigate();
  useEffect(() => {
    const timer = setInterval(() => { if (!document.hidden) reload(); }, 8000);
    return () => clearInterval(timer);
  }, [reload]);

  if (error) return <main className="page"><Problem error={error} /></main>;
  if (!data) return <main className="page" />;
  const { servers, findings, cases: open, changes } = data;
  const severityLine = SEVERITIES.map((level) => (findings.by_severity[level] ? `${findings.by_severity[level]} ${level}` : null))
    .filter(Boolean).join(" · ");

  return (
    <main className="page">
      <div className="row">
        <h1 className="grow">Dashboard</h1>
        <span className="row small muted" title="Refreshes every few seconds from the live database.">
          <i className="dot" />Live · updated {new Date(data.generated_at + "Z").toLocaleTimeString()}
        </span>
      </div>

      <div className="tiles">
        <Tile to="/inventory" label="Servers" value={servers.total}
          sub={`${servers.read} read · ${servers.total - servers.read} not read`} />
        <Tile to="/inventory" label="Deviations" value={servers.deviation} tone={servers.deviation ? "bad" : "ok"}
          sub={servers.deviation ? data.deviating.join(", ") : "All read servers match a release"} />
        <Tile to="/findings" label="Open findings" value={findings.open} tone={findings.by_severity.Critical ? "crit" : undefined}
          sub={severityLine || "Nothing open"} />
        <Tile to="/cases" label="Open cases" value={open.open}
          sub={open.unassigned ? `${open.unassigned} unassigned` : "All assigned"} />
        <Tile to="/changes" label="Changes, 7 days" value={changes.week}
          sub={`${servers.tools} tools declared · ${servers.flagged} flagged`} />
        <Tile to="/activity" label="Last scan" value={data.last_scan ? when(data.last_scan).split(",")[0] : "Never"}
          sub={data.last_scan ? when(data.last_scan) : "Run a scan from Inventory"} />
      </div>

      <div className="duo">
        <section className="stack tight" aria-label="Servers by risk">
          <h2>Servers by risk</h2>
          <div className="panel scroll">
            <table className="grid">
              <thead><tr><th>Server</th><th>Provenance</th><th>Severity</th><th className="num">Flagged</th>
                <th className="num">Cases</th><th>Last scan</th></tr></thead>
              <tbody>
                {data.risky.map((s) => (
                  <tr key={s.id} className="click" onClick={() => navigate(`/servers/${s.id}`)}>
                    <td style={{ fontWeight: 600 }}>{s.label}</td>
                    <td><Verdict scan={s.scan} /></td>
                    <td><Severity level={s.scan.severity} /></td>
                    <td className="num mono">{s.flagged_tools || "—"}</td>
                    <td className="num mono">{s.open_cases || "—"}</td>
                    <td className="mono">{when(s.scan.started_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!data.risky.length && <Empty title="Nothing read yet">Add a server in Inventory and run a scan.</Empty>}
          </div>
        </section>

        <div className="stack" style={{ gap: 16 }}>
          <Briefing />
          <section className="stack tight" aria-label="Open cases">
            <h2>Open cases</h2>
            <div className="panel scroll">
              <table className="grid"><tbody>
                {open.latest.map((c) => (
                  <tr key={c.reference} className="click" onClick={() => navigate(`/cases/${c.reference}`)}>
                    <td><span className="ref">{c.reference}</span></td>
                    <td style={{ fontWeight: 600 }}>{c.title}</td>
                    <td><Severity level={c.severity} /></td>
                    <td><Status value={c.status} labels={CASE_STATUS} /></td>
                    <td className="muted">{c.owner_name || "Unassigned"}</td>
                  </tr>
                ))}
              </tbody></table>
              {!open.latest.length && <Empty title="No open cases">Raqeeb opens a case when a rule in Settings matches a scan.</Empty>}
            </div>
          </section>
        </div>
      </div>

      <div className="duo">
        <section className="stack tight" aria-label="Latest changes">
          <h2>Latest changes</h2>
          <div className="panel scroll">
            <table className="grid"><tbody>
              {changes.latest.map((c) => (
                <tr key={c.scan + c.kind} className="click"
                  onClick={() => navigate(`/servers/${c.asset_id}/${c.kind === "against_release" ? "tools" : "scans"}`)}>
                  <td className="mono">{when(c.at)}</td>
                  <td style={{ fontWeight: 600 }}>{c.asset}</td>
                  <td className="muted">{c.kind === "against_release" ? "Against the published release" : "Between scans"}</td>
                  <td>{describeChange(c)}</td>
                  <td><span className="ref">{c.scan}</span></td>
                </tr>
              ))}
            </tbody></table>
            {!changes.latest.length && <Empty title="No changes recorded">Changes appear when a scan reads different declarations.</Empty>}
          </div>
        </section>

        <section className="stack tight" aria-label="Latest activity">
          <h2>Latest activity</h2>
          <div className="panel scroll">
            <table className="grid"><tbody>
              {data.activity.map((entry, index) => (
                <tr key={entry.ts + index}>
                  <td className="mono">{when(entry.ts)}</td>
                  <td>{nameOf(entry.operator)}</td>
                  <td style={{ fontWeight: 500 }}>{actionLabel(entry.action)}</td>
                  <td className="muted">{(entry.decision || "").replace(/_/g, " ")}</td>
                </tr>
              ))}
            </tbody></table>
            {!data.activity.length && <Empty title="Nothing recorded yet">Every action lands here, sealed in the audit chain.</Empty>}
          </div>
          <Link to="/activity">All activity</Link>
        </section>
      </div>
    </main>
  );
}
