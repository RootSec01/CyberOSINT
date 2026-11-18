import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../lib/api.js";
import { CASE_STATUS, actionLabel, describeChange, when } from "../lib/format.js";
import { useTeam } from "../lib/Team.jsx";
import { Empty, Problem, Segment, Severity, Status, Verdict, useAction, useLoad } from "../components/ui.jsx";

const SEVERITIES = [["Critical", "var(--crit)"], ["High", "var(--high)"], ["Medium", "var(--med)"], ["Low", "var(--muted)"]];
const VERDICT_PARTS = [["match", "Match", "var(--ok)"], ["subset", "Subset", "var(--info)"], ["deviation", "Deviation", "var(--crit)"],
  ["unknown", "Unknown", "var(--edge)"], ["not_read", "Not read", "var(--line-strong)"]];
const EVERY = { 1: "1 min", 5: "5 min", 15: "15 min", 60: "1 hour", 360: "6 hours", 1440: "24 hours" };
const percent = (share) => `${(share * 100).toFixed(1)}%`;

function Panel({ title, hint, extra, span, children, flush }) {
  return (
    <section className={`card dash span-${span}`} aria-label={title}>
      <div className="row dash-head">
        <h2 className="grow" title={hint}>{title}</h2>
        {extra}
      </div>
      <div className={`dash-body${flush ? " flush" : ""}`}>{children}</div>
    </section>
  );
}

function Tile({ to, label, value, sub, tone }) {
  return (
    <Link className="card tile" to={to}>
      <span className="small muted">{label}</span>
      <strong className={`big${tone ? ` tone-${tone}` : ""}`}>{value}</strong>
      <span className="small muted clip1">{sub}</span>
    </Link>
  );
}

function Stacked({ parts, label }) {
  const total = parts.reduce((sum, part) => sum + part.value, 0);
  return (
    <div className="stack tight">
      <div className="row small"><span className="grow muted">{label}</span><span className="mono">{total}</span></div>
      <div className="stackbar" role="img" aria-label={`${label}: ${parts.map((p) => `${p.value} ${p.label}`).join(", ")}`}>
        {total === 0 && <i style={{ flex: 1, background: "var(--line)" }} />}
        {parts.filter((p) => p.value).map((p) => (
          <i key={p.label} title={`${p.label}: ${p.value}`} style={{ flex: p.value, background: p.color }} />
        ))}
      </div>
      <div className="legend">
        {parts.map((p) => (
          <span key={p.label} className="small"><i style={{ background: p.color }} />{p.label} <b className="mono">{p.value}</b></span>
        ))}
      </div>
    </div>
  );
}

const DAY = (iso, opts) => new Date(`${iso}T12:00:00Z`).toLocaleDateString(undefined, opts);

function Trend({ days }) {
  const top = Math.max(1, ...days.map((d) => d.manual + d.scheduled));
  const step = top <= 4 ? 1 : Math.ceil(top / 4);
  const ticks = [];
  for (let value = 0; value <= top; value += step) ticks.push(value);
  if (ticks[ticks.length - 1] < top) ticks.push(ticks[ticks.length - 1] + step);
  const ceiling = ticks[ticks.length - 1];
  const every = Math.ceil(days.length / 7);
  const total = days.reduce((sum, d) => sum + d.manual + d.scheduled, 0);
  return (
    <div className="stack tight" style={{ height: "100%" }}>
      <div className="legend">
        <span className="small"><i style={{ background: "var(--brand)" }} />Manual scans</span>
        <span className="small"><i style={{ background: "var(--info)" }} />Scheduled scans</span>
        <span className="small muted grow" style={{ textAlign: "right" }}>{total} in {days.length} days</span>
      </div>
      <div className="chart">
        <div className="yaxis">{[...ticks].reverse().map((t) => <span key={t} className="small muted mono">{t}</span>)}</div>
        <div className="plot">
          <div className="trend" role="img" aria-label={`Scans per day over the last ${days.length} days`}>
            {ticks.map((t) => <i key={t} className="gridline" style={{ bottom: `${(t / ceiling) * 100}%` }} />)}
            {days.map((d) => (
              <div key={d.day} className="day" title={`${DAY(d.day, { weekday: "short", day: "numeric", month: "short" })}: ${d.manual} manual, ${d.scheduled} scheduled`}>
                <div className="bars">
                  {d.scheduled > 0 && <i style={{ height: `${(d.scheduled / ceiling) * 100}%`, background: "var(--info)" }} />}
                  {d.manual > 0 && <i style={{ height: `${(d.manual / ceiling) * 100}%`, background: "var(--brand)" }} />}
                </div>
              </div>
            ))}
          </div>
          <div className="xaxis">
            {days.map((d, index) => (
              <span key={d.day} className="small muted">{(days.length - 1 - index) % every === 0 ? DAY(d.day, { day: "numeric", month: "short" }) : ""}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function Bars({ rows, color = "var(--brand)" }) {
  const top = Math.max(1, ...rows.map((r) => r.value));
  return (
    <div className="stack tight">
      {rows.map((r) => (
        <div key={r.label} className="hbar" title={`${r.label}: ${r.value}`}>
          <span className="clip1">{r.label}</span>
          <span className="track"><i style={{ width: `${(r.value / top) * 100}%`, background: color }} /></span>
          <span className="mono">{r.text || r.value}</span>
        </div>
      ))}
    </div>
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
    <Panel span={4} title="Copilot briefing" hint="Written from the rows already in the database. Nothing leaves the platform."
      extra={<button type="button" className="btn" disabled={action.busy} onClick={write}>{brief ? "Write again" : "Write a briefing"}</button>}>
      {brief
        ? brief.text.split("\n").map((line, index) => <p key={index} className={index ? "" : "muted small"} style={{ margin: "0 0 6px" }}>{line}</p>)
        : <Empty title="Ask Copilot for a briefing">A written summary of servers, findings, cases and changes, with the next steps.</Empty>}
      <Problem error={action.error} />
    </Panel>
  );
}

function AlertList({ alerts, onRead }) {
  const navigate = useNavigate();
  const open = async (alert) => {
    if (!alert.acknowledged) await api.post(`/api/alerts/${alert.id}/ack`).catch(() => {});
    onRead();
    if (alert.asset_id) navigate(`/servers/${alert.asset_id}`);
  };
  if (!alerts.length) return <Empty title="No alerts">Raised when a scan sees a server change, deviate or stop answering.</Empty>;
  return alerts.map((alert) => (
    <button key={alert.id} type="button" className={`alert-row${alert.acknowledged ? "" : " unread"}`} onClick={() => open(alert)}>
      <span className={`sevdot sev-${alert.severity}`} />
      <span className="stack tight" style={{ minWidth: 0 }}>
        <span style={{ fontWeight: 600 }}>{alert.title}</span>
        <span className="small muted clip">{alert.detail}</span>
        <span className="small muted mono">{when(alert.created_at)}</span>
      </span>
    </button>
  ));
}

export default function Dashboard() {
  const [period, setPeriod] = useState(14);
  const { data, error, reload } = useLoad(() => api.get("/api/overview", { days: period }), [period]);
  const { nameOf, can } = useTeam();
  const navigate = useNavigate();
  useEffect(() => {
    const timer = setInterval(() => { if (!document.hidden) reload(); }, 8000);
    return () => clearInterval(timer);
  }, [reload]);

  if (error) return <main className="page"><Problem error={error} /></main>;
  if (!data) return <main className="page" />;
  const { servers, findings, cases: open, changes, field } = data;
  const readAll = async () => { await api.post("/api/alerts/ack-all"); reload(); };

  return (
    <main className="page">
      <div className="row">
        <h1 className="grow">Dashboard</h1>
        <span className="row small muted" title="Refreshes every few seconds from the live database.">
          <i className="dot" />Live · {when(data.generated_at).split(", ")[1]}
        </span>
      </div>

      <div className="tiles">
        <Tile to="/inventory" label="Servers" value={servers.total} sub={`${servers.read} read · ${servers.total - servers.read} not read`} />
        <Tile to="/inventory" label="Deviations" value={servers.deviation} tone={servers.deviation ? "bad" : "ok"}
          sub={servers.deviation ? data.deviating.join(", ") : "All read servers match"} />
        <Tile to="/findings" label="Open findings" value={findings.open} tone={findings.by_severity.Critical ? "crit" : undefined}
          sub={`${findings.by_severity.Critical} Critical · ${findings.by_severity.High} High`} />
        <Tile to="/cases" label="Open cases" value={open.open} sub={open.unassigned ? `${open.unassigned} unassigned` : "All assigned"} />
        <Tile to="/changes" label="Unread alerts" value={data.alerts.unread} tone={data.alerts.unread ? "high" : undefined}
          sub={data.alerts.latest[0] ? data.alerts.latest[0].title : "Nothing raised"} />
        <Tile to="/settings/monitoring" label="Monitored" value={`${data.monitoring.monitored}/${servers.total}`}
          sub={data.monitoring.enabled ? "Scheduler running" : "Scheduler off"} tone={data.monitoring.enabled ? undefined : "muted"} />
        <Tile to="/changes" label="Changes, 7 days" value={changes.week} sub={`${servers.tools} tools · ${servers.flagged} flagged`} />
        <Tile to="/activity" label="Last scan" value={data.last_scan ? new Date(data.last_scan).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "—"}
          sub={data.last_scan ? when(data.last_scan) : "Run a scan from Inventory"} />
      </div>

      <div className="dash-grid">
        <Panel span={5} title="Servers by risk" flush extra={<Link to="/inventory" className="small">Inventory</Link>}>
          <table className="grid">
            <thead><tr><th>Server</th><th>Provenance</th><th>Severity</th><th className="num">Flagged</th><th className="num">Cases</th></tr></thead>
            <tbody>
              {data.risky.map((s) => (
                <tr key={s.id} className="click" onClick={() => navigate(`/servers/${s.id}`)}>
                  <td style={{ fontWeight: 600 }}>{s.label}</td>
                  <td><Verdict scan={s.scan} /></td>
                  <td><Severity level={s.scan.severity} /></td>
                  <td className="num mono">{s.flagged_tools || "—"}</td>
                  <td className="num mono">{s.open_cases || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!data.risky.length && <Empty title="Nothing read yet">Add a server in Inventory and run a scan.</Empty>}
        </Panel>

        <Panel span={3} title="Risk mix">
          <div className="stack" style={{ gap: 22 }}>
            <Stacked label="Open findings by severity" parts={SEVERITIES.map(([level, color]) => ({ label: level, value: findings.by_severity[level] || 0, color }))} />
            <Stacked label="Servers by provenance" parts={VERDICT_PARTS.map(([key, label, color]) => ({ label, value: data.provenance[key] || 0, color }))} />
          </div>
        </Panel>

        <Panel span={4} title="Alerts" flush extra={data.alerts.unread > 0 && can("work") && <button type="button" className="link small" onClick={readAll}>Mark all read</button>}>
          <AlertList alerts={data.alerts.latest} onRead={reload} />
        </Panel>

        <Panel span={5} title="Scans per day" hint="Every scan Raqeeb ran, split into the ones a person started and the ones the schedule started."
          extra={<Segment label="Period" value={String(period)} onChange={(v) => setPeriod(Number(v))}
            options={[["7", "7d"], ["14", "14d"], ["30", "30d"], ["90", "90d"]].map(([id, label]) => ({ id, label }))} />}>
          <Trend days={data.trend} />
        </Panel>

        <Panel span={4} title="Open findings by category" hint="OWASP MCP Top 10 category in brackets.">
          {data.categories.length
            ? <Bars rows={data.categories.map((c) => ({ label: `${c.title}${c.owasp ? ` (${c.owasp.split(":")[0]})` : ""}`, value: c.count }))} />
            : <Empty title="No open findings" />}
          {data.techniques.length > 0 && (
            <div className="row small" style={{ marginTop: 14, gap: "6px 8px" }}>
              <span className="muted">MITRE ATT&CK</span>
              {data.techniques.map((t) => <span key={t.id} className="chipline mono">{t.id} · {t.count}</span>)}
            </div>
          )}
        </Panel>

        <Panel span={3} title="Monitoring" extra={<Link to="/settings/monitoring" className="small">Schedules</Link>}>
          <div className="stack tight">
            {data.monitoring.upcoming.map((p) => (
              <div key={p.asset_id} className="row small" style={{ gap: 8 }}>
                <Link to={`/servers/${p.asset_id}`} className="grow clip1" style={{ fontWeight: 600 }}>{p.asset}</Link>
                <span className="muted">{EVERY[p.every_minutes] || `${p.every_minutes} min`}</span>
                <span className="mono">{new Date(p.next_scan).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
              </div>
            ))}
            {!data.monitoring.upcoming.length && <span className="muted">No server is on a schedule.</span>}
            <div className="divider" />
            <div className="row small"><span className="grow muted">Audit chain</span>
              <span className={data.integrity.intact ? "tone-ok" : "tone-crit"}>{data.integrity.intact ? "Intact" : "Broken"} · {data.integrity.sealed}</span></div>
            <div className="row small"><span className="grow muted">Signing key</span><span className="mono">{data.integrity.key_id}</span></div>
          </div>
        </Panel>

        <Briefing />

        <Panel span={4} title="Open cases" flush extra={<Link to="/cases" className="small">All cases</Link>}>
          <table className="grid"><tbody>
            {open.latest.map((c) => (
              <tr key={c.reference} className="click" onClick={() => navigate(`/cases/${c.reference}`)}>
                <td><span className="ref">{c.reference}</span><div className="small muted clip1">{c.title}</div></td>
                <td><Severity level={c.severity} /></td>
                <td><Status value={c.status} labels={CASE_STATUS} /><div className="small muted">{c.owner_name || "Unassigned"}</div></td>
              </tr>
            ))}
          </tbody></table>
          {!open.latest.length && <Empty title="No open cases">Raqeeb opens a case when a rule matches a scan.</Empty>}
        </Panel>

        <Panel span={4} title="Latest changes" flush extra={<Link to="/changes" className="small">All changes</Link>}>
          <table className="grid"><tbody>
            {changes.latest.map((c) => (
              <tr key={c.scan + c.kind} className="click"
                onClick={() => navigate(`/servers/${c.asset_id}/${c.kind === "against_release" ? "tools" : "scans"}`)}>
                <td style={{ fontWeight: 600 }}>{c.asset}<div className="small muted">{c.kind === "against_release" ? "Against release" : "Between scans"}</div></td>
                <td>{describeChange(c)}</td>
                <td className="mono small">{when(c.at)}</td>
              </tr>
            ))}
          </tbody></table>
          {!changes.latest.length && <Empty title="No changes recorded">Changes appear when a scan reads different declarations.</Empty>}
        </Panel>

        {field && (
          <Panel span={5} title="Public MCP baseline"
            hint="Reference figures for the wider ecosystem: open endpoints listed in the official MCP registry, read with the handshake and tool list only. Aggregate numbers; no server is named."
            extra={<span className="small muted">Official registry · {DAY(field.from.slice(0, 10), { day: "numeric", month: "short" })} to {DAY(field.to.slice(0, 10), { day: "numeric", month: "short", year: "numeric" })}</span>}>
            <div className="field">
              <div className="stack tight">
                <span className="big">{field.endpoints}</span><span className="small muted">listed endpoints</span>
                <Stacked label="How they answered" parts={[
                  { label: "Tool list", value: field.ok, color: "var(--brand)" },
                  { label: "Credential asked", value: field.auth_required, color: "var(--info)" },
                  { label: "Other", value: field.other, color: "var(--line-strong)" }]} />
              </div>
              <div className="stack tight">
                <span className="small muted">Listed servers whose tools changed</span>
                {field.day_to_day.map((d) => (
                  <div key={d.to} className="row small"><span className="grow">{new Date(d.to).toLocaleDateString(undefined, { day: "numeric", month: "short" })}</span>
                    <span className="mono">{d.changed} of {d.comparable}</span><b className="mono">{percent(d.share)}</b></div>
                ))}
                <div className="row small"><span className="grow">At least once in {field.runs} runs</span>
                  <span className="mono">{field.changed_once} of {field.listed}</span><b className="mono">{percent(field.changed_once / field.listed)}</b></div>
              </div>
            </div>
            <div className="divider" />
            <span className="small muted">What Raqeeb's rules match across {field.ok} servers ({field.tools.toLocaleString()} tools). Matches, not confirmed weaknesses.</span>
            <Bars color="var(--info)" rows={field.rules.map((r) => ({ label: r.finding, value: r.servers, text: `${r.servers} · ${percent(r.share)}` }))} />
          </Panel>
        )}

        <Panel span={3} title="Reference library" hint="Tool declarations of published npm releases, used to judge provenance.">
          {data.library ? (
            <div className="stack" style={{ gap: 14 }}>
              <div className="row"><div className="stack tight grow"><span className="big">{data.library.packages}</span><span className="small muted">packages</span></div>
                <div className="stack tight grow"><span className="big">{data.library.releases}</span><span className="small muted">releases</span></div></div>
              <Stacked label="Your servers against it" parts={VERDICT_PARTS.slice(0, 4).map(([key, label, color]) => ({ label, value: data.provenance[key] || 0, color }))} />
            </div>
          ) : <Empty title="Library not found" />}
        </Panel>

        <Panel span={field ? 4 : 9} title="Latest activity" flush extra={<Link to="/activity" className="small">All activity</Link>}>
          <table className="grid"><tbody>
            {data.activity.map((entry, index) => (
              <tr key={entry.ts + index}>
                <td className="mono small">{when(entry.ts)}</td>
                <td>{nameOf(entry.operator)}</td>
                <td style={{ fontWeight: 500 }}>{actionLabel(entry.action)}</td>
              </tr>
            ))}
          </tbody></table>
          {!data.activity.length && <Empty title="Nothing recorded yet">Every action lands here, sealed in the audit chain.</Empty>}
        </Panel>
      </div>
    </main>
  );
}
