import { useMemo, useState } from "react";
import { Link, NavLink, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, download } from "../lib/api.js";
import ScheduleSelect from "../components/Schedule.jsx";
import { compareTexts, hiddenCharacters } from "../lib/diff.js";
import { CASE_STATUS, OUTCOMES, describeChange, plural, provenanceLine, shortRelease, when, worst } from "../lib/format.js";
import { useTeam } from "../lib/Team.jsx";
import Explain from "../components/Explain.jsx";
import ScanMap from "../components/ScanMap.jsx";
import { Empty, Problem, Severity, Status, Verdict, VerdictWord, useAction, useLoad } from "../components/ui.jsx";

const NOT_READ = {
  auth_required: ["Authentication required", "This server asked for a credential before listing its tools. Raqeeb stops at that request and reads nothing further."],
  no_mcp: ["No MCP server answered", "Nothing at this endpoint completed an MCP handshake. Check the address and that the server is running."],
  unauthorized: ["Outside the authorized scope", "This target is not in the authorized scope, so Raqeeb did not contact it."],
  null: ["Not scanned yet", "Run a scan to read the handshake and the tool list. No tool is called."],
};

function releaseChange(release) {
  if (release.first) return "First release in library";
  const parts = [["redefined", release.redefined], ["added", release.added], ["removed", release.removed]]
    .filter(([, count]) => count).map(([word, count]) => `${count} ${word}`);
  return parts.join(", ") || "Unchanged";
}

function Overview({ page }) {
  const verdict = page.provenance ? page.provenance.verdict : "unknown";
  const severities = ["Critical", "High", "Medium", "Low"]
    .map((level) => [level, page.findings.filter((f) => f.severity === level).length]).filter(([, count]) => count);
  const groups = Object.values(page.findings.reduce((all, f) => {
    const group = all[f.title] || (all[f.title] = { ...f, count: 0 });
    group.count += 1;
    return all;
  }, {}));
  const change = page.last_change;

  return (
    <main className="page stack" style={{ gap: 24 }}>
      {verdict === "deviation" && (
        <section className="card alarm" aria-label="Verdict">
          <div className="row">
            <strong className="tone-bad">Declared tools differ from the published release</strong>
            <span className="grow">{provenanceLine(page)}</span>
            <Link className="btn primary" style={{ display: "flex", alignItems: "center" }} to={`/servers/${page.id}/tools`}>Open diff</Link>
          </div>
        </section>
      )}
      <Explain assetId={page.id} />
      <section className="stack tight" aria-label="Checks">
        <h2>Three checks on this scan</h2>
        <div className="three">
          <div className="card" title="Works for known published packages only."><span className="small muted">Published release comparison</span>
            <span style={{ fontSize: 20, lineHeight: "28px" }}><VerdictWord verdict={verdict} /></span>
            <span>{provenanceLine(page)}</span></div>
          <div className="card" title="Reads declarations; does not see what a tool does when called."><span className="small muted">Declaration analysis</span>
            <span style={{ fontSize: 20, lineHeight: "28px", fontWeight: 600 }}>{plural(page.findings.length, "finding")}</span>
            <span>{severities.map(([level, count]) => `${count} ${level}`).join(", ") || "Nothing flagged."}</span></div>
          <div className="card" title="Cannot see anything that happened before the first scan."><span className="small muted">Change monitoring</span>
            <span style={{ fontSize: 20, lineHeight: "28px", fontWeight: 600 }}>{change ? "Changed" : (page.scans.length > 1 ? "No change" : "First scan")}</span>
            <span>{change ? `${when(change.at)}: ${describeChange(change)} (${change.scan}).`
              : (page.scans.length > 1 ? `Same declarations across ${plural(page.scans.length, "scan")}.` : "No earlier scan to compare with. Monitoring starts from this one.")}</span></div>
        </div>
      </section>
      {page.cases.length > 0 && (
        <section className="stack tight" aria-label="Cases">
          <h2>Cases on this server</h2>
          <div className="panel scroll"><table className="grid"><tbody>
            {page.cases.map((c) => (
              <tr key={c.reference}><td><Link className="ref" to={`/cases/${c.reference}`}>{c.reference}</Link></td>
                <td style={{ fontWeight: 600 }}>{c.title}</td><td><Severity level={c.severity} /></td>
                <td><Status value={c.status} labels={CASE_STATUS} /></td><td className="muted">{c.owner_name || "Unassigned"}</td></tr>
            ))}
          </tbody></table></div>
        </section>
      )}
      {page.releases && (
        <section className="stack tight" aria-label="Release history">
          <div className="row"><h2>Where this server sits in the package history</h2>
            <span className="note">{page.releases.total} releases in the reference library, latest {page.releases.releases.length} shown</span></div>
          <div className="releases">
            {page.releases.releases.map((r) => (
              <div key={r.version} className="release" style={r.here ? { borderColor: verdict === "deviation" ? "var(--crit)" : "var(--ok)", borderWidth: 2 } : undefined}>
                <span className="row" style={{ justifyContent: "space-between" }}><span className="mono" style={{ fontWeight: 500 }}>{r.version}</span>
                  {r.here && <span className="small" style={{ fontWeight: 600 }}>This server</span>}</span>
                <span className="small muted">{r.published} · {plural(r.tool_count, "tool")}</span>
                <span className="small">{releaseChange(r)}</span>
              </div>
            ))}
          </div>
        </section>
      )}
      <section className="stack tight" aria-label="Findings by category">
        <h2>Findings by category</h2>
        <div className="panel scroll">
          <table className="grid" style={{ minWidth: 860 }}>
            <thead><tr><th>Severity</th><th>Category</th><th className="num">Findings</th><th>Evidence</th><th>OWASP MCP</th><th>MITRE</th></tr></thead>
            <tbody>
              {groups.map((g) => (
                <tr key={g.title}><td><Severity level={g.severity} /></td><td>{g.title}</td><td className="num mono">{g.count}</td>
                  <td className="mono small">{g.evidence_level}</td><td className="mono small">{(g.owasp_mcp || "—").split(":")[0]}</td>
                  <td className="mono small" style={{ color: "var(--brand)" }}>{g.technique_id || "—"}</td></tr>
              ))}
            </tbody>
          </table>
          {!groups.length && <Empty title="Nothing flagged">The declarations of this server raised no finding.</Empty>}
        </div>
        <Link to={`/findings?server=${page.id}`}>All findings on this server</Link>
      </section>
    </main>
  );
}

function Tools({ page }) {
  const [params, setParams] = useSearchParams();
  const byReference = useMemo(() => Object.fromEntries(page.findings.map((f) => [f.reference, f])), [page]);
  const changed = (tool) => tool.status === "redefined" || tool.status === "added";
  const ordered = useMemo(() => [...page.tools].sort((a, b) => Number(changed(b)) - Number(changed(a))
    || b.findings.length - a.findings.length || a.name.localeCompare(b.name)), [page]);
  const tool = ordered.find((t) => t.name === params.get("tool")) || ordered[0];
  if (!tool) return <Empty title="No tools declared">This server answered with an empty tool list.</Empty>;

  const found = tool.findings.map((reference) => byReference[reference]).filter(Boolean);
  const description = tool.differences.find((d) => d.field === "description");
  const others = tool.differences.filter((d) => d.field !== "description");
  const parts = description ? compareTexts(description.published || "", description.observed || "") : [];
  const hidden = description ? hiddenCharacters(description.observed || "").filter((c) => !hiddenCharacters(description.published || "").includes(c)) : [];
  const status = {
    redefined: `Differs from the published release in: ${tool.differences.map((d) => d.field).join(", ")}.`,
    added: "Not part of the published release.", identical: "Identical to the published release.",
    unverified: "No published release to compare with.",
  }[tool.status];

  return (
    <div className="split">
      <aside aria-label="Tools">
        {ordered.map((t) => {
          const top = worst(t.findings.map((r) => byReference[r]).filter(Boolean));
          return (
            <button key={t.name} type="button" className={t.name === tool.name ? "on" : ""} onClick={() => setParams({ tool: t.name })}>
              <span className="mono grow wrap-any">{t.name}</span>
              {changed(t) ? <span className="small tone-bad" style={{ fontWeight: 600 }}>{t.status === "redefined" ? "Redefined" : "Added"}</span>
                : (t.findings.length > 0 && <span className={`small tone-${{ Critical: "crit", High: "high", Medium: "med" }[top] || "muted"}`}>{t.findings.length}</span>)}
            </button>
          );
        })}
      </aside>
      <main>
        <div className="row" style={{ alignItems: "baseline" }}>
          <h2 className="mono" style={{ fontSize: 18, lineHeight: "24px", fontWeight: 500 }}>{tool.name}</h2>
          <span className={`small ${changed(tool) ? "tone-bad" : "muted"}`}>{status}</span>
        </div>
        <section className="stack tight" aria-label="Description">
          <h3>description</h3>
          {description ? (
            <>
              <div className="compare">
                <div><h4>Published · {(page.provenance.versions || []).slice(-1)[0]} · {(description.published || "").length} characters</h4><p>{description.published}</p></div>
                <div><h4>Observed · this server · {(description.observed || "").length} characters</h4>
                  <p>{parts.map((part, index) => (part.kind === "hidden"
                    ? <span key={index} className="hidden-char" title="Hidden character">{part.text}</span>
                    : <span key={index} className={part.kind === "same" ? undefined : part.kind}>{part.text}</span>))}</p></div>
              </div>
              <div className="row small muted">
                <span>{(description.observed || "").length - (description.published || "").length >= 0 ? "+" : ""}{(description.observed || "").length - (description.published || "").length} characters against the published text</span>
                {hidden.length > 0 && <span>{plural(hidden.length, "hidden character")}: {hidden.join(", ")}</span>}
              </div>
            </>
          ) : <p className="panel declared">{tool.description || "No description declared."}</p>}
        </section>
        {others.length > 0 && (
          <section className="stack tight" aria-label="Other changed fields">
            <h3>Other fields that differ</h3>
            {others.map((d) => (
              <div key={d.field} className="compare">
                <div><h4>{d.field} · published</h4><p>{typeof d.published === "string" ? d.published : JSON.stringify(d.published, null, 2)}</p></div>
                <div><h4>{d.field} · observed</h4><p>{typeof d.observed === "string" ? d.observed : JSON.stringify(d.observed, null, 2)}</p></div>
              </div>
            ))}
          </section>
        )}
        <section className="stack tight" aria-label="Parameters">
          <h3>Parameters</h3>
          {tool.parameters.length ? (
            <div className="panel"><table className="grid"><tbody>
              {tool.parameters.map((p) => (
                <tr key={p.name}><td className="mono">{p.name}</td><td className="mono muted">{p.type}</td><td className="mono muted">{p.required ? "required" : "optional"}</td></tr>
              ))}
            </tbody></table></div>
          ) : <p className="muted">This tool declares no parameters.</p>}
        </section>
        <section className="stack tight" aria-label="Findings on this tool">
          <h3>Findings on this tool</h3>
          {found.map((f) => (
            <div key={f.reference} className="card">
              <div className="row">
                <Link className="ref" to={`/findings?ref=${f.reference}`}>{f.reference}</Link>
                <Severity level={f.severity} /><strong className="grow">{f.title}</strong>
                <span className="mono small muted">{f.evidence_level}</span>
                <span className="mono small" style={{ color: "var(--brand)" }}>{f.technique_id}</span>
                {f.case && <Link className="ref" to={`/cases/${f.case}`}>{f.case}</Link>}
              </div>
              <span className="small">{(f.observed_facts || []).join(" · ")}</span>
              <span className="small muted">{f.inference}</span>
              <span className="small" style={{ color: "var(--brand)" }}>{f.recommendation}</span>
            </div>
          ))}
          {!found.length && <p className="muted">Nothing flagged in this declaration.</p>}
        </section>
      </main>
    </div>
  );
}

function Scans({ page }) {
  const action = useAction();
  const evidence = (reference) => action.run(() => download(`/api/scans/${reference}/evidence`, `${reference}.evidence.json`));
  return (
    <main className="page">
      <h2>Scan history</h2>
      <div className="panel scroll">
        <table className="grid" style={{ minWidth: 1100 }}>
          <thead><tr><th>Scan</th><th>Time</th><th>Run by</th><th>Trigger</th><th>Outcome</th><th>Provenance</th><th className="num">Tools</th><th className="num">Findings</th><th>Declarations</th><th title="Signed evidence can be checked without Raqeeb: see Settings, Evidence.">Signed evidence</th></tr></thead>
          <tbody>
            {page.scans.map((s) => (
              <tr key={s.reference}><td className="ref">{s.reference}</td><td className="mono">{when(s.started_at)}</td>
                <td>{s.operator === "raqeeb" ? "Raqeeb" : s.operator}</td><td>{s.trigger === "scheduled" ? "Scheduled" : "Manual"}</td>
                <td>{OUTCOMES[s.outcome] || s.outcome}</td>
                <td>{s.outcome === "read" ? <><VerdictWord verdict={s.verdict} /> <span className="mono small muted">{shortRelease(s.release)}</span></> : "—"}</td>
                <td className="num mono">{s.tool_count ?? "—"}</td><td className="num mono">{s.finding_count ?? "—"}</td>
                <td className="mono muted">{(s.declarations || "—").slice(0, 12)}</td>
                <td><button type="button" className="link" disabled={action.busy} onClick={() => evidence(s.reference)}>Download</button></td></tr>
            ))}
          </tbody>
        </table>
        {!page.scans.length && <Empty title="No scans yet">Run a scan to start this server's history.</Empty>}
      </div>
      <Problem error={action.error} />
    </main>
  );
}

export default function Server() {
  const { id, tab = "overview" } = useParams();
  const navigate = useNavigate();
  const { can } = useTeam();
  const { data: page, error, reload } = useLoad(() => api.get(`/api/assets/${id}/detail`), [id]);
  const [replayKey, setReplayKey] = useState(0);
  const action = useAction();

  if (error) return <main className="page"><Problem error={error} /><Link to="/">Back to inventory</Link></main>;
  if (!page) return <main className="page"><p className="muted">Loading…</p></main>;

  const read = !!page.read_scan;
  const base = `/servers/${page.id}`;
  const scan = async () => {
    const done = await action.run(() => api.post(`/api/assets/${page.id}/scan`));
    if (!done) return;
    reload();
    setReplayKey(Date.now());
    navigate(`${base}/map`);
  };
  const remove = async () => {
    if (!window.confirm(`Remove ${page.label}? Its scans, findings and cases are removed with it.`)) return;
    if (await action.run(() => api.del(`/api/assets/${page.id}`))) navigate("/");
  };
  const tabs = [["overview", "Overview"], ["tools", "Tools", read ? page.tools.length : null], ["map", "Scan map"], ["scans", "Scans", page.scans.length]];
  const blank = NOT_READ[page.latest_outcome] || NOT_READ.null;

  return (
    <>
      <section className="subhead" aria-label="Server">
        <div>
          <div className="small muted"><Link to="/inventory">Inventory</Link> / {page.label}</div>
          <div className="row server-head">
            <h1>{page.label}</h1>
            <span className="mono muted endpoint">{page.endpoint}</span>
            <Verdict scan={page.scan} badge />
            <span className="mono small muted">{read && page.read_scan.release ? `against ${page.read_scan.release}` : ""}</span>
            <span className="grow" />
            <span className="small muted">{page.scan ? `Scanned ${when(page.scan.started_at)}` : "Never scanned"}</span>
            {page.scan && <span className="ref small">{page.scan.reference}</span>}
            <ScheduleSelect assetId={page.id} value={page.schedule.every_minutes} onSaved={reload} disabled={!can("work")} />
            <button type="button" className="btn" disabled={action.busy || !read}
              title="An investigation report of this server: verdict, differences, findings, scans and evidence."
              onClick={() => action.run(() => download(`/api/assets/${page.id}/report`, `${page.label}-report.html`))}>Report</button>
            {can("work") && <button type="button" className="btn danger" disabled={action.busy} onClick={remove}>Remove</button>}
            {can("work") && <button type="button" className="btn primary" disabled={action.busy} onClick={scan}>{action.busy ? "Scanning…" : "Scan"}</button>}
          </div>
          <Problem error={action.error} />
          <dl className="facts">
            <div><dt>Severity</dt><dd><Severity level={read ? page.read_scan.severity : null} /></dd></div>
            <div><dt>Authentication</dt><dd>{read ? (page.auth_required ? "Required" : "None") : "—"}</dd></div>
            <div><dt>Tools</dt><dd className="mono">{read ? page.tools.length : "—"}</dd></div>
            <div><dt>Flagged</dt><dd className="mono">{read ? page.flagged_tools : "—"}</dd></div>
            <div><dt>Open cases</dt><dd className="mono">{page.open_cases}</dd></div>
            <div title={page.basis.since ? `Since ${when(page.basis.since)}` : undefined}><dt>Basis</dt><dd>{{ registry: "Official MCP registry", attested: "Owner statement", local: "Lab" }[page.basis.kind]}</dd></div>
            <div><dt>Next scan</dt><dd className="mono">{page.schedule.next_scan ? when(page.schedule.next_scan) : "Not scheduled"}</dd></div>
          </dl>
          <div className="tabs">
            {tabs.map(([key, label, count]) => (
              <NavLink key={key} to={key === "overview" ? base : `${base}/${key}`} end className={() => (tab === key ? "active" : "")}>
                {label}{count != null && <span className="mono small muted">{count}</span>}
              </NavLink>
            ))}
          </div>
        </div>
      </section>
      {tab === "scans" ? <Scans page={page} />
        : !read ? <Empty title={blank[0]}>{blank[1]}</Empty>
          : tab === "tools" ? <Tools page={page} />
            : tab === "map" ? <main className="page"><ScanMap page={page} replayKey={replayKey} toolsPath={`${base}/tools`} /></main>
              : <Overview page={page} />}
    </>
  );
}
