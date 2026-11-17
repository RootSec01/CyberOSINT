import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, download } from "../lib/api.js";
import { CASE_STATUS, CLOSURES, when } from "../lib/format.js";
import { useTeam } from "../lib/Team.jsx";
import { Pills, Problem, Severity, Status, useAction, useLoad } from "../components/ui.jsx";

const MIN_NOTE = 10;

export default function CaseDetail() {
  const { reference } = useParams();
  const { can, members, nameOf } = useTeam();
  const { data: loaded, error } = useLoad(() => api.get(`/api/cases/${reference}`), [reference]);
  const [fresh, setFresh] = useState(null);
  const [closing, setClosing] = useState(false);
  const [reason, setReason] = useState("");
  const [note, setNote] = useState("");
  const [comment, setComment] = useState("");
  const [reopening, setReopening] = useState("");
  const action = useAction();
  const item = fresh && fresh.reference === reference ? fresh : loaded;

  if (error) return <main className="page narrow"><Problem error={error} /><Link to="/cases">Back to cases</Link></main>;
  if (!item) return <main className="page narrow"><p className="muted">Loading…</p></main>;

  const change = async (path, form) => {
    const updated = await action.run(() => api.post(`/api/cases/${reference}/${path}`, form));
    if (updated) setFresh(updated);
    return updated;
  };
  const closed = item.status === "closed";
  const works = can("work");
  const assignable = members.filter((m) => m.active && m.role !== "viewer");
  const ready = reason && note.trim().length >= MIN_NOTE;
  const meta = [["Server", <Link to={`/servers/${item.asset_id}`}>{item.asset}</Link>], ["Opened", when(item.opened_at)],
    ["Opened by", item.automatic ? "Raqeeb (automatic)" : nameOf(item.opened_by)], ["Scan", item.scan], ["Last scan", item.last_scan],
    ["Owner", item.owner_name || "Unassigned"], ["Still observed", item.still_observed ? "Yes" : "Not in the last scan"]];

  return (
    <main className="page narrow" style={{ gap: 20 }}>
      <div className="small muted"><Link to="/cases">Cases</Link> / {item.reference}</div>
      <div className="row">
        <span className="ref" style={{ fontSize: 14 }}>{item.reference}</span>
        <h1 style={{ flex: "1 1 320px" }}>{item.title}</h1>
        <Severity level={item.severity} /><Status value={item.status} labels={CASE_STATUS} badge />
      </div>
      {works && (
        <div className="row">
          {item.status === "open" && <button type="button" className="btn primary" disabled={action.busy} onClick={() => change("status", { status: "investigating" })}>Start investigation</button>}
          {!closed && !closing && <button type="button" className="btn" onClick={() => { setClosing(true); action.clear(); }}>Close case</button>}
          <Link className="btn" style={{ display: "flex", alignItems: "center" }} to={`/servers/${item.asset_id}`}>Open server</Link>
        </div>
      )}
      <div className="row">
        <button type="button" className="btn" disabled={action.busy}
          onClick={() => action.run(() => download(`/api/scans/${item.last_scan}/evidence`, `${item.last_scan}.evidence.json`))}>Download signed evidence</button>
        <span className="note">The record, declarations and findings of {item.last_scan}, signed by this installation.</span>
      </div>
      <Problem error={action.error} />

      {closing && !closed && (
        <section className="card selected" aria-label="Close case">
          <h2>Close this case</h2>
          <Pills label="Closure reason" value={reason} onChange={setReason} options={Object.entries(CLOSURES).map(([id, label]) => ({ id, label }))} />
          <label className="stack tight">What was done, and how it was confirmed
            <textarea className="input" rows={3} value={note} onChange={(event) => setNote(event.target.value)} />
          </label>
          <div className="row">
            <button type="button" className="btn primary" disabled={!ready || action.busy}
              onClick={async () => { if (await change("close", { reason, note })) { setClosing(false); setReason(""); setNote(""); } }}>Close case</button>
            <button type="button" className="btn" onClick={() => setClosing(false)}>Cancel</button>
            <span className="note">{ready ? "Ready to close." : `Choose a reason and write at least ${MIN_NOTE} characters.`}</span>
          </div>
        </section>
      )}

      {closed && (
        <section className="card done" aria-label="Closure">
          <strong className="tone-ok">Closed by {nameOf(item.closed_by)} as {CLOSURES[item.closure_reason] || item.closure_reason} · {when(item.closed_at)}</strong>
          <span>{item.closure_note}</span>
          {works && (
            <div className="row">
              <input className="input grow" aria-label="Reason to reopen" placeholder="Reason to reopen" value={reopening} onChange={(event) => setReopening(event.target.value)} />
              <button type="button" className="btn" disabled={reopening.trim().length < MIN_NOTE || action.busy}
                onClick={async () => { if (await change("reopen", { note: reopening })) setReopening(""); }}>Reopen</button>
            </div>
          )}
        </section>
      )}

      <section className="card" aria-label="Origin">
        <h2>Reason</h2>
        <span>{item.automatic
          ? `Opened automatically by Raqeeb on ${when(item.opened_at)}, from scan ${item.scan}. No person opened it.`
          : `Opened by ${nameOf(item.opened_by)} on ${when(item.opened_at)}, from scan ${item.scan}.`}</span>
        {item.rule_text && <span className="muted">Rule: {item.rule_text}</span>}
        <span style={{ borderTop: "1px solid var(--line2)", paddingTop: 12 }}>{item.reason}</span>
      </section>

      <dl className="card metas" style={{ display: "grid" }}>{meta.map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}</dl>

      {works && !closed && (
        <section className="card" aria-label="Owner" title="Members are managed in Settings. Viewers cannot own a case.">
          <h2>Assign to</h2>
          <div className="row">
            {assignable.map((m) => (
              <button key={m.id} type="button" className={`btn${item.owner === m.username ? " primary" : ""}`} disabled={action.busy}
                onClick={() => change("assign", { owner: m.username })}>{m.display_name} · {m.role}</button>
            ))}
            {item.owner && <button type="button" className="btn" disabled={action.busy} onClick={() => change("assign", { owner: "" })}>Unassign</button>}
          </div>
        </section>
      )}

      <section className="stack tight" aria-label="Linked findings">
        <h2>Linked findings</h2>
        <div className="panel scroll"><table className="grid"><tbody>
          {item.findings.map((f) => (
            <tr key={f.reference}><td><Link className="ref" to={`/findings?ref=${f.reference}`}>{f.reference}</Link></td>
              <td><Severity level={f.severity} /></td><td>{f.title}</td><td className="mono">{f.tool || "server"}</td>
              <td className="mono small">{f.evidence_level}</td><td className="muted">{f.status === "resolved" ? "Resolved" : ""}</td></tr>
          ))}
        </tbody></table></div>
      </section>

      <section className="stack tight" aria-label="Timeline">
        <h2>Timeline</h2>
        <div className="panel">
          {item.timeline.map((event, index) => (
            <div key={index} className="timeline"><span className="mono">{when(event.at)}</span><span className="muted">{nameOf(event.actor)}</span><span>{event.text}</span></div>
          ))}
          {works && (
            <form className="row" style={{ padding: "12px 16px" }} onSubmit={async (event) => { event.preventDefault(); if (await change("notes", { text: comment })) setComment(""); }}>
              <input className="input grow" aria-label="Note" placeholder="Add a note to this case" value={comment} onChange={(event) => setComment(event.target.value)} />
              <button className="btn" type="submit" disabled={!comment.trim() || action.busy}>Add note</button>
            </form>
          )}
        </div>
      </section>
    </main>
  );
}
