import { useEffect, useState } from "react";
import { NavLink, useParams } from "react-router-dom";
import { api, sendFile } from "../lib/api.js";
import { applyTheme, storedTheme } from "../lib/theme.js";
import { useTeam } from "../lib/Team.jsx";
import { useAuth } from "../lib/AuthContext.jsx";
import { Problem, Segment, Severity, useAction, useLoad } from "../components/ui.jsx";
import ScheduleSelect from "../components/Schedule.jsx";
import { when } from "../lib/format.js";

const SECTIONS = [["profile", "Profile"], ["members", "Members"], ["rules", "Case rules"], ["monitoring", "Monitoring"], ["scope", "Scope"], ["evidence", "Evidence"], ["assistant", "Assistant"], ["appearance", "Appearance"]];
const ROLE_NOTES = [["owner", "Everything, including admins"], ["admin", "Manage members and rules; work findings and cases"],
  ["analyst", "Add servers, run scans, work findings and cases"], ["viewer", "Read only"]];
const ROLES = [{ id: "admin", label: "Admin" }, { id: "analyst", label: "Analyst" }, { id: "viewer", label: "Viewer" }];

function Profile() {
  const { me, reload } = useTeam();
  const { user, signOut } = useAuth();
  const [form, setForm] = useState(null);
  const [saved, setSaved] = useState(false);
  const action = useAction();
  useEffect(() => { if (me && !form) setForm({ display_name: me.display_name || "", email: me.email || "", title: me.title || "" }); }, [me, form]);
  if (!form) return null;
  const set = (key) => (event) => { setSaved(false); setForm({ ...form, [key]: event.target.value }); };
  const save = async (event) => {
    event.preventDefault();
    if (await action.run(() => api.put("/api/profile", form))) { setSaved(true); reload(); }
  };
  return (
    <form className="card" onSubmit={save}>
      <h2>Profile</h2>
      <label className="formrow" title="Shown on every case action and note you make."><span>Display name</span><input className="input" value={form.display_name} onChange={set("display_name")} /></label>
      <label className="formrow"><span>Email</span><input className="input" type="email" value={form.email} onChange={set("email")} /></label>
      <label className="formrow"><span>Job title</span><input className="input" value={form.title} onChange={set("title")} /></label>
      <div className="formrow"><span>Username</span><span className="mono">{me.username}</span></div>
      <div className="formrow"><span>Role</span><strong style={{ textTransform: "capitalize" }}>{me.role}</strong></div>
      <div className="row"><button className="btn primary" type="submit" disabled={action.busy}>Save</button>{saved && <span className="note">Saved.</span>}</div>
      <Problem error={action.error} />
      {!(user && user.guest) && (
        <div className="row" style={{ marginTop: 20, paddingTop: 16, borderTop: "1px solid var(--line)" }}>
          <button type="button" className="btn danger" onClick={signOut}>Sign out</button>
          <span className="muted small">Ends this session on this browser.</span>
        </div>
      )}
    </form>
  );
}

function Members() {
  const { me, members, can, reload } = useTeam();
  const manage = can("manage");
  const [form, setForm] = useState({ username: "", display_name: "", email: "", password: "", role: "analyst" });
  const action = useAction();
  const set = (key) => (event) => setForm({ ...form, [key]: event.target.value });
  const ready = form.username.trim().length >= 2 && form.password.length >= 8;
  const add = async (event) => {
    event.preventDefault();
    if (await action.run(() => api.post("/api/members", form))) { setForm({ username: "", display_name: "", email: "", password: "", role: "analyst" }); reload(); }
  };
  const change = async (work) => { if (await action.run(work)) reload(); };
  const ownerOnly = (member) => member.role === "admin" && me.role !== "owner";

  return (
    <>
      <section className="card">
        <div className="row"><h2 className="grow" title={ROLE_NOTES.map(([role, text]) => `${role[0].toUpperCase()}${role.slice(1)}: ${text.toLowerCase()}.`).join(" ")}>Members</h2><span className="note">{members.length} in this team</span></div>
        {members.map((m) => (
          <div key={m.id} className="row" style={{ borderTop: "1px solid var(--line2)", paddingTop: 12 }}>
            <span className="stack grow" style={{ gap: 0, flexBasis: 200 }}><strong>{m.display_name}</strong><span className="mono small muted">{m.username}{m.email ? ` · ${m.email}` : ""}</span></span>
            {!m.active && <span className="note">Removed</span>}
            {m.role === "owner" || !manage || !m.active || ownerOnly(m)
              ? <strong style={{ textTransform: "capitalize" }}>{m.role}</strong>
              : <>
                <Segment label={`Role of ${m.display_name}`} value={m.role} options={me.role === "owner" ? ROLES : ROLES.slice(1)}
                  onChange={(role) => change(() => api.patch(`/api/members/${m.id}`, { role }))} />
                <button type="button" className="btn danger" disabled={action.busy}
                  onClick={() => window.confirm(`Remove ${m.display_name}? Their cases become unassigned.`) && change(() => api.del(`/api/members/${m.id}`))}>Remove</button>
              </>}
          </div>
        ))}
        <Problem error={action.error} />
      </section>
      {manage && (
        <form className="card" onSubmit={add}>
          <h2>Add a member</h2>
          <div className="row">
            <input className="input grow" aria-label="Username" placeholder="Username" autoComplete="off" value={form.username} onChange={set("username")} />
            <input className="input grow" aria-label="Full name" placeholder="Full name" value={form.display_name} onChange={set("display_name")} />
            <input className="input grow" aria-label="Email" type="email" placeholder="Email (optional)" value={form.email} onChange={set("email")} />
          </div>
          <div className="row">
            <input className="input" aria-label="First password" type="password" autoComplete="new-password" placeholder="First password (8+ characters)" style={{ minWidth: 260 }} value={form.password} onChange={set("password")} />
            <Segment label="Role" value={form.role} options={me.role === "owner" ? ROLES : ROLES.slice(1)} onChange={(role) => setForm({ ...form, role })} />
            <button className="btn primary" type="submit" disabled={!ready || action.busy}>Add member</button>
          </div>
          <p className="note">You create the account and hand over the first password. No email is sent.</p>
        </form>
      )}
    </>
  );
}

function Rules() {
  const { can } = useTeam();
  const { data, reload } = useLoad(() => api.get("/api/case-rules"), []);
  const action = useAction();
  const toggle = async (rule) => { if (await action.run(() => api.put(`/api/case-rules/${rule.rule}`, { enabled: String(!rule.enabled) }))) reload(); };
  return (
    <section className="card">
      <h2 title="A case opened by a rule names the rule, the scan and the evidence. Switching a rule off stops new cases; open ones stay.">When Raqeeb opens a case by itself</h2>
      {(data ? data.rules : []).map((rule) => (
        <div key={rule.rule} className="row" style={{ borderTop: "1px solid var(--line2)", paddingTop: 12 }}>
          <span className="stack grow" style={{ gap: 2, flexBasis: 320 }}><strong>{rule.title}</strong><span className="muted">{rule.text}</span></span>
          <Severity level={rule.severity} />
          <button type="button" aria-pressed={rule.enabled} className={`pill${rule.enabled ? " on" : ""}`} disabled={!can("manage") || action.busy} onClick={() => toggle(rule)}>{rule.enabled ? "On" : "Off"}</button>
        </div>
      ))}
      <Problem error={action.error} />
    </section>
  );
}

function Monitoring() {
  const { data, error, reload } = useLoad(() => api.get("/api/monitoring"), []);
  const { can } = useTeam();
  return (
    <section className="card">
      <h2 title="A scheduled scan runs as Raqeeb and raises an alert when the tool list changes, deviates from the release or stops answering.">Scheduled scans and alerts</h2>
      <Problem error={error} />
      {data && (
        <>
          <div className="formrow"><span>Scheduler</span>
            <span className={data.enabled ? "tone-ok" : "tone-high"}
              title={data.enabled ? undefined : "Set SCHEDULER_ENABLED=true in .env and restart the server."}>{data.enabled ? "Running" : "Off on this installation"}</span></div>
          <div className="formrow"><span>Alert webhook</span>
            <span className="muted" title="ALERT_WEBHOOK_URL in .env receives every alert as JSON.">{data.webhook ? "Configured" : "Not configured"}</span></div>
          <table className="grid" style={{ marginTop: 8 }}>
            <thead><tr><th>Server</th><th>Schedule</th><th>Last scan</th><th>Next scan</th></tr></thead>
            <tbody>
              {data.plans.map((p) => (
                <tr key={p.asset_id}>
                  <td style={{ fontWeight: 600 }}>{p.asset}</td>
                  <td><ScheduleSelect assetId={p.asset_id} value={p.every_minutes} onSaved={reload} disabled={!can("work")} /></td>
                  <td className="mono">{when(p.last_scan)}</td>
                  <td className="mono">{p.next_scan ? when(p.next_scan) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!data.plans.length && <span className="muted">No servers yet.</span>}
        </>
      )}
    </section>
  );
}

function Scope() {
  const { data, error, reload } = useLoad(() => api.get("/api/scope"), []);
  const { me } = useTeam();
  const [ip, setIp] = useState("");
  const [hours, setHours] = useState("24");
  const [reason, setReason] = useState("");
  const action = useAction();
  const standing = data ? data.standing_scope || [] : [];
  const grants = data ? data.active_grants || [] : [];
  const grant = async (event) => {
    event.preventDefault();
    if (await action.run(() => api.post("/api/authorize", { ip: ip.trim(), ttl_minutes: Number(hours) * 60, reason: reason.trim() }))) {
      setIp(""); setReason(""); reload();
    }
  };
  const revoke = async (address) => { if (await action.run(() => api.post("/api/revoke", { ip: address, reason: "revoked from settings" }))) reload(); };
  return (
    <>
      <section className="card">
        <h2 title="A server is read only when one of these allows it.">What may be scanned</h2>
        <Problem error={error} />
        <div className="formrow"><span>Official MCP registry</span><span className="muted">Open endpoints their operators list for any client. Read at most once an hour.</span></div>
        <div className="formrow"><span>Your own servers</span><span className="muted">Added with a signed statement of ownership or written permission, and inside the ranges below.</span></div>
        <div className="formrow"><span>Standing ranges</span><span className="mono">{standing.length ? standing.join(", ") : "None configured"}</span></div>
        {data && data.unrestricted && <p className="error">Unrestricted scanning is switched on in the server environment.</p>}
      </section>
      <section className="card">
        <h2 title="A temporary grant lets Raqeeb read one address for a set time. Only platform administrators can issue one.">Temporary grants</h2>
        <table className="grid">
          <thead><tr><th>Address</th><th>Until</th><th /></tr></thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.ip}><td className="mono">{g.ip}</td><td className="mono">{when(g.expires)}</td>
                <td className="num">{me && me.platform_admin && <button type="button" className="link small" onClick={() => revoke(g.ip)}>Revoke</button>}</td></tr>
            ))}
          </tbody>
        </table>
        {!grants.length && <span className="muted">None active.</span>}
        {me && me.platform_admin && (
          <form className="row" onSubmit={grant}>
            <input className="input mono" style={{ maxWidth: 220 }} placeholder="IP address" aria-label="IP address" value={ip} onChange={(e) => setIp(e.target.value)} />
            <select className="input" style={{ maxWidth: 160 }} aria-label="Duration" value={hours} onChange={(e) => setHours(e.target.value)}>
              {[["1", "1 hour"], ["24", "1 day"], ["168", "7 days"], ["720", "30 days"]].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
            <input className="input grow" placeholder="Reason, e.g. the written permission it rests on" aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} />
            <button type="submit" className="btn primary" disabled={action.busy || !ip.trim() || reason.trim().length < 5}>Grant</button>
          </form>
        )}
        <Problem error={action.error} />
      </section>
    </>
  );
}

function Platform() {
  const { data, error, reload } = useLoad(() => api.get("/api/platform"), []);
  const [message, setMessage] = useState("");
  const action = useAction();
  const flip = async (online) => {
    if (!online && !window.confirm("Take Raqeeb offline? Everyone except platform administrators is signed out of the console, and scheduled scans pause.")) return;
    if (await action.run(() => api.put("/api/platform", { online, message: online ? "" : message.trim() }))) {
      setMessage("");
      reload();
      window.dispatchEvent(new Event("platform:changed"));
    }
  };
  if (error) return <Problem error={error} />;
  if (!data) return null;
  return (
    <section className="card">
      <h2 title="Only platform administrators see this section.">Platform</h2>
      <div className="formrow"><span>Status</span>
        <strong className={data.online ? "tone-ok" : "tone-crit"}>{data.online ? "Online" : "Offline"}</strong></div>
      {data.changed_by && <div className="formrow"><span>Last change</span><span className="muted">{data.changed_by}, {when(data.changed_at)}</span></div>}
      {data.online ? (
        <div className="row">
          <input className="input grow" placeholder="Message shown to users while offline (optional)" aria-label="Offline message"
            value={message} onChange={(e) => setMessage(e.target.value)} />
          <button type="button" className="btn danger" disabled={action.busy} onClick={() => flip(false)}>Take offline</button>
        </div>
      ) : (
        <div className="row">
          {data.message && <span className="grow muted">{data.message}</span>}
          <button type="button" className="btn primary" disabled={action.busy} onClick={() => flip(true)}>Bring online</button>
        </div>
      )}
      <Problem error={action.error} />
    </section>
  );
}

function Evidence() {
  const key = useLoad(() => api.get("/api/evidence/key"), []);
  const chain = useLoad(() => api.get("/api/audit/integrity"), []);
  const [checked, setChecked] = useState(null);
  const action = useAction();
  const check = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    setChecked(null);
    const result = await action.run(() => sendFile("/api/evidence/verify", file));
    if (result) setChecked({ ...result, name: file.name });
    event.target.value = "";
  };
  return (
    <>
      <section className="card">
        <h2 title="Every evidence file from this installation is signed with this key. Publish the key id where the people who receive your evidence can find it.">Signing key</h2>
        <div className="formrow"><span>Key id</span><span className="mono">{key.data ? key.data.key_id : "—"}</span></div>
        <div className="formrow"><span>Public key</span><span className="mono wrap-any">{key.data ? key.data.public_key : "—"}</span></div>
        <div className="formrow"><span>Algorithm</span><span>{key.data ? key.data.algorithm : "—"}</span></div>
        <p className="note mono">python3 -m raqeeb.evidence verify SCN-….evidence.json --key {key.data ? key.data.key_id : "KEY_ID"}</p>
      </section>
      <section className="card">
        <h2>Check an evidence file</h2>
        <label className="row"><span className="btn" style={{ display: "flex", alignItems: "center" }}>Choose a file</span>
          <input type="file" accept="application/json,.json" style={{ position: "absolute", left: -9999 }} onChange={check} /></label>
        {checked && (
          <div className="stack tight">
            <strong className={checked.valid ? "tone-ok" : "tone-bad"}>{checked.valid ? "Valid" : "Not valid"} · {checked.scan || checked.name}</strong>
            <span>{checked.reason}</span>
            <span className="muted">{checked.valid ? (checked.signed_here ? "Signed by this installation's key." : "Signed by a different key than this installation's.") : ""}</span>
          </div>
        )}
        <Problem error={action.error} />
      </section>
      <section className="card">
        <h2 title="Each entry is sealed with a hash covering the one before it, so an edited or removed entry breaks the chain.">Audit log integrity</h2>
        {chain.data && (
          <strong className={chain.data.intact ? "tone-ok" : "tone-bad"}>
            {chain.data.intact ? `Intact: ${chain.data.sealed} sealed entries` : `Broken at entry ${chain.data.broken_at}: ${chain.data.reason}`}
          </strong>
        )}
      </section>
    </>
  );
}

const MODES = [["offline", "Offline", "A fixed briefing is built from the evidence. Nothing leaves the platform."],
  ["redacted", "Redacted", "Identifiers and secrets are stripped, then the question goes to the chosen provider."],
  ["local", "Local model", "Sent as is to a model inside your own network."]];

function Assistant() {
  const { me } = useTeam();
  const { data, reload } = useLoad(() => api.get("/api/settings"), []);
  const [form, setForm] = useState(null);
  const action = useAction();
  useEffect(() => { if (data) setForm({ ai_base_url: data.ai_base_url || "", ai_model: data.ai_model || "" }); }, [data]);
  if (!data || !form) return null;
  const save = async (patch) => { if (await action.run(() => api.put("/api/settings", patch))) reload(); };
  return (
    <>
      <section className="card">
        <h2 title="The assistant only explains evidence a scan already recorded. Verdicts, findings and cases never depend on it, and every question is written to Activity.">Assistant privacy mode</h2>
        {MODES.map(([id, label, text]) => (
          <button key={id} type="button" className="btn" aria-pressed={data.ai_mode === id} disabled={action.busy} onClick={() => save({ ai_mode: id })}
            style={{ height: "auto", minHeight: 56, padding: "8px 12px", display: "flex", flexWrap: "wrap", alignItems: "center", gap: "4px 16px", textAlign: "left", whiteSpace: "normal",
              borderColor: data.ai_mode === id ? "var(--brand)" : undefined, background: data.ai_mode === id ? "var(--sel)" : undefined }}>
            <strong style={{ flex: "0 0 120px" }}>{label}</strong><span className="muted" style={{ flex: "1 1 320px" }}>{text}</span>
            {data.ai_mode === id && <span className="small" style={{ color: "var(--brand)", fontWeight: 600 }}>Selected</span>}
          </button>
        ))}
      </section>
      {me && me.platform_admin && <form className="card" onSubmit={(event) => { event.preventDefault(); save(form); }}>
        <h2 title="Keys are read from the server environment and are never shown or stored here.">Local model endpoint</h2>
        <label className="formrow"><span>Endpoint</span><input className="input mono" placeholder="Base URL of an OpenAI-compatible endpoint" value={form.ai_base_url} onChange={(event) => setForm({ ...form, ai_base_url: event.target.value })} /></label>
        <label className="formrow"><span>Model name</span><input className="input mono" placeholder="As named by your provider" value={form.ai_model} onChange={(event) => setForm({ ...form, ai_model: event.target.value })} /></label>
        <div className="row"><button className="btn primary" type="submit" disabled={action.busy}>Save</button></div>
      </form>}
      <Problem error={action.error} />
    </>
  );
}

function Appearance() {
  const [theme, setTheme] = useState(storedTheme());
  return (
    <section className="card">
      <h2>Appearance</h2>
      <Segment label="Theme" value={theme} options={[{ id: "dark", label: "Dark" }, { id: "light", label: "Light" }]}
        onChange={(next) => { applyTheme(next); setTheme(next); }} />
    </section>
  );
}

const VIEWS = { profile: Profile, members: Members, rules: Rules, monitoring: Monitoring, scope: Scope, platform: Platform, evidence: Evidence, assistant: Assistant, appearance: Appearance };

export default function Settings() {
  const { section } = useParams();
  const { me } = useTeam();
  const admin = !!(me && me.platform_admin);
  const sections = admin ? [...SECTIONS, ["platform", "Platform"]] : SECTIONS;
  const View = (section === "platform" && !admin ? null : VIEWS[section]) || Profile;
  return (
    <div className="settings">
      <nav aria-label="Settings">
        <h1 style={{ marginBottom: 12 }}>Settings</h1>
        {sections.map(([id, label]) => <NavLink key={id} to={`/settings/${id}`} className={({ isActive }) => (isActive ? "active" : "")}>{label}</NavLink>)}
      </nav>
      <div className="settings-body"><View /></div>
    </div>
  );
}
