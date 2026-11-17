import { useEffect, useState } from "react";
import { Link, NavLink, useLocation, useNavigate } from "react-router-dom";
import { api } from "../lib/api.js";
import { useAuth } from "../lib/AuthContext.jsx";
import { when } from "../lib/format.js";
import { useTeam } from "../lib/Team.jsx";
import Guard from "./Guard.jsx";
import Mark from "./Mark.jsx";

const PAGES = [["/", "Dashboard"], ["/inventory", "Inventory"], ["/findings", "Findings"], ["/cases", "Cases"], ["/changes", "Changes"],
  ["/activity", "Activity"], ["/settings", "Settings"]];

function Search() {
  const [text, setText] = useState("");
  const [found, setFound] = useState(null);
  const location = useLocation();

  useEffect(() => { setText(""); setFound(null); }, [location.pathname, location.search]);
  useEffect(() => {
    const query = text.trim();
    if (query.length < 2) { setFound(null); return undefined; }
    const timer = setTimeout(() => {
      api.get("/api/search", { q: query }).then(setFound).catch(() => setFound(null));
    }, 220);
    return () => clearTimeout(timer);
  }, [text]);

  const hits = found ? [
    ...found.servers.map((s) => ({ kind: "Server", name: s.label || s.value, text: s.value, to: `/servers/${s.id}` })),
    ...found.cases.map((c) => ({ kind: "Case", name: c.reference, text: `${c.title} · ${c.asset}`, to: `/cases/${c.reference}` })),
    ...found.findings.map((f) => ({ kind: "Finding", name: f.reference, text: `${f.title} · ${f.asset}`, to: `/findings?ref=${f.reference}` })),
    ...found.scans.map((s) => ({ kind: "Scan", name: s.reference, text: `${s.asset}`, to: `/servers/${s.asset_id}/scans` })),
  ].slice(0, 10) : [];

  return (
    <div className="search">
      <input className="input" type="search" aria-label="Search" value={text} onChange={(event) => setText(event.target.value)}
        placeholder="Search server, SCN-, FND-, CASE-" />
      {found && (
        <div className="results">
          {hits.map((hit) => (
            <Link key={hit.kind + hit.name} to={hit.to}>
              <span className="small muted">{hit.kind}</span><span className="ref">{hit.name}</span>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{hit.text}</span>
            </Link>
          ))}
          {!hits.length && <p className="note" style={{ padding: "8px" }}>Nothing matches. Try a server name or a reference.</p>}
        </div>
      )}
    </div>
  );
}

function Alerts() {
  const [data, setData] = useState({ unread: 0, alerts: [] });
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const load = () => api.get("/api/alerts").then(setData).catch(() => {});

  useEffect(() => {
    load();
    const timer = setInterval(() => { if (!document.hidden) load(); }, 10000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => { setOpen(false); }, [location.pathname]);

  const readAll = async () => { await api.post("/api/alerts/ack-all"); load(); };
  const go = async (alert) => {
    if (!alert.acknowledged) await api.post(`/api/alerts/${alert.id}/ack`).catch(() => {});
    load();
    if (alert.asset_id) navigate(`/servers/${alert.asset_id}${alert.kind === "change" ? "/scans" : ""}`);
  };

  return (
    <div className="alerts">
      <button type="button" className={`btn bell${data.unread ? " ringing" : ""}`} aria-label={`Alerts, ${data.unread} unread`}
        aria-expanded={open} onClick={() => setOpen(!open)}>
        Alerts{data.unread > 0 && <span className="count">{data.unread}</span>}
      </button>
      {open && (
        <div className="results drop" role="dialog" aria-label="Alerts">
          <div className="row" style={{ padding: "4px 8px 8px" }}>
            <strong className="grow">Alerts</strong>
            {data.unread > 0 && <button type="button" className="link small" onClick={readAll}>Mark all read</button>}
          </div>
          {data.alerts.slice(0, 12).map((alert) => (
            <button key={alert.id} type="button" className={`alert-row${alert.acknowledged ? "" : " unread"}`} onClick={() => go(alert)}>
              <span className={`sevdot sev-${alert.severity}`} />
              <span className="stack tight" style={{ minWidth: 0 }}>
                <span style={{ fontWeight: 600 }}>{alert.title}</span>
                <span className="small muted clip">{alert.detail}</span>
                <span className="small muted mono">{when(alert.created_at)}</span>
              </span>
            </button>
          ))}
          {!data.alerts.length && <p className="note" style={{ padding: 8 }}>No alerts. Raqeeb raises one when a scan sees a server change, deviate or stop answering.</p>}
        </div>
      )}
    </div>
  );
}

export default function Shell({ children }) {
  const { signOut } = useAuth();
  const { me } = useTeam();
  const location = useLocation();
  const inServer = location.pathname.startsWith("/servers");

  return (
    <>
      <header className="topbar">
        <Link to="/" className="brand"><Mark />Raqeeb</Link>
        <nav className="nav" aria-label="Primary">
          {PAGES.map(([to, label]) => (
            <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => (isActive || (to === "/inventory" && inServer) ? "active" : "")}>{label}</NavLink>
          ))}
        </nav>
        <Search />
        <Alerts />
        <Link to="/settings/profile" className="btn" style={{ display: "flex", alignItems: "center", borderRadius: 18 }}>{me ? me.display_name : "Account"}</Link>
        <button type="button" className="link small" onClick={signOut}>Sign out</button>
      </header>
      <Guard at={location.pathname}>{children}</Guard>
    </>
  );
}
