import { useEffect, useState } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";
import { api } from "../lib/api.js";
import { useAuth } from "../lib/AuthContext.jsx";
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
        <Link to="/settings/profile" className="btn" style={{ display: "flex", alignItems: "center", borderRadius: 18 }}>{me ? me.display_name : "Account"}</Link>
        <button type="button" className="link small" onClick={signOut}>Sign out</button>
      </header>
      <Guard at={location.pathname}>{children}</Guard>
    </>
  );
}
