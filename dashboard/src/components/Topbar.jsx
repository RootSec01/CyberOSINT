import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { getScope, getAlerts, ackAlert } from "../lib/api.js";
import { useAuth } from "../lib/AuthContext.jsx";
import PlatformCopilot from "./PlatformCopilot.jsx";

const SEV_TONE = {
  Critical: "text-alert-crit border-alert-crit/40",
  High: "text-alert-high border-alert-high/40",
  Medium: "text-alert-med border-alert-med/40",
};
const SEV_DOT = {
  Critical: "bg-alert-crit",
  High: "bg-alert-high",
  Medium: "bg-alert-med",
};

function timeAgo(iso) {
  if (!iso) return "";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const s = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} hr ago`;
  const d = Math.floor(h / 24);
  return `${d} day${d > 1 ? "s" : ""} ago`;
}

function BellIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.73 21a2 2 0 0 1-3.46 0" />
    </svg>
  );
}

function AlertBell() {
  const [alerts, setAlerts] = useState([]);
  const [unread, setUnread] = useState(0);
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();

  const load = useCallback(() => {
    getAlerts()
      .then((r) => {
        setAlerts(Array.isArray(r?.alerts) ? r.alerts : []);
        setUnread(r?.unread ?? 0);
        window.dispatchEvent(new Event("alerts:updated"));
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  async function openAlert(a) {
    setOpen(false);
    if (!a.acknowledged) {
      try { await ackAlert(a.id); } catch { /* ignore */ }
      load();
    }
    if (a.asset_id) navigate(`/assets?open=${a.asset_id}`);
  }

  async function markAll() {
    const pending = alerts.filter((a) => !a.acknowledged);
    await Promise.all(pending.map((a) => ackAlert(a.id).catch(() => {})));
    load();
  }

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        title="Alerts"
        className={`relative flex items-center justify-center h-[28px] w-[32px] rounded-md border transition-colors ${
          open ? "border-signal/50 text-signal bg-signal/10"
               : "border-edge bg-ink-700 text-mist-200 hover:text-mist-100 hover:bg-ink-600/50"
        }`}
      >
        <BellIcon />
        {unread > 0 && (
          <span className="absolute -top-1.5 -right-1.5 min-w-[16px] h-[16px] px-1 rounded-full bg-alert-crit text-white text-[10px] leading-[16px] text-center font-600 animate-pulse">
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 mt-2 w-[340px] max-h-[440px] overflow-auto z-50 rounded-lg border border-edge bg-ink-800 shadow-2xl">
            <div className="sticky top-0 flex items-center justify-between px-3 py-2 border-b border-edge bg-ink-800">
              <span className="text-[12px] font-600 text-mist-100">
                Alerts{unread > 0 ? ` · ${unread} new` : ""}
              </span>
              {unread > 0 && (
                <button onClick={markAll} className="text-[11px] text-signal hover:underline">
                  Mark all read
                </button>
              )}
            </div>

            {alerts.length === 0 ? (
              <div className="px-3 py-8 text-center text-[12px] text-mist-300">
                No alerts — you&apos;re all clear.
              </div>
            ) : (
              <ul className="divide-y divide-edge">
                {alerts.slice(0, 12).map((a) => (
                  <li key={a.id}>
                    <button
                      onClick={() => openAlert(a)}
                      className={`w-full text-left px-3 py-2.5 flex gap-2.5 hover:bg-ink-700/60 transition-colors ${a.acknowledged ? "opacity-55" : ""}`}
                    >
                      <span className={`mt-1 h-2 w-2 rounded-full shrink-0 ${SEV_DOT[a.severity] || "bg-mist-300"}`} />
                      <span className="min-w-0 flex-1">
                        <span className="flex items-center gap-1.5">
                          <span className={`text-[10px] px-1.5 py-0.5 rounded border ${SEV_TONE[a.severity] || "border-edge text-mist-300"}`}>
                            {a.severity}
                          </span>
                          {!a.acknowledged && <span className="h-1.5 w-1.5 rounded-full bg-signal" />}
                          <span className="ml-auto text-[10px] text-mist-300">{timeAgo(a.created_at)}</span>
                        </span>
                        <span className="block text-[12px] text-mist-100 mt-1 truncate">{a.title}</span>
                        {a.detail && <span className="block text-[11px] text-mist-300 truncate">{a.detail}</span>}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}

            <button
              onClick={() => { setOpen(false); navigate("/assets"); }}
              className="w-full text-center px-3 py-2 border-t border-edge text-[11px] text-mist-300 hover:text-mist-100 hover:bg-ink-700/60 transition-colors"
            >
              View monitored assets →
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function Topbar({ title, subtitle }) {
  const [scope, setScope] = useState(null);
  const { user, signOut } = useAuth();

  useEffect(() => {
    let alive = true;
    getScope()
      .then((s) => alive && setScope(s))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  const grants = scope?.active_grants?.length ?? 0;
  const unrestricted = scope?.unrestricted;

  return (
    <header className="h-16 flex-shrink-0 border-b border-edge bg-ink-800/60 flex items-center justify-between px-6">
      <div>
        <h1 className="font-display font-600 text-[17px] text-mist-100 leading-none">
          {title}
        </h1>
        {subtitle && (
          <p className="text-[12px] text-mist-300 mt-1.5">{subtitle}</p>
        )}
      </div>

      <div className="flex items-center gap-3 text-[11px]">
        {unrestricted && (
          <span className="px-2.5 py-1 rounded-md border border-alert-crit/40 bg-alert-crit/10 text-alert-crit font-500">
            unrestricted mode
          </span>
        )}
        <span className="px-2.5 py-1 rounded-md border border-edge bg-ink-700 text-mist-200 font-mono">
          {grants} active grant{grants === 1 ? "" : "s"}
        </span>

        <PlatformCopilot />

        <AlertBell />

        {user && (
          <div className="flex items-center gap-2 pl-3 ml-1 border-l border-edge">
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-edge bg-ink-700 text-mist-200">
              <span className="h-1.5 w-1.5 rounded-full bg-signal" />
              {user.username}
              <span className="text-mist-300">· {user.role}</span>
            </span>
            <button
              onClick={signOut}
              className="px-2.5 py-1 rounded-md border border-edge text-mist-300 hover:text-mist-100 hover:bg-ink-600/50 transition-colors"
            >
              Logout
            </button>
          </div>
        )}
      </div>
    </header>
  );
}

export default Topbar;
