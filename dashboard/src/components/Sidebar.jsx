import { useEffect, useState, useCallback } from "react";
import { NavLink } from "react-router-dom";
import { getSettings } from "../lib/api.js";
import SettingsPanel from "./SettingsPanel.jsx";

const NAV = [
  { to: "/", label: "Overview", glyph: "◈", end: true },
  { to: "/scan", label: "Surface scan", glyph: "⊹" },
  { to: "/assets", label: "Assets", glyph: "▤" },
  { to: "/shadow-ai", label: "Shadow AI", glyph: "⬡" },
  { to: "/safe-proof", label: "Safe Proof", glyph: "🛡" },
  { to: "/authorization", label: "Authorization", glyph: "⊘" },
];

const MODE_META = {
  offline: { icon: "🔒", label: "Offline", cls: "text-signal border-signal/40 bg-signal/10" },
  redacted: { icon: "🛡", label: "Redacted", cls: "text-alert-med border-alert-med/40 bg-alert-med/10" },
  local: { icon: "🏠", label: "Local AI", cls: "text-alert-low border-alert-low/40 bg-alert-low/10" },
};

function Sidebar() {
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState("offline");

  const load = useCallback(() => {
    getSettings().then((r) => setMode(r?.ai_mode || "offline")).catch(() => {});
  }, []);
  useEffect(() => { load(); }, [load]);

  const meta = MODE_META[mode] || MODE_META.offline;

  return (
    <aside className="w-60 flex-shrink-0 border-r border-edge bg-ink-800/80 flex flex-col">
      <div className="px-5 py-5 border-b border-edge">
        <div className="flex items-center gap-2.5">
          <div className="h-8 w-8 rounded-lg bg-signal/10 border border-signal/30 flex items-center justify-center">
            <span className="text-signal text-sm">◆</span>
          </div>
          <div>
            <div className="font-display font-600 text-[15px] leading-none text-mist-100">
              CyberOSINT
            </div>
            <div className="text-[10px] uppercase tracking-[0.18em] text-mist-300 mt-1">
              Intelligence
            </div>
          </div>
        </div>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1">
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              [
                "group flex items-center gap-3 rounded-lg px-3 py-2 text-[13px] transition-colors",
                isActive
                  ? "bg-signal/10 text-mist-100 border border-signal/25"
                  : "text-mist-300 hover:text-mist-100 hover:bg-ink-600/50 border border-transparent",
              ].join(" ")
            }
          >
            {({ isActive }) => (
              <>
                <span
                  className={
                    isActive ? "text-signal" : "text-mist-300 group-hover:text-mist-200"
                  }
                >
                  {item.glyph}
                </span>
                {item.label}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="px-3 pt-3 pb-2 border-t border-edge space-y-3">
        {/* AI Privacy box — sits just above "engine online" */}
        <button
          onClick={() => setOpen(true)}
          className="w-full rounded-xl border border-edge bg-ink-900/50 hover:bg-ink-700/50 transition-colors px-3 py-2.5 text-left group"
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase tracking-[0.16em] text-mist-300">AI Privacy</span>
            <span className="text-mist-300 group-hover:text-mist-100 text-[12px]">⚙</span>
          </div>
          <div className="mt-1.5 flex items-center gap-2">
            <span className={`text-[11px] px-2 py-0.5 rounded-md border ${meta.cls}`}>
              {meta.icon} {meta.label}
            </span>
          </div>
        </button>

        <div className="px-2 text-[10px] font-mono text-mist-300">
          <div className="flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-signal animate-pulse" />
            engine online
          </div>
        </div>
      </div>

      <SettingsPanel open={open} onClose={() => { setOpen(false); load(); }} />
    </aside>
  );
}

export default Sidebar;
