import { useEffect, useState } from "react";
import { api } from "../lib/api.js";
import { useAuth } from "../lib/AuthContext.jsx";
import Mark from "./Mark.jsx";
import { Problem, useAction } from "./ui.jsx";

const STEPS = [
  ["Read", "Handshake and tool list. No tool is called and no credential is sent."],
  ["Compare", "Against the published release and against the previous scan."],
  ["Act", "Findings, cases, alerts and signed evidence for every scan."],
];

const BLIPS = [[150, 0.62, "ok"], [205, 0.83, "ok"], [262, 0.42, "ok"], [318, 0.7, "bad"], [20, 0.9, "ok"], [80, 0.5, "ok"]];

function Backdrop() {
  const cx = 300;
  const cy = 300;
  const rings = [70, 140, 210, 280];
  return (
    <svg className="backdrop" viewBox="0 0 600 600" aria-hidden="true">
      <defs>
        <radialGradient id="sweep-fill" cx="0" cy="0" r="1">
          <stop offset="0" stopColor="var(--brand)" stopOpacity="0.35" />
          <stop offset="1" stopColor="var(--brand)" stopOpacity="0" />
        </radialGradient>
      </defs>
      {rings.map((r) => <circle key={r} cx={cx} cy={cy} r={r} fill="none" stroke="var(--brand)" strokeOpacity={0.12 + r / 2800} />)}
      <line x1={cx - 290} y1={cy} x2={cx + 290} y2={cy} stroke="var(--brand)" strokeOpacity="0.12" />
      <line x1={cx} y1={cy - 290} x2={cx} y2={cy + 290} stroke="var(--brand)" strokeOpacity="0.12" />
      {Array.from({ length: 12 }, (_, i) => i * 30).map((angle) => {
        const a = (angle * Math.PI) / 180;
        return <line key={angle} x1={cx + Math.cos(a) * 272} y1={cy + Math.sin(a) * 272} x2={cx + Math.cos(a) * 288} y2={cy + Math.sin(a) * 288}
          stroke="var(--brand)" strokeOpacity="0.4" />;
      })}
      <g className="sweep" style={{ transformOrigin: `${cx}px ${cy}px` }}>
        <path d={`M${cx} ${cy} L${cx + 280} ${cy} A280 280 0 0 0 ${cx + 280 * Math.cos(Math.PI / 5)} ${cy - 280 * Math.sin(Math.PI / 5)} Z`} fill="url(#sweep-fill)" />
        <line x1={cx} y1={cy} x2={cx + 280} y2={cy} stroke="var(--brand)" strokeOpacity="0.7" />
      </g>
      {BLIPS.map(([angle, share, tone]) => {
        const a = (angle * Math.PI) / 180;
        const x = cx + Math.cos(a) * 280 * share;
        const y = cy + Math.sin(a) * 280 * share;
        const color = tone === "bad" ? "var(--crit)" : "var(--brand)";
        return (
          <g key={angle}>
            <circle cx={x} cy={y} r="11" fill="none" stroke={color} strokeOpacity="0.35" />
            <circle cx={x} cy={y} r="4" fill={color} />
          </g>
        );
      })}
      <circle cx={cx} cy={cy} r="5" fill="var(--brand)" />
    </svg>
  );
}

export default function Login() {
  const { signIn } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [state, setState] = useState(null);
  const action = useAction();

  useEffect(() => { api.get("/api/platform").then(setState).catch(() => {}); }, []);

  const submit = (event) => {
    event.preventDefault();
    action.run(() => signIn(username.trim(), password));
  };

  return (
    <div className="login">
      <section className="login-brand">
        <Backdrop />
        <div className="login-copy">
          <span className="brand big-brand"><Mark size={44} />Raqeeb</span>
          <h1>Know what your MCP servers tell your agents.</h1>
          <p className="muted">Provenance, change monitoring and investigation for Model Context Protocol servers.</p>
          <ol className="login-steps">
            {STEPS.map(([title, text], index) => (
              <li key={title}><span className="mono">{String(index + 1).padStart(2, "0")}</span><b>{title}</b><span className="muted">{text}</span></li>
            ))}
          </ol>
        </div>
      </section>
      <section className="login-form">
        <form onSubmit={submit}>
          <h2>Sign in</h2>
          <p className="muted small">Accounts are created by the administrator of this installation.</p>
          {state && !state.online && <p className="notice">Raqeeb is offline{state.message ? `: ${state.message}` : "."} Administrators can still sign in.</p>}
          <label className="stack tight">Username
            <input className="input" autoFocus autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} />
          </label>
          <label className="stack tight">Password
            <input className="input" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} />
          </label>
          <Problem error={action.error} />
          <button className="btn primary" type="submit" disabled={action.busy || !username || !password}>Sign in</button>
          <p className="small muted">Authorized use only. Sign-ins and actions are recorded.</p>
        </form>
        <nav className="login-links small"><a href="/terms">Terms of use</a><a href="/privacy">Privacy</a><a href="/about">About the scanner</a></nav>
      </section>
    </div>
  );
}
