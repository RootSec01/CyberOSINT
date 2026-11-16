import { useCallback, useEffect, useState } from "react";
import { VERDICTS, verdictOf } from "../lib/format.js";

const SEVERITY_VAR = { Critical: "--crit", High: "--high", Medium: "--med", Low: "--muted" };

export function Severity({ level }) {
  if (!level) return <span className="muted">—</span>;
  return <span className="sev"><i style={{ background: `var(${SEVERITY_VAR[level] || "--muted"})` }} />{level}</span>;
}

export function Verdict({ scan, badge = false }) {
  const verdict = verdictOf(scan);
  return <span className={`${badge ? "badge " : ""}tone-${verdict.tone}`} style={{ fontWeight: verdict.tone === "muted" ? 400 : 600 }}>{verdict.label}</span>;
}

export function VerdictWord({ verdict }) {
  const known = VERDICTS[verdict] || VERDICTS.unknown;
  return <span className={`tone-${known.tone}`} style={{ fontWeight: 600 }}>{known.label}</span>;
}

const STATUS_TONE = { open: "bad", investigating: "high", closed: "ok", acknowledged: "info", risk_accepted: "muted", resolved: "ok" };

export function Status({ value, labels, badge = false }) {
  return <span className={`${badge ? "badge " : ""}tone-${STATUS_TONE[value] || "plain"}`} style={{ fontWeight: 500 }}>{labels[value] || value}</span>;
}

export function Pills({ options, value, onChange, label }) {
  return (
    <div className="pills" role="group" aria-label={label}>
      {options.map((option) => (
        <button key={option.id} type="button" aria-pressed={value === option.id}
          className={`pill${value === option.id ? " on" : ""}`} onClick={() => onChange(option.id)}>
          {option.label}{option.count != null && <> <span className="mono">{option.count}</span></>}
        </button>
      ))}
    </div>
  );
}

export function Segment({ options, value, onChange, label }) {
  return (
    <span className="segment" role="group" aria-label={label}>
      {options.map((option) => (
        <button key={option.id} type="button" aria-pressed={value === option.id}
          className={value === option.id ? "on" : ""} onClick={() => onChange(option.id)}>{option.label}</button>
      ))}
    </span>
  );
}

export function Empty({ title, children }) {
  return <div className="empty"><h2>{title}</h2><p className="muted">{children}</p></div>;
}

export function Problem({ error }) {
  return error ? <p className="error" role="alert">{error}</p> : null;
}

export function useLoad(load, deps) {
  const [state, setState] = useState({ data: null, error: "", loading: true });
  const run = useCallback(() => {
    let live = true;
    setState((prior) => ({ ...prior, loading: true }));
    load()
      .then((data) => live && setState({ data, error: "", loading: false }))
      .catch((error) => live && setState({ data: null, error: error.message, loading: false }));
    return () => { live = false; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => run(), [run]);
  return { ...state, reload: run };
}

export function useAction() {
  const [state, setState] = useState({ busy: false, error: "" });
  const run = async (work) => {
    setState({ busy: true, error: "" });
    try {
      const result = await work();
      setState({ busy: false, error: "" });
      return result;
    } catch (error) {
      setState({ busy: false, error: error.message });
      return undefined;
    }
  };
  return { ...state, run, clear: () => setState({ busy: false, error: "" }) };
}
