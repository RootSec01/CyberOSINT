// Standing state of every exposure on one asset.
//
// The Changes card answers "what moved between the last two scans". This one
// answers the question that outlives any single scan: what is open right now,
// what was proven closed and by which scan, and what came back after being
// closed. A closure is only ever recorded by a scan that actually observed the
// surface — see exposure_state.py — so an empty result here means "nothing
// recorded", never "nothing wrong".

const STATE_STYLE = {
  regressed: {
    chip: "↺ returned",
    cls: "text-alert-crit border-alert-crit/40 bg-alert-crit/10",
    dot: "bg-alert-crit",
  },
  open: {
    chip: "● open",
    cls: "text-alert-high border-alert-high/40 bg-alert-high/10",
    dot: "bg-alert-high",
  },
  remediated: {
    chip: "✓ closed",
    cls: "text-signal border-signal/40 bg-signal/10",
    dot: "bg-signal",
  },
};

const KIND_LABEL = { tool: "tool", auth: "access", cve: "vulnerability" };

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

function shortHash(value) {
  if (!value) return "";
  return value.length > 14 ? `${value.slice(0, 12)}…` : value;
}

export function lifecycleVerdict(summary) {
  const s = summary || {};
  if (s.regressed > 0)
    return { label: "Exposure returned after remediation", icon: "↺",
             cls: "text-alert-crit border-alert-crit/50 bg-alert-crit/10" };
  if (s.exposed_now > 0)
    return { label: `${s.exposed_now} exposure${s.exposed_now > 1 ? "s" : ""} open`, icon: "●",
             cls: "text-alert-high border-alert-high/50 bg-alert-high/10" };
  if (s.remediated > 0)
    return { label: "All recorded exposures proven closed", icon: "✓",
             cls: "text-signal border-signal/50 bg-signal/10" };
  return { label: "Nothing recorded yet", icon: "—",
           cls: "text-mist-300 border-edge bg-ink-800/50" };
}

// What proved the current state, said plainly rather than as a field dump.
function evidenceLine(e) {
  if (e.state === "remediated") {
    const when = timeAgo(e.remediated_at);
    const run = e.evidence_run_id ? ` by scan ${e.evidence_run_id}` : "";
    return `closed${when ? " " + when : ""}${run}`;
  }
  if (e.state === "regressed") {
    const closed = e.remediated_at ? `closed ${timeAgo(e.remediated_at)}` : "closed earlier";
    const back = e.regressed_at ? `seen again ${timeAgo(e.regressed_at)}` : "seen again";
    const times = e.times_regressed > 1 ? ` · ${e.times_regressed}× so far` : "";
    return `${closed} → ${back}${times}`;
  }
  const first = e.first_seen_at ? `first seen ${timeAgo(e.first_seen_at)}` : "";
  const last = e.last_seen_at ? `confirmed ${timeAgo(e.last_seen_at)}` : "";
  return [first, last].filter(Boolean).join(" · ");
}

function ExposureRow({ exposure }) {
  const style = STATE_STYLE[exposure.state] || STATE_STYLE.open;
  return (
    <li className="flex items-start justify-between gap-3 py-2 border-b border-edge/60 last:border-0">
      <div className="min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-[12.5px] text-mist-100 truncate">{exposure.label}</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded border border-edge text-mist-300">
            {KIND_LABEL[exposure.kind] || exposure.kind}
          </span>
          {exposure.detail && (
            <span className="font-mono text-[11px] text-mist-300">{exposure.detail}</span>
          )}
        </div>
        <div className="text-[11px] text-mist-300 mt-0.5">
          {evidenceLine(exposure)}
          {exposure.evidence_fingerprint && (
            <span className="font-mono"> · manifest {shortHash(exposure.evidence_fingerprint)}</span>
          )}
        </div>
      </div>
      <span className={`shrink-0 text-[10px] px-2 py-0.5 rounded-md border ${style.cls}`}>
        {style.chip}
        {exposure.state === "regressed" && exposure.times_regressed > 1
          ? ` ×${exposure.times_regressed}` : ""}
      </span>
    </li>
  );
}

function Group({ title, items, dotCls }) {
  if (!items.length) return null;
  return (
    <div>
      <div className="text-[11px] text-mist-300 mb-1 flex items-center gap-1.5">
        <span className={`h-1.5 w-1.5 rounded-full ${dotCls}`} /> {title}
      </div>
      <ul>
        {items.map((e) => <ExposureRow key={e.key} exposure={e} />)}
      </ul>
    </div>
  );
}

export function ExposureLifecycleCard({ data }) {
  if (!data) {
    return (
      <div className="rounded-lg border border-edge bg-ink-900/60 px-3 py-2.5 text-[12px] text-mist-300">
        Loading exposure history…
      </div>
    );
  }
  if (data.error) {
    return (
      <div className="rounded-lg border border-alert-med/30 bg-alert-med/5 px-3 py-2.5 text-[12px] text-alert-med">
        {data.error}
      </div>
    );
  }

  const exposures = Array.isArray(data.exposures) ? data.exposures : [];
  const summary = data.summary || {};
  if (exposures.length === 0) {
    return (
      <div className="rounded-lg border border-edge bg-ink-900/60 px-3 py-2.5 text-[12px] text-mist-300">
        No exposure recorded for this asset yet. Run a scan — tracking starts
        with the first scan that observes the target.
      </div>
    );
  }

  const verdict = lifecycleVerdict(summary);
  const returned = exposures.filter((e) => e.state === "regressed");
  const open = exposures.filter((e) => e.state === "open");
  const closed = exposures.filter((e) => e.state === "remediated");

  return (
    <div className="rounded-lg border border-edge bg-ink-900/60 overflow-hidden">
      <div className={`flex items-center justify-between px-3 py-2 border-b border-edge ${verdict.cls}`}>
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-[13px] leading-none">{verdict.icon}</span>
          <span className="text-[13px] font-600 truncate">{verdict.label}</span>
        </div>
        <span className="text-[11px] font-mono text-mist-300 shrink-0">
          {summary.exposed_now || 0} exposed · {summary.remediated || 0} closed
        </span>
      </div>

      <div className="px-3 py-2.5 space-y-3">
        <Group title="Returned after being closed" items={returned} dotCls="bg-alert-crit" />
        <Group title="Open now" items={open} dotCls="bg-alert-high" />
        <Group title="Proven closed" items={closed} dotCls="bg-signal" />
      </div>

      <div className="px-3 py-2 border-t border-edge text-[11px] text-mist-300">
        A closure is recorded only when a scan actually observed this surface.
        A skipped, unauthorized or unconfirmed scan leaves every state untouched.
      </div>
    </div>
  );
}

export default ExposureLifecycleCard;
