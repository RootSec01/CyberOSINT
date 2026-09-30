const TIER_TONE = {
  OBSERVED: "text-alert-crit border-alert-crit/50",
  DEMONSTRATED: "text-alert-med border-alert-med/50",
  INFERRED: "text-mist-300 border-edge",
};

const SEV_TONE = {
  Critical: "text-alert-crit border-alert-crit/50",
  High: "text-alert-high border-alert-high/50",
  Medium: "text-alert-med border-alert-med/50",
  Low: "text-alert-low border-alert-low/50",
  None: "text-mist-300 border-edge",
};

// Defensible titles — a capability/exposure is not a confirmed vulnerability.
const DETECTOR_LABEL = {
  rce: "Exposed Command-Execution Capability",
  path_traversal: "Potential Unconstrained Filesystem Path",
  secrets_leakage: "Secrets / Credential Exposure",
  auth_bypass: "Unauthenticated Sensitive Capability Exposure",
  prompt_injection: "Prompt-Injection Markers in Declaration",
  tool_poisoning: "Deceptive or Hidden Tool Declaration",
};

// Evidence grading — what was actually established, not over-claimed.
const EVIDENCE_TONE = {
  OBSERVED: "text-signal border-signal/50",       // directly seen
  DEMONSTRATED: "text-alert-med border-alert-med/50",
  INFERRED: "text-mist-300 border-edge",          // reasoned, not confirmed
  VERIFIED: "text-alert-crit border-alert-crit/50",
};

const yesNo = (value) => value === true ? "YES" : value === false ? "NO" : "UNKNOWN";

function SafeBadge({ label, value, good = true }) {
  return (
    <div className="rounded-xl border border-edge bg-ink-700/60 p-4">
      <div className="text-[10px] uppercase tracking-[0.12em] text-mist-300">
        {label}
      </div>
      <div
        className={`mt-1.5 text-xl font-700 ${
          good ? "text-signal" : "text-alert-crit"
        }`}
      >
        {value}
      </div>
    </div>
  );
}

function SafeProofReport({ proof }) {
  if (!proof) return null;
  const sevTone = SEV_TONE[proof.severity] || SEV_TONE.None;
  const safety = proof.safety || {};

  return (
    <div className="space-y-5">
      {/* verdict banner */}
      <div className={`panel p-6 border ${sevTone.split(" ")[1]}`}>
        <div className="flex items-start justify-between gap-6 flex-wrap">
          <div className="min-w-0 flex-1">
            <span
              className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[11px] font-700 uppercase tracking-[0.14em] ${sevTone}`}
            >
              ● {proof.report_schema === "safe-proof-v2" ? proof.exposure_verdict : "LEGACY REPORT — rescan for current evidence grading"}
            </span>
            <h2
              className={`mt-3 font-display font-700 text-[26px] leading-tight ${
                sevTone.split(" ")[0]
              }`}
            >
              {proof.report_schema === "safe-proof-v2" ? proof.exposure_verdict : "LEGACY REPORT — rescan for current evidence grading"}
            </h2>
            <div className="font-mono text-[13px] text-mist-300 mt-1">
              {proof.target}
            </div>
          </div>

          {typeof proof.exposure_index === "number" && (
            <div className="text-center shrink-0">
              <div
                className={`font-display font-800 text-5xl leading-none ${
                  sevTone.split(" ")[0]
                }`}
              >
                {proof.exposure_index}
              </div>
              <div className="text-[10px] uppercase tracking-[0.12em] text-mist-300 mt-1">
                heuristic exposure index
              </div>
              {proof.confidence_label && (
                <div className="text-[11px] text-signal mt-1">
                  {proof.confidence_label} ·{" "}
                  {Math.round((proof.confidence || 0) * 100)}%
                </div>
              )}
            </div>
          )}
        </div>

        {proof.attacker_narrative && (
          <p className="text-[13.5px] text-mist-100 mt-4 border-l-2 border-alert-crit pl-3 leading-relaxed">
            {proof.attacker_narrative}
          </p>
        )}
        <p className="text-[12px] text-mist-300 mt-3 border-l-2 border-signal pl-3">
          {proof.summary}
        </p>

        <div className="flex flex-wrap items-center gap-2 mt-4 text-[11px]">
          {proof.exposure_vector && (
            <span className="rounded-md border border-signal/40 bg-signal/10 px-2.5 py-1 font-mono text-signal">
              {proof.exposure_vector}
            </span>
          )}
          <span className="rounded-md border border-edge bg-ink-700 px-2.5 py-1 text-mist-200">
            protocol <b className="text-signal">{proof.protocol_version}</b>
          </span>
          <span className="rounded-md border border-edge bg-ink-700 px-2.5 py-1 text-mist-200">
            via <b className="text-signal">{proof.verification_method}</b>
          </span>
          {proof.manifest_fingerprint && (
            <span className="rounded-md border border-edge bg-ink-700 px-2.5 py-1 text-mist-200 font-mono"
              title="Stable hash of the server's declared surface — changes when a tool, schema or auth posture changes">
              manifest <b className="text-signal">{String(proof.manifest_fingerprint).split(":").pop().slice(0, 10)}</b>
            </span>
          )}
          {proof.steps_to_impact && (
            <span className="rounded-md border border-edge bg-ink-700 px-2.5 py-1 text-mist-200">
              impact in <b className="text-signal">{proof.steps_to_impact}</b> steps
            </span>
          )}
        </div>
      </div>

      {/* safety envelope */}
      <div className="panel p-5">
        <h3 className="text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-4">
          Safety envelope — how this was verified
        </h3>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <SafeBadge label="Production data accessed" value={yesNo(safety.production_data_accessed)} good={safety.production_data_accessed === false} />
          <SafeBadge label="Destructive actions" value={yesNo(safety.destructive_action_performed)} good={safety.destructive_action_performed === false} />
          <SafeBadge label="Dangerous tool invoked" value={yesNo(safety.dangerous_tool_invoked)} good={safety.dangerous_tool_invoked === false} />
          <SafeBadge
            label="Verification"
            value={(safety.verification_method || "").toUpperCase()}
          />
        </div>
      </div>

      {/* attack path */}
      <div className="panel p-5">
        <h3 className="text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-4">
          Evidence and potential impact path — {proof.attack_path?.length || 0} steps · MITRE ATT&CK
        </h3>
        <div className="space-y-3">
          {(proof.attack_path || []).map((s) => {
            const tone = TIER_TONE[s.evidence_tier] || TIER_TONE.INFERRED;
            return (
              <div
                key={s.order}
                className="rounded-lg border border-edge bg-ink-700/40 p-3"
              >
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="font-mono text-[11px] text-mist-300">
                    {String(s.order).padStart(2, "0")}
                  </span>
                  <span className="text-[14px] font-600 text-mist-100">
                    {s.title}
                  </span>
                  <span
                    className={`text-[10px] font-700 tracking-[0.1em] px-2 py-0.5 rounded border ${tone}`}
                  >
                    {s.evidence_tier === "PROVEN" ? "LEGACY PROVEN — unreviewed" : s.evidence_tier}
                  </span>
                </div>
                <div className="text-[12px] text-mist-200 mt-1.5">
                  <span className="font-mono text-signal font-600">
                    {s.technique_id}
                  </span>{" "}
                  {s.technique_name}
                </div>
                <div className="text-[12px] text-mist-300 mt-1">{s.evidence}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* blast radius */}
      {proof.blast_radius?.reachable?.length > 0 && (
        <div className="panel p-5">
          <h3 className="text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-3">
            Potential impact — not verified access
          </h3>
          <div className="flex flex-wrap gap-2">
            {proof.blast_radius.reachable.map((r) => (
              <span
                key={r}
                className="rounded-lg border border-alert-crit/40 bg-alert-crit/10 px-3 py-2 text-[13px] text-mist-100"
              >
                {r}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* MCP threat detectors — the modern MCP vulnerability class */}
      {proof.mcp_findings?.length > 0 && (
        <div className="panel p-5">
          <h3 className="text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1">
            MCP threat detectors — {proof.mcp_findings.length} finding
            {proof.mcp_findings.length === 1 ? "" : "s"} · MITRE ATT&amp;CK · OWASP LLM Top 10
          </h3>
          <p className="text-[11px] text-mist-300 mb-4">
            Passive analysis of declared tools and metadata — nothing was invoked.
          </p>
          <div className="space-y-2.5">
            {proof.mcp_findings.map((f, i) => {
              const tone = SEV_TONE[f.severity] || SEV_TONE.None;
              const evTone = EVIDENCE_TONE[f.evidence_level] || EVIDENCE_TONE.INFERRED;
              const pct = typeof f.confidence === "number"
                ? Math.round(f.confidence * 100) : null;
              return (
                <div key={f.id + i} className="rounded-lg border border-edge bg-ink-700/40 p-3">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className={`text-[10px] font-700 tracking-[0.1em] px-2 py-0.5 rounded border ${tone}`}>
                      {f.severity}
                    </span>
                    {f.evidence_level && (
                      <span className={`text-[10px] font-700 tracking-[0.1em] px-2 py-0.5 rounded border ${evTone}`}>
                        {f.evidence_level}
                      </span>
                    )}
                    {pct !== null && (
                      <span className="text-[10px] text-mist-300">heuristic confidence {pct}%</span>
                    )}
                    {f.affected_tool && (
                      <span className="font-mono text-[11px] text-mist-300">{f.affected_tool}</span>
                    )}
                    <span className="ml-auto flex items-center gap-1.5">
                      {f.technique_id && (
                        <span className="font-mono text-[10px] text-signal border border-signal/40 rounded px-1.5 py-0.5">
                          {f.technique_id}
                        </span>
                      )}
                      {f.owasp_llm && (
                        <span className="font-mono text-[10px] text-mist-200 border border-edge rounded px-1.5 py-0.5">
                          {f.owasp_llm}
                        </span>
                      )}
                    </span>
                  </div>

                  <div className="text-[13.5px] font-600 text-mist-100 mt-2">
                    {DETECTOR_LABEL[f.category] || f.title}
                  </div>

                  {f.observed_facts?.length > 0 && (
                    <div className="mt-1.5">
                      <div className="text-[10px] uppercase tracking-[0.12em] text-mist-300">What we observed</div>
                      <ul className="mt-1 space-y-0.5">
                        {f.observed_facts.map((fact, k) => (
                          <li key={k} className="text-[12px] text-mist-200">• {fact}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {f.inference && (
                    <div className="text-[12px] text-mist-300 mt-1.5">
                      <span className="text-mist-300/70">Interpretation: </span>{f.inference}
                    </div>
                  )}

                  <div className="flex items-center gap-2 mt-2 flex-wrap text-[10px]">
                    <span className="px-2 py-0.5 rounded border border-signal/40 text-signal">
                      Status: {f.verification_status || "UNKNOWN"}
                    </span>
                  </div>

                  {f.recommendation && (
                    <div className="text-[12px] text-signal/90 mt-2 border-l-2 border-signal/40 pl-2">
                      Fix: {f.recommendation}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* dangerous tools */}
      {proof.dangerous_tools?.length > 0 && (
        <div className="panel p-5">
          <h3 className="text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-3">
            Dangerous capabilities declared (never invoked)
          </h3>
          <div className="space-y-2">
            {proof.dangerous_tools.map((t) => (
              <div
                key={t.name}
                className="flex items-center justify-between rounded-lg border border-edge bg-ink-700/40 px-3 py-2"
              >
                <span className="font-mono text-[13px] text-mist-100">
                  {t.name}
                </span>
                <span className="text-[11px] text-mist-300">
                  {(t.risk_flags || []).join(" · ")}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default SafeProofReport;
