import { useEffect, useState, useCallback } from "react";
import Topbar from "../components/Topbar.jsx";
import { getScope, authorizeTarget, revokeTarget } from "../lib/api.js";

function Authorization() {
  const [scope, setScope] = useState(null);
  const [error, setError] = useState("");
  const [ip, setIp] = useState("");
  const [ttl, setTtl] = useState(60);
  const [submitting, setSubmitting] = useState(false);
  const [feedback, setFeedback] = useState(null);

  const refresh = useCallback(() => {
    return getScope()
      .then(setScope)
      .catch((err) => setError(err.message || "Failed to load scope"));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function submitGrant(e) {
    e.preventDefault();
    if (!ip.trim()) return;
    setSubmitting(true);
    setFeedback(null);
    try {
      const res = await authorizeTarget(ip.trim(), Number(ttl));
      setFeedback({
        ok: res.allowed,
        text: res.allowed
          ? `Granted ${res.ip} for ${ttl} minute(s)`
          : res.reason || "Grant rejected",
      });
      if (res.allowed) setIp("");
      await refresh();
    } catch (err) {
      setFeedback({ ok: false, text: err.message || "Request failed" });
    } finally {
      setSubmitting(false);
    }
  }

  async function handleRevoke(targetIp) {
    try {
      await revokeTarget(targetIp);
      await refresh();
    } catch (err) {
      setFeedback({ ok: false, text: err.message || "Revoke failed" });
    }
  }

  const grants = scope?.active_grants || [];
  const standing = scope?.standing_scope || [];

  return (
    <div className="flex-1 flex flex-col min-w-0">
      <Topbar
        title="Authorization"
        subtitle="Every active check is gated by an explicit, audited authorization"
      />
      <div className="flex-1 overflow-auto p-6 space-y-6">
        {scope?.unrestricted && (
          <div className="rounded-lg border border-alert-crit/40 bg-alert-crit/10 px-4 py-3 text-[12px] text-alert-crit">
            Unrestricted mode is enabled — active checks are authorized against
            any target. Every scan is still recorded in the audit log.
          </div>
        )}

        {error && (
          <div className="rounded-lg border border-alert-crit/40 bg-alert-crit/10 px-3 py-2 text-[12px] text-alert-crit">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-[360px_1fr] gap-6">
          <form onSubmit={submitGrant} className="panel p-4 h-fit space-y-4">
            <div>
              <h3 className="font-display font-600 text-[13px] text-mist-100">
                Issue a grant
              </h3>
              <p className="text-[12px] text-mist-300 mt-1 leading-relaxed">
                Authorizes active checks — Nmap, TLS retrieval, and MCP
                verification — against a single host for a bounded window.
              </p>
            </div>

            <div>
              <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">
                IP address
              </label>
              <input
                value={ip}
                onChange={(e) => setIp(e.target.value)}
                placeholder="203.0.113.10"
                className="w-full rounded-lg border border-edge bg-ink-800 px-3 py-2 text-[13px] font-mono text-mist-100 placeholder:text-mist-300/50 focus:outline-none focus:border-signal/50"
              />
            </div>

            <div>
              <label className="block text-[11px] uppercase tracking-[0.14em] text-mist-300 mb-1.5">
                Duration (minutes)
              </label>
              <input
                type="number"
                min={1}
                max={1440}
                value={ttl}
                onChange={(e) => setTtl(e.target.value)}
                className="w-full rounded-lg border border-edge bg-ink-800 px-3 py-2 text-[13px] font-mono text-mist-100 focus:outline-none focus:border-signal/50"
              />
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-lg bg-signal/90 hover:bg-signal text-ink-900 font-600 text-[13px] py-2.5 transition-colors disabled:opacity-50"
            >
              {submitting ? "Authorizing…" : "Authorize target"}
            </button>

            {feedback && (
              <div
                className={`rounded-lg border px-3 py-2 text-[12px] ${
                  feedback.ok
                    ? "border-signal/30 bg-signal/10 text-signal"
                    : "border-alert-crit/40 bg-alert-crit/10 text-alert-crit"
                }`}
              >
                {feedback.text}
              </div>
            )}
          </form>

          <div className="space-y-5">
            <div className="panel p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-display font-600 text-[13px] text-mist-100">
                  Active grants
                </h3>
                <span className="text-[11px] font-mono text-mist-300">
                  {grants.length}
                </span>
              </div>
              {grants.length === 0 ? (
                <p className="text-[12px] text-mist-300">
                  No per-target grants are active. Active checks will only run
                  against hosts inside the standing scope.
                </p>
              ) : (
                <div className="space-y-2">
                  {grants.map((g) => (
                    <div
                      key={g.ip}
                      className="flex items-center justify-between rounded-lg border border-edge bg-ink-800/50 px-3 py-2"
                    >
                      <div>
                        <div className="font-mono text-[13px] text-mist-100">
                          {g.ip}
                        </div>
                        <div className="text-[11px] text-mist-300 mt-0.5">
                          expires {new Date(g.expires).toLocaleString()}
                        </div>
                      </div>
                      <button
                        onClick={() => handleRevoke(g.ip)}
                        className="text-[11px] px-2.5 py-1.5 rounded-md border border-alert-crit/30 text-alert-crit hover:bg-alert-crit/10 transition-colors"
                      >
                        Revoke
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="panel p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-display font-600 text-[13px] text-mist-100">
                  Standing scope
                </h3>
                <span className="text-[11px] font-mono text-mist-300">
                  {standing.length}
                </span>
              </div>
              {standing.length === 0 ? (
                <p className="text-[12px] text-mist-300">
                  No CIDRs are pre-authorized. Set{" "}
                  <code className="text-mist-200">AUTHORIZED_CIDRS</code> in{" "}
                  <code className="text-mist-200">.env</code> to always allow
                  active checks against specific ranges.
                </p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {standing.map((cidr) => (
                    <span
                      key={cidr}
                      className="font-mono text-[12px] text-mist-200 rounded-md border border-edge bg-ink-800/50 px-2.5 py-1"
                    >
                      {cidr}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Authorization;
