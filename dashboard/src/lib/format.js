const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const pad = (n) => String(n).padStart(2, "0");

export function when(iso) {
  if (!iso) return "—";
  const text = String(iso);
  const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(text) || text.length <= 10 ? text : `${text}Z`);
  if (Number.isNaN(d.getTime())) return "—";
  return `${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}, ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function plural(count, word) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

export const SEVERITY_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 };

export function worst(findings) {
  return findings.reduce((top, f) => (!top || SEVERITY_RANK[f.severity] > SEVERITY_RANK[top] ? f.severity : top), null);
}

export const VERDICTS = {
  match: { label: "Match", tone: "ok" },
  subset: { label: "Subset", tone: "plain" },
  deviation: { label: "Deviation", tone: "bad" },
  unknown: { label: "Unknown", tone: "muted" },
};

export const OUTCOMES = {
  read: "Tool list read",
  auth_required: "Authentication required",
  no_mcp: "No MCP server answered",
  unauthorized: "Outside the authorized scope",
};

export function verdictOf(scan) {
  if (!scan) return { label: "Not scanned", tone: "muted" };
  if (scan.outcome !== "read") return { label: OUTCOMES[scan.outcome] || scan.outcome, tone: "muted" };
  return VERDICTS[scan.verdict] || VERDICTS.unknown;
}

export function shortRelease(release) {
  return (release || "").replace("@modelcontextprotocol/", "");
}

export const FINDING_STATUS = {
  open: "Open",
  acknowledged: "Acknowledged",
  risk_accepted: "Risk accepted",
  resolved: "Resolved",
};

export const CASE_STATUS = { open: "Open", investigating: "Investigating", closed: "Closed" };

export const CLOSURES = {
  fixed: "True positive, fixed at source",
  mitigated: "True positive, mitigated",
  benign_positive: "Benign positive, expected behaviour",
  false_positive: "False positive",
  risk_accepted: "Risk accepted",
  duplicate: "Duplicate",
  inconclusive: "Undetermined, not enough evidence",
  out_of_scope: "Out of scope",
  other: "Other",
};

export const RULES = {
  deviation: "Differs from published release",
  command_execution: "Command execution without authentication",
  manual: "Opened by hand",
};

export const ACTIONS = {
  signed_in: "Signed in",
  sign_in_failed: "Sign-in refused",
  platform_switched: "Platform switched",
  registry_server_added: "Server added from the registry",
  server_attested: "Ownership statement recorded",
  schedule_set: "Schedule changed",
  report_exported: "Report downloaded",
  briefing: "Briefing written",
  finding_status: "Finding status changed",
  case_opened: "Case opened by hand",
  case_assigned: "Case assigned",
  case_status: "Case status changed",
  case_closed: "Case closed",
  case_reopened: "Case reopened",
  case_note: "Case note added",
  case_rule: "Case rule changed",
  member_added: "Member added",
  member_role: "Member role changed",
  member_removed: "Member removed",
  privacy_settings_update: "Assistant settings changed",
  evidence_exported: "Signed evidence exported",
  copilot_query: "Assistant asked",
};

export function actionLabel(action) {
  return ACTIONS[action] || action.replace(/_/g, " ");
}

export function describeChange(change) {
  if (!change || change.added == null) return "Declarations changed";
  const parts = [];
  if (change.redefined.length) parts.push(`${change.redefined.length} redefined`);
  if (change.added.length) parts.push(`${change.added.length} added`);
  if (change.removed.length) parts.push(`${change.removed.length} removed`);
  return parts.join(", ") || "Declarations changed";
}

export function provenanceLine(page) {
  const p = page.provenance;
  if (!p) return "";
  const release = `${p.package}@${(p.versions || []).slice(-1)[0]}`;
  const count = page.tools.length;
  if (p.verdict === "match") return `All ${plural(count, "tool")} are identical to ${release}.`;
  if (p.verdict === "subset") return `All ${plural(count, "tool")} are identical to ${release}; ${p.absent.length} of its tools are absent.`;
  if (p.verdict === "deviation") return `${p.redefined.length} redefined, ${p.added.length} added against ${release}.`;
  return "No published package matches these tools. Raqeeb makes no claim about origin.";
}

export function windowParams(value) {
  if (!value || value.mode === "any") return {};
  if (value.mode === "day" && value.day) {
    const start = new Date(`${value.day}T00:00`);
    const end = new Date(start.getTime() + 24 * 3600 * 1000);
    return { since: start.toISOString(), until: end.toISOString() };
  }
  if (value.mode === "range") {
    const out = {};
    if (value.from) out.since = new Date(value.from).toISOString();
    if (value.to) out.until = new Date(value.to).toISOString();
    return out;
  }
  return {};
}
