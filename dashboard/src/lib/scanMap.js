import { SEVERITY_RANK, VERDICTS, plural, provenanceLine, shortRelease, worst } from "./format.js";

export const COLUMNS = [
  { title: "TARGET", x: 24 },
  { title: "SERVER", x: 288 },
  { title: "ACCESS AND PROVENANCE", x: 552 },
  { title: "TOOLS", x: 876 },
  { title: "POTENTIAL IMPACT", x: 1256 },
];
export const NODE_WIDTH = 220;
export const NODE_HEIGHT = 76;
export const MAP_WIDTH = 1500;
export const LAST_STAGE = 6;
const ROW = 96;
const TOP = 72;
const SHOWN_TOOLS = 5;
const SHOWN_IMPACTS = 4;

const IMPACTS = {
  rce: "Command execution on the host",
  path_traversal: "Host filesystem reachable",
  secrets_leakage: "Credentials exposed",
  tool_poisoning: "Agent follows planted text",
  prompt_injection: "Agent instructions overridden",
};

const SEVERITY_TONE = { Critical: "crit", High: "high", Medium: "med", Low: "muted" };
const changed = (tool) => tool.status === "redefined" || tool.status === "added";

export function buildScanMap(page) {
  const byReference = Object.fromEntries(page.findings.map((f) => [f.reference, f]));
  const toolFindings = (tool) => tool.findings.map((reference) => byReference[reference]).filter(Boolean);
  const flagged = page.tools
    .filter((tool) => tool.findings.length || changed(tool))
    .sort((a, b) => Number(changed(b)) - Number(changed(a))
      || (SEVERITY_RANK[worst(toolFindings(b))] || 0) - (SEVERITY_RANK[worst(toolFindings(a))] || 0)
      || a.name.localeCompare(b.name));
  const shown = flagged.slice(0, SHOWN_TOOLS);
  const rest = page.tools.length - shown.length;
  const categories = [];
  shown.forEach((tool) => toolFindings(tool).forEach((f) => {
    if (IMPACTS[f.category] && !categories.includes(f.category)) categories.push(f.category);
  }));
  const impacts = categories.slice(0, SHOWN_IMPACTS);
  const access = page.findings.find((f) => !f.tool && f.category === "open_capability");
  const verdict = page.provenance ? page.provenance.verdict : "unknown";
  const compared = verdict !== "unknown";
  const scan = page.read_scan;

  const counts = [1, 1, 2 + (compared ? 1 : 0), shown.length + (rest > 0 ? 1 : 0), impacts.length];
  const rows = Math.max(...counts);
  const height = TOP + rows * ROW + 16;
  const top = (column, index) => TOP + ((rows - counts[column]) * ROW) / 2 + index * ROW + (ROW - NODE_HEIGHT) / 2;

  const nodes = [];
  const edges = [];
  const add = (id, column, index, stage, node) => nodes.push({
    id, x: COLUMNS[column].x, y: top(column, index), stage, tier: "OBSERVED", code: "", sub: "",
    tone: "line", dashed: false, lines: [], ...node,
  });
  const join = (from, to, stage, tone = "edge", dashed = false) => edges.push({ from, to, stage, tone, dashed });

  add("target", 0, 0, 1, {
    title: page.endpoint, sub: "No credential sent", tier: "TARGET", tone: "ok",
    lines: [`Endpoint ${page.endpoint}.`, "Raqeeb sends the handshake and asks for the tool list. It never calls a tool."],
  });
  add("server", 1, 0, 2, {
    title: "MCP server", sub: "Handshake answered", tone: "ok",
    lines: ["The endpoint answered the MCP handshake.", `Scan ${scan.reference}.`],
  });
  join("target", "server", 2, "ok");
  const slot = compared ? { release: 0, list: 1, auth: 2 } : { list: 0, auth: 1 };
  add("auth", 2, slot.auth, 3, access ? {
    title: "No authentication requested", sub: `${plural(page.flagged_tools, "tool")} flagged`, code: access.technique_id || "",
    tone: "crit", lines: access.observed_facts, inference: access.inference, fix: access.recommendation, finding: access.reference,
  } : {
    title: page.auth_required ? "Authentication requested" : "No authentication requested",
    sub: "Access check", tone: page.auth_required ? "ok" : "high",
    lines: [page.auth_required ? "The server asked for a credential." : "The tool list was read without a credential."],
  });
  join("server", "auth", 3, access ? "crit" : "edge");
  add("list", 2, slot.list, 3, {
    title: "Tool list read", sub: `${plural(page.tools.length, "declaration")}`, tone: "info",
    lines: [`${plural(page.tools.length, "tool declaration")} read.`, `Declarations fingerprint ${(scan.declarations || "").slice(0, 12)}.`],
  });
  join("server", "list", 3);
  if (compared) {
    const tone = { ok: "ok", bad: "crit", plain: "line", muted: "line" }[VERDICTS[verdict].tone];
    add("release", 2, slot.release, 5, {
      title: `Published release: ${VERDICTS[verdict].label}`, sub: shortRelease(scan.release), tone,
      lines: [provenanceLine(page), page.provenance.library
        ? `Reference library: ${page.provenance.library.packages} packages, ${page.provenance.library.releases} releases.` : ""].filter(Boolean),
      openTools: verdict === "deviation",
    });
    join("list", "release", 5, tone === "line" ? "edge" : tone);
  }
  shown.forEach((tool, index) => {
    const found = toolFindings(tool);
    const top1 = worst(found);
    const tone = changed(tool) ? "crit" : (top1 ? SEVERITY_TONE[top1] : "info");
    const hidden = tool.differences.length ? "Description differs from the published release." : "";
    add(`tool:${tool.name}`, 3, index, 4, {
      title: tool.name, mono: true,
      sub: changed(tool) ? (tool.status === "redefined" ? "Redefined against release" : "Not in release") : plural(found.length, "finding"),
      tier: changed(tool) ? "CHANGED" : (found[0] ? found[0].evidence_level : "OBSERVED"),
      code: found[0] ? found[0].technique_id || "" : "", tone,
      lines: found.map((f) => `${f.severity} · ${f.title}`).concat(hidden ? [hidden] : []),
      tool: tool.name, openTools: true,
    });
    join("list", `tool:${tool.name}`, 4, tone === "info" ? "edge" : tone);
    if (changed(tool) && compared) join("release", `tool:${tool.name}`, 5, "crit");
  });
  if (rest > 0) {
    add("rest", 3, shown.length, 4, {
      title: `+${plural(rest, "more tool")}`, sub: "Open the Tools tab",
      lines: [`${plural(rest, "other tool")} declared.`], openTools: true,
    });
    join("list", "rest", 4);
  }
  impacts.forEach((category, index) => {
    const related = [];
    let sample = null;
    shown.forEach((tool) => toolFindings(tool).forEach((f) => {
      if (f.category !== category) return;
      if (!related.includes(tool.name)) related.push(tool.name);
      sample = sample || f;
    }));
    add(`impact:${category}`, 4, index, 6, {
      title: IMPACTS[category], sub: `Through ${plural(related.length, "tool")}`, tier: "INFERRED",
      code: sample.technique_id || "", dashed: true, tone: "muted",
      lines: [`Reasoned from ${related.join(", ")}. Nothing was run.`], inference: sample.inference, fix: sample.recommendation,
    });
    related.forEach((name) => join(`tool:${name}`, `impact:${category}`, 6, "muted", true));
  });

  const at = Object.fromEntries(nodes.map((node) => [node.id, node]));
  const placed = nodes.filter((node) => node.id.startsWith("impact:"));
  placed.forEach((node) => {
    const sources = edges.filter((edge) => edge.to === node.id).map((edge) => at[edge.from].y);
    node.y = sources.reduce((sum, y) => sum + y, 0) / sources.length;
  });
  placed.sort((a, b) => a.y - b.y);
  const floor = TOP + (ROW - NODE_HEIGHT) / 2;
  const ceiling = height - 16 - NODE_HEIGHT - (ROW - NODE_HEIGHT) / 2;
  placed.forEach((node, index) => {
    node.y = Math.max(node.y, floor, index ? placed[index - 1].y + ROW : floor);
  });
  for (let index = placed.length - 1; index >= 0; index -= 1) {
    const limit = index === placed.length - 1 ? ceiling : placed[index + 1].y - ROW;
    if (placed[index].y > limit) placed[index].y = limit;
  }
  const lateral = edges.filter((edge) => at[edge.from].x !== at[edge.to].x);
  const spread = (key, farEnd) => {
    const groups = {};
    lateral.forEach((edge) => (groups[edge[key]] = groups[edge[key]] || []).push(edge));
    Object.values(groups).forEach((list) => list
      .sort((a, b) => at[farEnd(a)].y - at[farEnd(b)].y || at[farEnd(a)].x - at[farEnd(b)].x)
      .forEach((edge, index) => { edge[`${key}Port`] = (index + 1) / (list.length + 1); }));
  };
  spread("from", (edge) => edge.to);
  spread("to", (edge) => edge.from);
  const port = (node, share) => node.y + 16 + (NODE_HEIGHT - 32) * share;
  edges.forEach((edge) => {
    const a = at[edge.from];
    const b = at[edge.to];
    if (a.x === b.x) {
      const x = a.x + NODE_WIDTH / 2;
      const [upper, lower] = a.y < b.y ? [a, b] : [b, a];
      edge.d = `M${x} ${upper.y + NODE_HEIGHT} L${x} ${lower.y}`;
      return;
    }
    const x1 = a.x + NODE_WIDTH;
    const x2 = b.x;
    const y1 = port(a, edge.fromPort);
    const y2 = port(b, edge.toPort);
    const reach = (x2 - x1) * 0.45;
    edge.d = `M${x1} ${y1} C${x1 + reach} ${y1},${x2 - reach} ${y2},${x2} ${y2}`;
  });
  return { nodes, edges, height, initial: verdict === "deviation" ? "release" : "auth" };
}

const cross = (a, b) => (a.y1 - b.y1) * (a.y2 - b.y2) < 0;

export function crossings(map) {
  const at = Object.fromEntries(map.nodes.map((node) => [node.id, node]));
  const spans = map.edges.filter((edge) => at[edge.from].x !== at[edge.to].x).map((edge) => {
    const [, x1, y1] = edge.d.match(/^M([\d.]+) ([\d.]+)/);
    const end = edge.d.trim().split(/[ ,]/).slice(-2).map(Number);
    return { x1: Number(x1), y1: Number(y1), x2: end[0], y2: end[1] };
  });
  let count = 0;
  spans.forEach((a, i) => spans.slice(i + 1).forEach((b) => {
    if (a.x1 === b.x1 && a.x2 === b.x2 && cross(a, b)) count += 1;
  }));
  return count;
}
