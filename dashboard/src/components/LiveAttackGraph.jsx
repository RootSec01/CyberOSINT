export function escapeEvidence(value) {
  const text = typeof value === "object" ? JSON.stringify(value) : String(value ?? "");
  return text.replace(/[&<>"']/g, (c) => ({"&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"}[c]));
}

import { useRef, useEffect } from "react";
import { scanStreamUrl } from "../lib/api.js";

// Executable Evidence Graph — branching attack graph driven by the live SSE
// stream. Columns: TARGET · AGENT · ACCESS · CAPABILITIES · IMPACT · DOWNSTREAM.
// Each capability owns a lane (impact + downstream on the same row — no false
// vertical sequence). Click any node to trace its verified path and open its
// evidence. Adaptive: any node count stays spaced. Drag to pan, wheel to zoom.
const NS = "http://www.w3.org/2000/svg";
const TONE = { signal: "#2DD4BF", crit: "#FF5C6C", high: "#FF9F45", med: "#FFC94D", low: "#4CC3FF", mist: "#6C7D90" };
const HEADS = { access: "TARGET", agent: "AGENT", step: "ACCESS", cap: "CAPABILITIES", impact: "IMPACT", down: "DOWNSTREAM" };

function short(s, n) { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; }
function tierCol(t) { t = t || ""; return t === "OBSERVED" ? "#FF5C6C" : t.startsWith("DEMO") ? "#FF9F45" : "#6C7D90"; }

function LiveAttackGraph({ host, port, useTls, onDone, onError }) {
  const svgRef = useRef(null), stageRef = useRef(null), idxRef = useRef(null), vecRef = useRef(null);
  const dTitle = useRef(null), dTier = useRef(null), dBody = useRef(null), drawer = useRef(null);

  useEffect(() => {
    const svg = svgRef.current;
    const world = svg.querySelector("#world");
    const edgesG = svg.querySelector("#edges");
    const headsG = svg.querySelector("#heads");
    const partG = svg.querySelector("#particles");
    const nodesG = svg.querySelector("#nodes");
    const el = (n) => document.createElementNS(NS, n);

    const meta = {};            // id -> node data
    const order = [];           // arrival order of ids
    const caps = [];            // capKey lane order
    const pos = {};             // id -> {x,y}
    const domNode = {};         // id -> <g>
    const domEdge = {};         // "from>to" -> <path>
    const edgesModel = [];      // {from,to,cls}
    const headsDrawn = {};
    const halfW = {};   // id -> box half width (for edge anchoring)
    let L = {};

    function computeLayout() {
      const laneCount = Math.max(caps.length, 1);
      const laneGap = laneCount > 8 ? 88 : laneCount > 5 ? 100 : 112;
      const top = 140;
      const H = Math.max(560, top + (laneCount - 1) * laneGap + 130);
      const W = 1440;
      const cy = top + ((laneCount - 1) * laneGap) / 2;
      const laneY = {};
      caps.forEach((c, i) => (laneY[c] = top + i * laneGap));
      L = { W, H, top, laneGap, cy, laneY,
        colX: { access: 120, agent: 300, step: 470, cap: 720, impact: 1000, down: 1250 } };
      svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
      svg.querySelector("#bg").setAttribute("width", W);
      svg.querySelector("#bg").setAttribute("height", H);
    }
    function xy(n) {
      const c = L.colX;
      if (n.kind === "access") return { x: c.access, y: L.cy };
      if (n.kind === "agent") return { x: c.agent, y: L.cy };
      if (n.kind === "step") return { x: c.step, y: L.cy + (n.id === "unauth" ? -46 : 46) };
      if (n.kind === "cap") return { x: c.cap, y: L.laneY[n.capKey] ?? L.cy };
      if (n.kind === "impact") return { x: c.impact, y: L.laneY[n.capKey] ?? L.cy };
      if (n.kind === "down") {
        const sibs = order.filter((id) => meta[id].kind === "down" && meta[id].capKey === n.capKey);
        const idx = Math.max(0, sibs.indexOf(n.id));
        const gap = 44;
        const yc = (L.laneY[n.capKey] ?? L.cy) + (idx - (sibs.length - 1) / 2) * gap;
        return { x: c.down, y: yc };
      }
      return { x: 600, y: L.cy };
    }
    function head(kind) {
      if (headsDrawn[kind] || !HEADS[kind]) return; headsDrawn[kind] = true;
      const x = L.colX[kind];
      const t = el("text"); t.setAttribute("class", "g-head"); t.setAttribute("x", x); t.setAttribute("y", 64);
      t.setAttribute("text-anchor", "middle"); t.setAttribute("font-size", "10"); t.textContent = HEADS[kind];
      t.style.opacity = 0; t.style.transition = "opacity .5s";
      const ln = el("line"); ln.setAttribute("x1", x - 62); ln.setAttribute("x2", x + 62);
      ln.setAttribute("y1", 76); ln.setAttribute("y2", 76); ln.setAttribute("stroke", "#33465b");
      ln.style.opacity = 0; ln.style.transition = "opacity .5s";
      headsG.append(t, ln); requestAnimationFrame(() => { t.style.opacity = 1; ln.style.opacity = 0.5; });
    }
    function pathD(fromId, toId) {
      const a = pos[fromId], b = pos[toId];
      const ax = a.x + (halfW[fromId] || 0) + 2;   // leave source at its RIGHT edge
      const bx = b.x - (halfW[toId] || 0) - 2;      // arrive at target LEFT edge
      const dx = bx - ax;
      return `M${ax},${a.y} C${ax + dx * 0.5},${a.y} ${bx - dx * 0.5},${b.y} ${bx},${b.y}`;
    }

    function render() {
      computeLayout();
      // headers for present kinds
      order.forEach((id) => head(meta[id].kind));
      // positions
      order.forEach((id) => (pos[id] = xy(meta[id])));
      // nodes
      order.forEach((id) => {
        const n = meta[id];
        let g = domNode[id];
        if (!g) { g = drawNode(n); domNode[id] = g; nodesG.appendChild(g); }
        g.setAttribute("transform", `translate(${pos[id].x},${pos[id].y})`);
      });
      // edges (draw when both ends exist)
      edgesModel.forEach((e) => {
        if (!pos[e.from] || !pos[e.to]) return;
        const key = e.from + ">" + e.to;
        let p = domEdge[key];
        const isNew = !p;
        if (isNew) { p = makeEdge(e); domEdge[key] = p; edgesG.appendChild(p); }
        p.setAttribute("d", pathD(e.from, e.to));               // final path first
        if (isNew) {
          drawIn(p, e.cls);                                     // then animate its REAL length
          if (e.cls === "attack") {
            const c = el("circle"); c.setAttribute("r", 2.3); c.setAttribute("fill", "#fff"); c.style.opacity = 0.8;
            const m = el("animateMotion"); m.setAttribute("dur", "2.4s"); m.setAttribute("repeatCount", "indefinite");
            m.setAttribute("path", p.getAttribute("d"));
            c.appendChild(m); partG.appendChild(c); p.__mo = m;
          }
        } else {
          // node moved during relayout -> refit the stroke to the new length
          if (e.cls !== "infer") {
            const len = p.getTotalLength();
            p.style.strokeDasharray = len;
            p.style.strokeDashoffset = 0;
          }
          if (p.__mo) p.__mo.setAttribute("path", p.getAttribute("d"));
        }
      });
    }
    function makeEdge(e) {
      const p = el("path"); p.setAttribute("class", "g-edge");
      p.setAttribute("data-from", e.from); p.setAttribute("data-to", e.to); p.setAttribute("data-cls", e.cls);
      p.setAttribute("stroke", e.cls === "attack" ? "url(#gA)" : e.cls === "spine" ? "#2DD4BF" : "#6C7D90");
      p.setAttribute("stroke-width", e.cls === "attack" ? 2.2 : 1.3);
      if (e.cls === "infer") p.setAttribute("stroke-dasharray", "5 5");
      else p.style.strokeDasharray = "none";
      p.style.opacity = e.cls === "tool" ? 0.4 : e.cls === "infer" ? 0.5 : 0.85;
      return p;
    }
    function drawIn(p, cls) {
      if (cls === "infer") return;               // dashed inferred edges stay static
      const len = p.getTotalLength();
      p.style.strokeDasharray = len;
      p.style.strokeDashoffset = len;
      // force reflow so the transition actually runs from full length -> 0
      // eslint-disable-next-line no-unused-expressions
      p.getBoundingClientRect();
      p.style.transition = "stroke-dashoffset .5s ease-out";
      requestAnimationFrame(() => { p.style.strokeDashoffset = 0; });
    }
    function txt(g, s, x, y, a, cls, fs, fill) {
      const t = el("text"); t.setAttribute("class", cls || "g-lbl"); t.setAttribute("x", x); t.setAttribute("y", y);
      t.setAttribute("text-anchor", a || "start"); if (fs) t.setAttribute("font-size", fs); if (fill) t.setAttribute("fill", fill);
      t.textContent = s; g.appendChild(t); return t;
    }
    function drawNode(n) {
      const col = TONE[n.tone] || TONE.mist;
      const g = el("g"); g.setAttribute("class", "g-node"); g.setAttribute("data-id", n.id);
      g.style.opacity = 0; g.style.transition = "opacity .4s"; requestAnimationFrame(() => (g.style.opacity = 1));
      if (n.kind === "access" || n.kind === "agent") {
        const isA = n.kind === "agent"; const c = el("circle"); c.setAttribute("r", isA ? 20 : 17);
        c.setAttribute("fill", isA ? "#111A26" : "url(#gT)"); c.setAttribute("stroke", col); c.setAttribute("stroke-width", 2.3);
        if (isA) c.setAttribute("filter", "url(#soft)"); g.appendChild(c); halfW[n.id] = isA ? 20 : 17;
        txt(g, isA ? "◆" : "◎", 0, 5, "middle", "g-lbl", "14", col);
        txt(g, short(n.label, 20), 0, 42, "middle", "g-lbl", "12");
        if (n.sub) txt(g, n.sub, 0, 56, "middle", "g-sm", "9.5");
      } else if (n.kind === "cap") {
        const lbl = (n.danger ? "⚠ " : "") + n.label; const w = Math.max(120, lbl.length * 7 + 24); halfW[n.id] = w / 2;
        const r = el("rect"); r.setAttribute("x", -w / 2); r.setAttribute("y", -13); r.setAttribute("width", w); r.setAttribute("height", 26); r.setAttribute("rx", 13);
        r.setAttribute("fill", "#111A26"); r.setAttribute("stroke", col); r.setAttribute("stroke-width", 1.3); g.appendChild(r);
        txt(g, lbl, 0, 4, "middle", "g-mono", "11.5");
      } else {
        const compact = n.kind === "down";
        const body = short(n.label, compact ? 20 : 26);
        const w = Math.max(compact ? 150 : 180, body.length * 6.4 + (compact ? 40 : 50));
        const h = compact ? 34 : 44; halfW[n.id] = w / 2;
        const r = el("rect"); r.setAttribute("x", -w / 2); r.setAttribute("y", -h / 2); r.setAttribute("width", w); r.setAttribute("height", h); r.setAttribute("rx", compact ? 8 : 10);
        r.setAttribute("fill", "#111A26"); r.setAttribute("stroke", col); r.setAttribute("stroke-width", 1.5); g.appendChild(r);
        if (n.tid) txt(g, n.tid, -w / 2 + 11, -h / 2 + (compact ? 13 : 15), "start", "g-tid", "9");
        txt(g, body, -w / 2 + 11, -h / 2 + (compact ? 26 : 31), "start", "g-lbl", compact ? "10.5" : "11.5");
        if (n.tier) txt(g, String(n.tier).slice(0, 5), w / 2 - 10, -h / 2 + (compact ? 13 : 15), "end", "g-tier", "8", col);
      }
      g.addEventListener("click", (e) => { e.stopPropagation(); select(n); openEvidence(n); });
      return g;
    }

    // interactive path highlight
    let selected = null;
    const capOf = (n) => n.capKey || (n.kind === "cap" ? n.id : null);
    function pathIds(capKey) {
      const ids = new Set(["target", "mcp", "unauth", "enum"]);
      if (capKey) order.forEach((id) => { if (meta[id].capKey === capKey || id === capKey) ids.add(id); });
      return ids;
    }
    function select(n) {
      const capKey = capOf(n);
      if (selected === capKey) { selected = null; clearHi(); return; }
      selected = capKey; const ids = pathIds(capKey);
      Object.entries(domNode).forEach(([id, g]) => g.classList.toggle("dim", !ids.has(id)));
      Object.values(domEdge).forEach((p) => {
        const on = ids.has(p.getAttribute("data-from")) && ids.has(p.getAttribute("data-to"));
        p.classList.toggle("dim", !on);
        p.style.strokeWidth = on ? (p.getAttribute("data-cls") === "attack" ? 3 : 2) : "";
      });
    }
    function clearHi() {
      Object.values(domNode).forEach((g) => g.classList.remove("dim"));
      Object.values(domEdge).forEach((p) => { p.classList.remove("dim"); p.style.strokeWidth = ""; });
    }
    svg.addEventListener("click", () => { selected = null; clearHi(); });

    // evidence drawer
    function rowHTML(k, v, ok) { return `<div class="edrow"><div class="edk">${k}</div><div class="edv${ok ? " ok" : ""}">${escapeEvidence(v)}</div></div>`; }
    function openEvidence(n) {
      const e = n.evidence || {};
      dTitle.current.textContent = n.label;
      const tier = e.tier;
      dTier.current.innerHTML = (tier
        ? `<span class="tpill" style="color:${tierCol(tier)};border-color:${tierCol(tier)}">${escapeEvidence(tier)}</span>`
        : `<span class="tpill" style="color:#6C7D90;border-color:#1E2C3C">info</span>`)
        + `<span class="tpill" style="color:#2DD4BF;border-color:rgba(45,212,191,.4);margin-left:6px">${escapeEvidence(e.verdict || "")}</span>`;
      let h = `<div style="font-size:11px;color:#6C7D90;margin-bottom:14px">Why is this ${escapeEvidence(tier || "shown")}?</div>`;
      if (e.disc) h += rowHTML("Discovery evidence", e.disc);
      if (e.reach) h += rowHTML("Reachability evidence", e.reach);
      if (e.verify) h += rowHTML("Verification evidence", e.verify, true);
      if (e.canary) h += rowHTML("Reported marker", e.canary, true);
      if (e.action) h += rowHTML("Recorded request", e.action, true);
      if (e.result !== null && e.result !== undefined) h += rowHTML("Observed result", e.result, true);
      if (e.timestamp) h += rowHTML("Timestamp", e.timestamp);
      if (e.target_fingerprint) h += rowHTML("Target fingerprint", e.target_fingerprint);
      if (e.evidence_hash) h += rowHTML("Content checksum", e.evidence_hash, true);
      if (e.notDone) h += `<div class="edrow"><div class="edk">What was NOT done</div>` +
        e.notDone.map((x) => `<div class="edv ok" style="margin-bottom:6px">${escapeEvidence(x)}</div>`).join("") + `</div>`;
      dBody.current.innerHTML = h; drawer.current.style.transform = "none";
    }

    // pan + zoom
    const V = { x: 0, y: 0, k: 1 };
    const apply = () => world.setAttribute("transform", `translate(${V.x},${V.y}) scale(${V.k})`);
    let drag = false, sx = 0, sy = 0, ox = 0, oy = 0;
    const down = (e) => { drag = true; svg.style.cursor = "grabbing"; sx = e.clientX; sy = e.clientY; ox = V.x; oy = V.y; };
    const up = () => { drag = false; svg.style.cursor = "grab"; };
    const mv = (e) => { if (drag) { V.x = ox + (e.clientX - sx); V.y = oy + (e.clientY - sy); apply(); } };
    const wh = (e) => {
      e.preventDefault(); const rect = svg.getBoundingClientRect(); const sf = svg.viewBox.baseVal.width / rect.width;
      const mx = (e.clientX - rect.left) * sf, my = (e.clientY - rect.top) * sf;
      const nk = Math.min(2.6, Math.max(0.4, V.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12)));
      V.x = mx - (mx - V.x) * (nk / V.k); V.y = my - (my - V.y) * (nk / V.k); V.k = nk; apply();
    };
    svg.style.cursor = "grab";
    svg.addEventListener("mousedown", down); window.addEventListener("mouseup", up);
    window.addEventListener("mousemove", mv); svg.addEventListener("wheel", wh, { passive: false });
    const resetBtn = svg.closest(".panel").querySelector("[data-reset]");
    if (resetBtn) resetBtn.onclick = () => { V.x = 0; V.y = 0; V.k = 1; apply(); };

    // consume SSE
    const es = new EventSource(scanStreamUrl(host, port, useTls));
    es.onmessage = (evt) => {
      let ev; try { ev = JSON.parse(evt.data); } catch { return; }
      if (ev.type === "stage") { if (stageRef.current) stageRef.current.textContent = ev.message; }
      else if (ev.type === "node") {
        if (meta[ev.id]) return;
        meta[ev.id] = ev; order.push(ev.id);
        if (ev.kind === "cap" && !caps.includes(ev.id)) caps.push(ev.id);
        if (ev.parent && ev.edge) edgesModel.push({ from: ev.parent, to: ev.id, cls: ev.edge });
        render();
      } else if (ev.type === "done") {
        es.close(); const r = ev.result || {};
        if (idxRef.current && typeof r.exposure_index === "number") idxRef.current.textContent = r.exposure_index;
        if (vecRef.current && r.exposure_vector) { vecRef.current.textContent = r.exposure_vector; vecRef.current.style.opacity = 1; }
        if (stageRef.current) stageRef.current.textContent = r.exposure_verdict || "Scan complete";
        render(); onDone && onDone(r);
      } else if (ev.type === "error") { es.close(); onError && onError(ev.message); }
    };
    es.onerror = () => { es.close(); onError && onError("stream disconnected"); };

    return () => {
      es.close(); svg.removeEventListener("mousedown", down); window.removeEventListener("mouseup", up);
      window.removeEventListener("mousemove", mv); svg.removeEventListener("wheel", wh);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [host, port, useTls]);

  return (
    <div className="panel overflow-hidden relative">
      <style>{`
        .g-node{cursor:pointer}
        .g-edge{fill:none;stroke-linecap:round;transition:opacity .25s,stroke-width .25s}
        .g-node .dim,.dim{opacity:.13}
        .g-head{letter-spacing:.18em;fill:#8496a8;font-weight:700}
        .g-lbl{font-weight:600;fill:#E8EEF6}
        .g-sm{fill:#6C7D90;font-family:ui-monospace,monospace}
        .g-tid{fill:#2DD4BF;font-family:ui-monospace,monospace;font-weight:600}
        .g-tier{font-weight:700;letter-spacing:.5px}
        .g-mono{fill:#E8EEF6;font-family:ui-monospace,monospace}
        .edrow{margin-bottom:13px}
        .edk{font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;color:#6C7D90;margin-bottom:4px}
        .edv{font-size:12px;color:#E8EEF6;font-family:ui-monospace,monospace;word-break:break-all;background:#111A26;border:1px solid #1E2C3C;border-radius:7px;padding:7px 9px}
        .edv.ok{border-color:rgba(45,212,191,.4)}
        .tpill{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.1em;padding:3px 9px;border-radius:6px;border:1px solid}
      `}</style>
      <div className="flex items-center justify-between px-4 py-3 border-b border-edge">
        <div className="flex items-center gap-2.5">
          <span className="h-2 w-2 rounded-full bg-signal animate-pulse" />
          <span ref={stageRef} className="text-[12px] text-mist-200 font-mono">Connecting…</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[11px] text-mist-300 hidden sm:inline">click a node for evidence</span>
          <button data-reset className="text-[11px] px-2.5 py-1 rounded-md border border-edge text-mist-300 hover:text-mist-100 hover:bg-ink-600/50 transition-colors">⌖ Reset</button>
          <div className="flex items-center gap-2 border border-edge rounded-lg px-3 py-1 bg-ink-700">
            <b ref={idxRef} className="text-[18px] font-800 text-alert-crit leading-none">—</b>
            <span className="text-[9px] uppercase tracking-[0.12em] text-mist-300 leading-tight">exposure<br />index</span>
          </div>
        </div>
      </div>
      <div className="relative">
        <svg ref={svgRef} preserveAspectRatio="xMidYMid meet" style={{ width: "100%", height: "560px", display: "block" }}>
          <defs>
            <pattern id="gGrid" width="38" height="38" patternUnits="userSpaceOnUse">
              <path d="M38 0H0V38" fill="none" stroke="rgba(45,212,191,0.05)" strokeWidth="1" /></pattern>
            <linearGradient id="gA" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stopColor="#FF9F45" /><stop offset="1" stopColor="#FF5C6C" /></linearGradient>
            <radialGradient id="gT"><stop offset="0" stopColor="#2DD4BF" /><stop offset="1" stopColor="#0d7a6d" /></radialGradient>
            <filter id="soft" x="-80%" y="-80%" width="260%" height="260%"><feGaussianBlur stdDeviation="4" result="b" /><feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
          </defs>
          <rect id="bg" x="0" y="0" width="100%" height="100%" fill="url(#gGrid)" />
          <g id="world"><g id="edges" /><g id="heads" /><g id="particles" /><g id="nodes" /></g>
        </svg>
        <div ref={vecRef} className="absolute right-3 bottom-3 font-mono text-[11px] text-signal border border-signal/35 rounded-lg px-3 py-1.5"
          style={{ background: "rgba(45,212,191,.08)", opacity: 0 }} />
      </div>
      {/* evidence drawer */}
      <div ref={drawer} className="absolute top-0 right-0 h-full w-[360px] max-w-[85%] bg-ink-800 border-l border-edge flex flex-col"
        style={{ transform: "translateX(100%)", transition: "transform .28s cubic-bezier(.2,.8,.2,1)", boxShadow: "-20px 0 50px rgba(0,0,0,.4)", zIndex: 5 }}>
        <div className="px-4 py-4 border-b border-edge relative">
          <span onClick={() => (drawer.current.style.transform = "translateX(100%)")} className="absolute top-3 right-4 cursor-pointer text-mist-300 text-lg">✕</span>
          <div ref={dTitle} className="font-700 text-[15px] pr-6 text-mist-100">—</div>
          <div ref={dTier} className="mt-2" />
        </div>
        <div ref={dBody} className="px-4 py-4 overflow-auto flex-1" />
      </div>
    </div>
  );
}

export default LiveAttackGraph;
