import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { COLUMNS, LAST_STAGE, MAP_WIDTH, buildScanMap } from "../lib/scanMap.js";

export default function ScanMap({ page, replayKey, toolsPath }) {
  const map = useMemo(() => buildScanMap(page), [page]);
  const [stage, setStage] = useState(LAST_STAGE);
  const [picked, setPicked] = useState(map.initial);
  const timer = useRef(null);
  const evidence = useRef(null);

  const pick = (id) => {
    setPicked(id);
    const card = evidence.current;
    if (!card) return;
    card.classList.remove("flash");
    requestAnimationFrame(() => {
      card.classList.add("flash");
      card.scrollIntoView({ behavior: "smooth", block: "center" });
    });
  };

  const replay = () => {
    clearInterval(timer.current);
    setStage(1);
    timer.current = setInterval(() => {
      setStage((current) => {
        if (current + 1 >= LAST_STAGE) clearInterval(timer.current);
        return Math.min(current + 1, LAST_STAGE);
      });
    }, 650);
  };

  useEffect(() => { setPicked(map.initial); }, [map]);
  useEffect(() => {
    if (replayKey) replay();
    return () => clearInterval(timer.current);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [replayKey]);

  const node = map.nodes.find((n) => n.id === picked) || map.nodes[0];

  return (
    <>
      <div className="row">
        <h2 className="grow">Scan map <span className="ref" style={{ fontWeight: 400 }}>{page.read_scan.reference}</span></h2>
        <span className="row small muted"><i style={{ width: 20, height: 12, border: "1px solid var(--muted)", borderRadius: 3 }} />Observed directly</span>
        <span className="row small muted"><i style={{ width: 20, height: 12, border: "1px dashed var(--muted)", borderRadius: 3 }} />Inferred, not executed</span>
        <button type="button" className="btn" onClick={replay}>Replay scan</button>
      </div>
      <div className="panel scroll mapwrap">
        <div className="map" style={{ height: map.height, width: MAP_WIDTH }}>
          {COLUMNS.map((column) => <span key={column.title} className="column" style={{ left: column.x }}>{column.title}</span>)}
          <svg aria-hidden="true" width={MAP_WIDTH} height={map.height}>
            {map.edges.map((edge) => (
              <path key={`${edge.from}>${edge.to}`} d={edge.d} className={`stroke-${edge.tone}`}
                strokeDasharray={edge.dashed ? "5 5" : undefined} style={{ opacity: edge.stage <= stage ? 0.9 : 0 }} />
            ))}
          </svg>
          {map.nodes.map((n) => (
            <button key={n.id} type="button" onClick={() => pick(n.id)} aria-pressed={n.id === node.id}
              className={`node border-${n.tone}${n.dashed ? " dashed" : ""}${n.id === node.id ? " picked" : ""}`}
              style={{ left: n.x, top: n.y, opacity: n.stage <= stage ? 1 : 0, transform: `translateX(${n.stage <= stage ? 0 : 8}px)` }}>
              <span className="top"><span style={{ color: "var(--brand)" }}>{n.code}</span><span className={`tone-${n.tone === "line" ? "muted" : n.tone}`}>{n.tier}</span></span>
              <span className={`title${n.mono ? " mono" : ""}`}>{n.title}</span>
              <span className="sub">{n.sub}</span>
            </button>
          ))}
        </div>
      </div>
      <section ref={evidence} className="card evidence" aria-label="Evidence for the selected node">
        <div className="row">
          <h3 className="grow" style={{ fontSize: 16 }}>{node.title}</h3>
          <span className="ref">{node.code}</span>
          <span className={`mono small tone-${node.tone === "line" ? "muted" : node.tone}`}>{node.tier}</span>
          {node.finding && <Link className="btn" style={{ display: "flex", alignItems: "center" }} to={`/findings?ref=${node.finding}`}>Open {node.finding}</Link>}
          {node.openTools && <Link className="btn" style={{ display: "flex", alignItems: "center" }} to={node.tool ? `${toolsPath}?tool=${encodeURIComponent(node.tool)}` : toolsPath}>Open in Tools</Link>}
        </div>
        {node.lines.map((line) => <span key={line}>{line}</span>)}
        {node.inference && <span className="muted">{node.inference}</span>}
        {node.fix && <span style={{ color: "var(--brand)" }}>{node.fix}</span>}
      </section>
    </>
  );
}
