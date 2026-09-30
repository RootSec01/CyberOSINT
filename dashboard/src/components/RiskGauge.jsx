const LEVEL_TONE = {
  Critical: { ring: "#F87171", text: "text-alert-crit" },
  High: { ring: "#FB923C", text: "text-alert-high" },
  Medium: { ring: "#FBBF24", text: "text-alert-med" },
  Low: { ring: "#38BDF8", text: "text-alert-low" },
  Unknown: { ring: "#8595AB", text: "text-mist-300" },
};

function RiskGauge({ score, level }) {
  const value = typeof score === "number" ? score : null;
  const pct = value === null ? 0 : Math.min(value / 10, 1);
  const tone = LEVEL_TONE[level] || LEVEL_TONE.Unknown;

  const size = 132;
  const stroke = 9;
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const dash = circ * pct;

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="#1C2634"
          strokeWidth={stroke}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={tone.ring}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`}
          style={{ transition: "stroke-dasharray 700ms cubic-bezier(0.22,1,0.36,1)" }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`font-display font-700 text-3xl ${tone.text}`}>
          {value === null ? "—" : value.toFixed(1)}
        </span>
        <span className="text-[10px] uppercase tracking-[0.16em] text-mist-300 mt-0.5">
          {level || "no data"}
        </span>
      </div>
    </div>
  );
}

export default RiskGauge;
