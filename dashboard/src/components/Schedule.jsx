import { api } from "../lib/api.js";
import { useAction } from "./ui.jsx";

const INTERVALS = { 0: "Off", 1: "Every minute", 5: "Every 5 minutes", 15: "Every 15 minutes", 60: "Every hour", 360: "Every 6 hours", 1440: "Every day" };

export default function ScheduleSelect({ assetId, value, onSaved, disabled }) {
  const action = useAction();
  const change = async (event) => {
    const saved = await action.run(() => api.put(`/api/assets/${assetId}/schedule`, { every_minutes: event.target.value }));
    if (saved && onSaved) onSaved(saved);
  };
  return (
    <select className="input" aria-label="Scan schedule" value={value} disabled={disabled || action.busy} onChange={change}
      title={action.error ? action.error.message : undefined}>
      {Object.entries(INTERVALS).map(([minutes, label]) => <option key={minutes} value={minutes}>{label}</option>)}
    </select>
  );
}
