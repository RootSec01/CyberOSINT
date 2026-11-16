export const ANY_TIME = { mode: "any", day: "", from: "", to: "" };

export default function When({ value, onChange }) {
  const set = (patch) => onChange({ ...value, ...patch });
  return (
    <>
      <label>Time
        <select className="input" value={value.mode} onChange={(event) => set({ mode: event.target.value })}>
          <option value="any">Any time</option>
          <option value="day">On a day</option>
          <option value="range">Between</option>
        </select>
      </label>
      {value.mode === "day" && (
        <label>Day
          <input className="input" type="date" value={value.day} onChange={(event) => set({ day: event.target.value })} />
        </label>
      )}
      {value.mode === "range" && (
        <>
          <label>From
            <input className="input" type="datetime-local" value={value.from} onChange={(event) => set({ from: event.target.value })} />
          </label>
          <label>To
            <input className="input" type="datetime-local" value={value.to} onChange={(event) => set({ to: event.target.value })} />
          </label>
        </>
      )}
    </>
  );
}
