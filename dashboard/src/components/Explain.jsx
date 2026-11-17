import { useState } from "react";
import { api } from "../lib/api.js";
import { Problem, useAction } from "./ui.jsx";

const MODES = {
  offline: "Offline briefing, built from this scan's evidence. Nothing left the platform.",
  redacted: "Identifiers and secrets were stripped before the provider was called.",
  local: "Answered by a model inside your own network.",
};

export default function Explain({ assetId }) {
  const [answer, setAnswer] = useState(null);
  const [question, setQuestion] = useState("");
  const action = useAction();
  const ask = async (text) => {
    const result = await action.run(() => api.post(`/api/assets/${assetId}/copilot`, { question: text }));
    if (result) setAnswer({ ...result, asked: text });
  };

  return (
    <section className="card" aria-label="Copilot">
      <div className="row">
        <h2 className="grow">Copilot</h2>
        {!answer && <button type="button" className="btn" disabled={action.busy} onClick={() => ask("")}>Explain this server</button>}
      </div>
      {answer && (
        <>
          <p style={{ whiteSpace: "pre-wrap" }}>{answer.answer}</p>
          <div className="pills">
            {(answer.suggestions || []).map((text) => (
              <button key={text} type="button" className="pill" disabled={action.busy} onClick={() => ask(text)}>{text}</button>
            ))}
          </div>
          <form className="row" onSubmit={(event) => { event.preventDefault(); if (question.trim()) ask(question.trim()); }}>
            <input className="input grow" aria-label="Question" placeholder="Ask about this server's evidence" value={question} onChange={(event) => setQuestion(event.target.value)} />
            <button className="btn" type="submit" disabled={action.busy || !question.trim()}>Ask</button>
          </form>
          <p className="note">{answer.fallback ? "The provider did not answer; this is the offline briefing." : MODES[answer.mode] || ""}</p>
        </>
      )}
      <Problem error={action.error} />
    </section>
  );
}
