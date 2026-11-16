import { useState } from "react";
import { useAuth } from "../lib/AuthContext.jsx";
import Mark from "./Mark.jsx";
import { Problem, useAction } from "./ui.jsx";

export default function Login() {
  const { signIn } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const action = useAction();

  const submit = (event) => {
    event.preventDefault();
    action.run(() => signIn(username.trim(), password));
  };

  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <span className="brand"><Mark size={26} />Raqeeb</span>
        <p className="muted">Sign in to the console.</p>
        <label className="stack tight">Username
          <input className="input" autoFocus autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} />
        </label>
        <label className="stack tight">Password
          <input className="input" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} />
        </label>
        <Problem error={action.error} />
        <button className="btn primary" type="submit" disabled={action.busy || !username || !password}>Sign in</button>
      </form>
    </div>
  );
}
