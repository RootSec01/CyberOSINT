import { useEffect, useState } from "react";
import { api } from "../lib/api.js";
import Mark from "../components/Mark.jsx";

function Operator({ who }) {
  if (!who) return null;
  const contact = who.contact ? (who.contact.includes("@") && !who.contact.includes(":") ? `mailto:${who.contact}` : who.contact) : null;
  return (
    <p>
      This installation is operated by {who.name || "its administrator"}.
      {contact && <> Contact: <a href={contact}>{who.contact}</a>.</>}
    </p>
  );
}

const PAGES = {
  terms: ["Terms of use", (who) => (
    <>
      <Operator who={who} />
      <h2>What Raqeeb does</h2>
      <p>Raqeeb connects to a Model Context Protocol server the way any MCP client does: it completes the handshake and asks for the tool list. It never calls a tool, never sends a credential it was not given, and never tries to bypass authentication.</p>
      <h2>Which servers may be added</h2>
      <p>Only two kinds of server may be added: servers whose operators publish an open endpoint in the official MCP registry for any client to use, and servers that you own or hold written permission to scan. Adding any other server is not permitted. Each addition records who added it and on what basis.</p>
      <h2>Your responsibilities</h2>
      <p>Keep your credentials private, use the console only for work you are entitled to do, and follow the laws that apply to you and to the servers you monitor. Do not use findings to attack, disrupt or embarrass any party.</p>
      <h2>Findings</h2>
      <p>Findings describe what a server declares. They are not proof that a weakness can be exploited, and they are not statements about any vendor.</p>
      <h2>Accounts and suspension</h2>
      <p>Accounts are created by the administrator. Access can be suspended, and the console can be taken offline, at any time.</p>
    </>
  )],
  privacy: ["Privacy", (who) => (
    <>
      <Operator who={who} />
      <h2>What is stored</h2>
      <p>For each account: username, display name, optional email and title, and a salted password hash. For each server: its address, the tool declarations it returned, findings, cases, notes and the scan history. An audit log records sign-in sessions and every change, sealed in a hash chain.</p>
      <h2>What is not stored</h2>
      <p>Raqeeb does not store the results of tool calls, because it makes none. Secrets that appear inside tool declarations are redacted before storage.</p>
      <h2>Where it goes</h2>
      <p>Data stays in this installation's database. The assistant sends nothing outside unless the administrator enables an external model, and then only redacted evidence. Alerts are sent to a webhook only if the administrator configures one.</p>
      <h2>Your rights</h2>
      <p>Ask the operator to see, correct or delete your account data. Audit entries are kept for accountability.</p>
    </>
  )],
  about: ["About the scanner", (who) => (
    <>
      <Operator who={who} />
      <p>Requests with the user agent <span className="mono">Raqeeb/2.0</span> come from this installation. Raqeeb reads the MCP handshake and the tool list only, at most once an hour for servers taken from the public registry. It does not call tools or attempt to sign in.</p>
      <p>If you operate a server and want it excluded, contact the operator above; it will be removed and no longer read.</p>
    </>
  )],
};

export default function Legal({ page }) {
  const [who, setWho] = useState(null);
  useEffect(() => { api.get("/api/public/operator").then(setWho).catch(() => setWho({})); }, []);
  const [title, body] = PAGES[page] || PAGES.terms;
  return (
    <main className="legal">
      <a href="/" className="brand"><Mark size={26} />Raqeeb</a>
      <h1>{title}</h1>
      {body(who)}
      <nav className="login-links small"><a href="/terms">Terms of use</a><a href="/privacy">Privacy</a><a href="/about">About the scanner</a><a href="/">Sign in</a></nav>
    </main>
  );
}
