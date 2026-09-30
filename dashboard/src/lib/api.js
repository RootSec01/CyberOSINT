// Session token (JWT) is kept in sessionStorage and sent as a Bearer header
// on every request. Cleared on logout or when the server returns 401.
const TOKEN_KEY = "authToken";

export function getToken() {
  return (typeof sessionStorage !== "undefined" &&
    sessionStorage.getItem(TOKEN_KEY)) || "";
}

export function setToken(token) {
  if (typeof sessionStorage === "undefined") return;
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

function authHeaders() {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

async function asJson(res) {
  if (res.status === 401 && typeof window !== "undefined") {
    window.dispatchEvent(new Event("auth:401"));
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || `Request failed (${res.status})`);
  }
  return res.json();
}

function form(data) {
  const body = new URLSearchParams();
  Object.entries(data).forEach(([k, v]) => body.append(k, v));
  return body;
}

export async function login(username, password) {
  const res = await fetch("/api/login", {
    method: "POST",
    body: form({ username, password }),
  });
  if (!res.ok) {
    throw new Error("invalid username or password");
  }
  const data = await res.json();
  setToken(data.token);
  return data; // { token, username, role }
}

export function logout() {
  setToken("");
}

export function getScope() {
  return fetch("/api/scope", { headers: authHeaders() }).then(asJson);
}

export function authorizeTarget(ip, ttlMinutes = 60, reason = "") {
  return fetch("/api/authorize", {
    method: "POST",
    headers: authHeaders(),
    body: form({ ip, ttl_minutes: ttlMinutes, reason }),
  }).then(asJson);
}

export function revokeTarget(ip, reason = "") {
  return fetch("/api/revoke", {
    method: "POST",
    headers: authHeaders(),
    body: form({ ip, reason }),
  }).then(asJson);
}

export function runScan(targetType, targetValue) {
  return fetch("/api/scan", {
    method: "POST",
    headers: authHeaders(),
    body: form({ target_type: targetType, target_value: targetValue }),
  }).then(asJson);
}

export function runMcpScan(target, targetType = "domain", verify = true) {
  return fetch("/api/mcp-scan", {
    method: "POST",
    headers: authHeaders(),
    body: form({ target, target_type: targetType, verify }),
  }).then(asJson);
}

export function verifyDirect(host, port, useTls = true) {
  return fetch("/api/mcp-verify-direct", {
    method: "POST",
    headers: authHeaders(),
    body: form({ host, port, use_tls: useTls }),
  }).then(asJson);
}

export function getRuns() {
  return fetch("/api/runs", { headers: authHeaders() }).then(asJson);
}

export function getRun(id) {
  return fetch(`/api/runs/${id}`, { headers: authHeaders() }).then(asJson);
}

export function safeProof(host, port, useTls = false) {
  return fetch("/api/safe-proof", {
    method: "POST",
    headers: authHeaders(),
    body: form({ host, port, use_tls: useTls }),
  }).then(asJson);
}

export function scanStreamUrl(host, port, useTls = false) {
  const params = new URLSearchParams({
    host,
    port: String(port),
    use_tls: String(useTls),
    token: getToken(),
  });
  return `/api/scan-stream?${params.toString()}`;
}

export function listAssets() {
  return fetch("/api/assets", { headers: authHeaders() }).then(asJson);
}
export function createAsset(value, kind = "domain", label = "") {
  return fetch("/api/assets", {
    method: "POST", headers: authHeaders(),
    body: form({ value, kind, label }),
  }).then(asJson);
}
export function toggleAsset(id, monitoring) {
  return fetch(`/api/assets/${id}`, {
    method: "PATCH", headers: authHeaders(),
    body: form({ monitoring }),
  }).then(asJson);
}
export function deleteAsset(id) {
  return fetch(`/api/assets/${id}`, { method: "DELETE", headers: authHeaders() }).then(asJson);
}
export function scanAssetNow(id) {
  return fetch(`/api/assets/${id}/scan`, { method: "POST", headers: authHeaders() }).then(asJson);
}
export function getDrift(id) {
  return fetch(`/api/assets/${id}/drift`, { headers: authHeaders() }).then(asJson);
}
export function getAlerts(unacknowledged = false) {
  const q = unacknowledged ? "?unacknowledged=true" : "";
  return fetch(`/api/alerts${q}`, { headers: authHeaders() }).then(asJson);
}
export function ackAlert(id) {
  return fetch(`/api/alerts/${id}/ack`, { method: "POST", headers: authHeaders() }).then(asJson);
}
export function getSettings() {
  return fetch("/api/settings", { headers: authHeaders() }).then(asJson);
}
export function updateSettings(fields) {
  const body = new URLSearchParams();
  Object.entries(fields).forEach(([k, v]) => { if (v !== undefined && v !== null) body.append(k, v); });
  return fetch("/api/settings", { method: "PUT", headers: authHeaders(), body }).then(asJson);
}
export function askCopilot(id, question = "") {
  const body = new URLSearchParams();
  body.append("question", question || "");
  return fetch(`/api/assets/${id}/copilot`, { method: "POST", headers: authHeaders(), body }).then(asJson);
}
// Platform-wide copilot: grounded across ALL of the user's assets/alerts/changes.
export function askPlatformCopilot(question = "") {
  const body = new URLSearchParams();
  body.append("question", question || "");
  return fetch(`/api/copilot`, { method: "POST", headers: authHeaders(), body }).then(asJson);
}
