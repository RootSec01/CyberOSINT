const TOKEN_KEY = "authToken";

export function getToken() {
  return (typeof sessionStorage !== "undefined" && sessionStorage.getItem(TOKEN_KEY)) || "";
}

export function setToken(token) {
  if (typeof sessionStorage === "undefined") return;
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

function withParams(path, params) {
  const query = new URLSearchParams();
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") query.append(key, value);
  });
  const text = query.toString();
  return text ? `${path}?${text}` : path;
}

async function request(method, path, { params, form } = {}) {
  const headers = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  let body;
  if (form) {
    body = new URLSearchParams();
    Object.entries(form).forEach(([key, value]) => body.append(key, value ?? ""));
  }
  const response = await fetch(withParams(path, params), { method, headers, body });
  if (response.status === 401 && typeof window !== "undefined") {
    window.dispatchEvent(new Event("auth:401"));
  }
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!response.ok) {
    const detail = data && (data.detail || data.error);
    throw new Error(typeof detail === "string" ? detail : `Request failed (${response.status})`);
  }
  return data;
}

export const api = {
  get: (path, params) => request("GET", path, { params }),
  post: (path, form) => request("POST", path, { form: form || {} }),
  put: (path, form) => request("PUT", path, { form: form || {} }),
  patch: (path, form) => request("PATCH", path, { form: form || {} }),
  del: (path) => request("DELETE", path),
};

export async function login(username, password) {
  setToken("");
  let data;
  try {
    data = await api.post("/api/login", { username, password });
  } catch {
    throw new Error("Wrong username or password");
  }
  setToken(data.token);
  return data;
}

export function logout() {
  setToken("");
}
