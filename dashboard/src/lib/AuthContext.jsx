import { createContext, useContext, useEffect, useState } from "react";
import { enterAsVisitor, login as apiLogin, logout as apiLogout, getToken, setToken } from "./api.js";

const AuthCtx = createContext(null);

export function useAuth() {
  return useContext(AuthCtx);
}

function handedOver() {
  const match = window.location.hash.match(/^#session=([\w-]+\.[\w-]+\.[\w-]+)$/);
  if (!match) return null;
  window.history.replaceState(null, "", window.location.pathname);
  try {
    const claims = JSON.parse(atob(match[1].split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    const handed = { username: claims.username, role: claims.role, guest: false };
    setToken(match[1]);
    sessionStorage.setItem("authUser", JSON.stringify(handed));
    return handed;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const handed = handedOver();
    if (handed) return handed;
    try {
      const raw = sessionStorage.getItem("authUser");
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  });

  const authed = !!user && !!getToken();

  useEffect(() => {
    const onExpire = () => {
      apiLogout();
      sessionStorage.removeItem("authUser");
      setUser(null);
    };
    window.addEventListener("auth:401", onExpire);
    return () => window.removeEventListener("auth:401", onExpire);
  }, []);

  function keep(data) {
    const u = { username: data.username, role: data.role, guest: !!data.guest };
    sessionStorage.setItem("authUser", JSON.stringify(u));
    setUser(u);
    return u;
  }

  async function signIn(username, password) {
    return keep(await apiLogin(username, password));
  }

  async function visit() {
    return keep(await enterAsVisitor());
  }

  function signOut() {
    apiLogout();
    sessionStorage.removeItem("authUser");
    sessionStorage.setItem("signedOut", "1");
    setUser(null);
  }

  return (
    <AuthCtx.Provider value={{ user, authed, signIn, visit, signOut }}>
      {children}
    </AuthCtx.Provider>
  );
}
