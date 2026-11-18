import { createContext, useContext, useEffect, useState } from "react";
import { enterAsVisitor, login as apiLogin, logout as apiLogout, getToken } from "./api.js";

const AuthCtx = createContext(null);

export function useAuth() {
  return useContext(AuthCtx);
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
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
