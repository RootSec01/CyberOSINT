import { createContext, useContext, useEffect, useState } from "react";
import { login as apiLogin, logout as apiLogout, getToken } from "./api.js";

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

  async function signIn(username, password) {
    const data = await apiLogin(username, password);
    const u = { username: data.username, role: data.role };
    sessionStorage.setItem("authUser", JSON.stringify(u));
    setUser(u);
    return u;
  }

  function signOut() {
    apiLogout();
    sessionStorage.removeItem("authUser");
    setUser(null);
  }

  return (
    <AuthCtx.Provider value={{ user, authed, signIn, signOut }}>
      {children}
    </AuthCtx.Provider>
  );
}
