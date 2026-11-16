import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api } from "./api.js";

const TeamContext = createContext({ me: null, members: [], can: () => false, reload: () => {} });

export function useTeam() {
  return useContext(TeamContext);
}

export function TeamProvider({ children }) {
  const [me, setMe] = useState(null);
  const [members, setMembers] = useState([]);
  const reload = useCallback(() => {
    api.get("/api/profile").then(setMe).catch(() => setMe(null));
    api.get("/api/members").then((data) => setMembers(data.members)).catch(() => setMembers([]));
  }, []);
  useEffect(() => reload(), [reload]);
  const can = (action) => !!me && me.can.includes(action);
  const nameOf = (username) => {
    if (!username) return "—";
    if (username === "raqeeb") return "Raqeeb";
    const found = members.find((member) => member.username === username);
    return found ? found.display_name : username;
  };
  return <TeamContext.Provider value={{ me, members, can, nameOf, reload }}>{children}</TeamContext.Provider>;
}
