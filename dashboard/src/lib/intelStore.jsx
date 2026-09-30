import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
} from "react";
import { getRuns, getRun } from "./api.js";

const IntelContext = createContext(null);

export function IntelProvider({ children }) {
  const [lastScan, setLastScan] = useState(null);
  const [lastMcpScan, setLastMcpScan] = useState(null);
  const [history, setHistory] = useState([]);

  const refreshHistory = useCallback(() => {
    return getRuns()
      .then((rows) => setHistory(Array.isArray(rows) ? rows : []))
      .catch(() => {});
  }, []);

  // Load the signed-in user's saved runs once the app mounts.
  useEffect(() => {
    refreshHistory();
  }, [refreshHistory]);

  const recordScan = useCallback(
    (data) => {
      setLastScan({ ...data, receivedAt: new Date().toISOString() });
      refreshHistory();
    },
    [refreshHistory]
  );

  const recordMcpScan = useCallback(
    (data) => {
      setLastMcpScan({ ...data, receivedAt: new Date().toISOString() });
      refreshHistory();
    },
    [refreshHistory]
  );

  // Re-open a stored run from history into the active view.
  const openRun = useCallback(async (id) => {
    const report = await getRun(id);
    if (report && report.kind === "mcp") {
      setLastMcpScan({ ...(report.mcp || {}), receivedAt: new Date().toISOString() });
    } else if (report) {
      setLastScan({ ...report, receivedAt: new Date().toISOString() });
    }
  }, []);

  return (
    <IntelContext.Provider
      value={{
        lastScan,
        lastMcpScan,
        history,
        refreshHistory,
        openRun,
        recordScan,
        recordMcpScan,
      }}
    >
      {children}
    </IntelContext.Provider>
  );
}

export function useIntel() {
  const ctx = useContext(IntelContext);
  if (!ctx) throw new Error("useIntel must be used within IntelProvider");
  return ctx;
}
