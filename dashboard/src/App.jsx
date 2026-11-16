import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./lib/AuthContext.jsx";
import { TeamProvider } from "./lib/Team.jsx";
import Login from "./components/Login.jsx";
import Shell from "./components/Shell.jsx";
import Inventory from "./pages/Inventory.jsx";
import Server from "./pages/Server.jsx";
import Findings from "./pages/Findings.jsx";
import Cases from "./pages/Cases.jsx";
import CaseDetail from "./pages/CaseDetail.jsx";
import Changes from "./pages/Changes.jsx";
import Activity from "./pages/Activity.jsx";
import Settings from "./pages/Settings.jsx";

function Console() {
  const { authed } = useAuth();
  if (!authed) return <Login />;
  return (
    <TeamProvider>
      <Shell>
        <Routes>
          <Route path="/" element={<Inventory />} />
          <Route path="/servers/:id" element={<Server />} />
          <Route path="/servers/:id/:tab" element={<Server />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/cases" element={<Cases />} />
          <Route path="/cases/:reference" element={<CaseDetail />} />
          <Route path="/changes" element={<Changes />} />
          <Route path="/activity" element={<Activity />} />
          <Route path="/settings" element={<Navigate to="/settings/profile" replace />} />
          <Route path="/settings/:section" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Shell>
    </TeamProvider>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Console />
    </AuthProvider>
  );
}
