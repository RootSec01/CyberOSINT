import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar.jsx";
import Overview from "./pages/Overview.jsx";
import Scan from "./pages/Scan.jsx";
import ShadowAI from "./pages/ShadowAI.jsx";
import Authorization from "./pages/Authorization.jsx";
import SafeProof from "./pages/SafeProof.jsx";
import Assets from "./pages/Assets.jsx";
import { IntelProvider } from "./lib/intelStore.jsx";
import { AuthProvider, useAuth } from "./lib/AuthContext.jsx";
import LoginOverlay from "./components/LoginOverlay.jsx";

function Shell() {
  const { authed } = useAuth();
  if (!authed) {
    return <LoginOverlay />;
  }
  return (
    <IntelProvider>
      <div className="h-full flex bg-ink-900">
        <Sidebar />
        <main className="flex-1 flex min-w-0">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/scan" element={<Scan />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/shadow-ai" element={<ShadowAI />} />
            <Route path="/safe-proof" element={<SafeProof />} />
            <Route path="/authorization" element={<Authorization />} />
          </Routes>
        </main>
      </div>
    </IntelProvider>
  );
}

function App() {
  return (
    <AuthProvider>
      <Shell />
    </AuthProvider>
  );
}

export default App;
