import { Route, Routes, Link } from "react-router-dom";
import IncidentQueue from "./pages/IncidentQueue";
import IncidentDetailPage from "./pages/IncidentDetail";
import AuditTrail from "./pages/AuditTrail";

export default function App() {
  return (
    <div className="app-shell">
      <header className="topbar">
        <Link to="/" className="brand">
          🛡️ AI SOC Workbench
        </Link>
        <nav>
          <Link to="/">Incident Queue</Link>
          <Link to="/audit">Audit Trail</Link>
        </nav>
        <div className="topbar-note">AI assists — a human approves every consequential claim</div>
      </header>
      <main className="content">
        <Routes>
          <Route path="/" element={<IncidentQueue />} />
          <Route path="/incidents/:id" element={<IncidentDetailPage />} />
          <Route path="/audit" element={<AuditTrail />} />
        </Routes>
      </main>
    </div>
  );
}
