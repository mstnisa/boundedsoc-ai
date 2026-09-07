import { Route, Routes } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import IncidentQueue from "./pages/IncidentQueue";
import IncidentDetailPage from "./pages/IncidentDetail";
import AuditTrail from "./pages/AuditTrail";
import Integrations from "./pages/Integrations";

export default function App() {
  return (
    <div className="app-shell">
      <Sidebar />
      <div className="main-area">
        <main className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/queue" element={<IncidentQueue />} />
            <Route path="/incidents/:id" element={<IncidentDetailPage />} />
            <Route path="/audit" element={<AuditTrail />} />
            <Route path="/integrations" element={<Integrations />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
