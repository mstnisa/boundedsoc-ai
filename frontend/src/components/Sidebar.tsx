import { NavLink } from "react-router-dom";

const linkClass = ({ isActive }: { isActive: boolean }) => `sidebar-link${isActive ? " active" : ""}`;

export default function Sidebar() {
  return (
    <div className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2 L4 5 V11 C4 16.2 7.4 20.1 12 22 C16.6 20.1 20 16.2 20 11 V5 Z" />
            <polyline points="9 12 11 14 15 9" />
          </svg>
        </div>
        <div className="sidebar-brand-text">
          BoundedSOC
          <br />
          AI
        </div>
      </div>

      <div className="sidebar-section-label">Workspace</div>

      <NavLink to="/" end className={linkClass}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="3" width="7" height="7" rx="1.5" />
          <rect x="14" y="3" width="7" height="7" rx="1.5" />
          <rect x="3" y="14" width="7" height="7" rx="1.5" />
          <rect x="14" y="14" width="7" height="7" rx="1.5" />
        </svg>
        <span>Dashboard</span>
      </NavLink>

      <NavLink to="/queue" className={linkClass}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <line x1="4" y1="6" x2="20" y2="6" />
          <line x1="4" y1="12" x2="20" y2="12" />
          <line x1="4" y1="18" x2="14" y2="18" />
        </svg>
        <span>Incident Queue</span>
      </NavLink>

      <NavLink to="/audit" className={linkClass}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="9" />
          <polyline points="12 7 12 12 15 14" />
        </svg>
        <span>Audit Trail</span>
      </NavLink>

      <NavLink to="/compliance" className={linkClass}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <path d="M9 12 11 14 15 9" />
          <path d="M12 2 L4 5 V11 C4 16.2 7.4 20.1 12 22 C16.6 20.1 20 16.2 20 11 V5 Z" />
        </svg>
        <span>Compliance</span>
      </NavLink>

      <NavLink to="/integrations" className={linkClass}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <line x1="4" y1="6" x2="20" y2="6" />
          <circle cx="15" cy="6" r="2" />
          <line x1="4" y1="12" x2="20" y2="12" />
          <circle cx="9" cy="12" r="2" />
          <line x1="4" y1="18" x2="20" y2="18" />
          <circle cx="16" cy="18" r="2" />
        </svg>
        <span>Integrations</span>
      </NavLink>

      <div className="sidebar-footer">
        <div className="ai-disclaimer" style={{ marginBottom: 12, fontSize: "0.7rem" }}>
          AI assists only — every consequential claim needs analyst approval.
        </div>
        <div className="sidebar-user">
          <div className="sidebar-user-avatar">LA</div>
          <div>
            <div className="sidebar-user-name">local-analyst</div>
            <div className="sidebar-user-role">single-user demo mode</div>
          </div>
        </div>
      </div>
    </div>
  );
}
