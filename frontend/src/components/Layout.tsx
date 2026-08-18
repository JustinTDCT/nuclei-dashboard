import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth";
import { TimezoneProvider } from "../timezone";

const link = ({ isActive }: { isActive: boolean }) =>
  `block px-3 py-2 rounded-md text-sm ${isActive ? "bg-slate-800 text-white" : "text-slate-300 hover:bg-slate-800/70"}`;

export function Layout() {
  const { user, logout } = useAuth();
  return (
    <div className="min-h-screen grid grid-cols-[240px_1fr]">
      <aside className="border-r border-slate-800 bg-slate-950/80 p-4 flex flex-col">
        <div className="mb-6">
          <div className="text-xs uppercase tracking-[0.2em] text-cyan-400">Nuclei</div>
          <div className="text-lg font-semibold">Control Plane</div>
        </div>
        <nav className="space-y-1 flex-1">
          <NavLink to="/" end className={link}>
            Overview
          </NavLink>
          <NavLink to="/tenants" className={link}>
            Tenants
          </NavLink>
          <NavLink to="/alerts" className={link}>
            Alerts
          </NavLink>
          <NavLink to="/compliance" className={link}>
            Compliance
          </NavLink>
          {user?.role === "admin" && (
            <>
              <div className="pt-4 pb-1 px-3 text-[11px] uppercase tracking-wider text-slate-500">Admin</div>
              <NavLink to="/admin/users" className={link}>
                Users
              </NavLink>
              <NavLink to="/admin/settings" className={link}>
                Settings
              </NavLink>
            </>
          )}
        </nav>
        <div className="border-t border-slate-800 pt-4 text-sm">
          <div className="text-slate-200">{user?.username}</div>
          <div className="text-xs text-slate-500 mb-3">{user?.role}</div>
          <button className="text-cyan-400 text-sm" onClick={logout}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="p-8 overflow-auto">
        <TimezoneProvider>
          <Outlet />
        </TimezoneProvider>
      </main>
    </div>
  );
}
