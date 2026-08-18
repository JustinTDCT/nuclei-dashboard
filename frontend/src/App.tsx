import type { ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import { Layout } from "./components/Layout";
import { AdminSettings } from "./pages/AdminSettings";
import { AdminUsers } from "./pages/AdminUsers";
import { Alerts } from "./pages/Alerts";
import { Compliance } from "./pages/Compliance";
import { Home } from "./pages/Home";
import { Login } from "./pages/Login";
import { Policies } from "./pages/Policies";
import { TenantDetail } from "./pages/TenantDetail";
import { Tenants } from "./pages/Tenants";

function Protected({ children, admin }: { children: ReactNode; admin?: boolean }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="p-8 text-slate-400">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  if (admin && user.role !== "admin") return <Navigate to="/" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <Protected>
            <Layout />
          </Protected>
        }
      >
        <Route index element={<Home />} />
        <Route path="tenants" element={<Tenants />} />
        <Route path="tenants/:id" element={<TenantDetail />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="compliance" element={<Compliance />} />
        <Route path="policies" element={<Policies />} />
        <Route
          path="admin/users"
          element={
            <Protected admin>
              <AdminUsers />
            </Protected>
          }
        />
        <Route
          path="admin/settings"
          element={
            <Protected admin>
              <AdminSettings />
            </Protected>
          }
        />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
