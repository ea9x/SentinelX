import { t, useLocale } from "./i18n/language";
import { lazy, Suspense } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import WorkspaceErrorBoundary from "./components/WorkspaceErrorBoundary";
import ServiceStatus from "./components/ServiceStatus";
import Layout from "./components/Layout";
import LanguageSwitcher from './components/LanguageSwitcher';
import ProtectedRoute from "./components/ProtectedRoute";
const Remediation = lazy(() => import("./pages/Remediation"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
import Login from "./pages/login";
import ForgotPassword from "./pages/ForgotPassword";
import Register from "./pages/Register";
const Reports = lazy(() => import("./pages/Reports"));
const ScanDetails = lazy(() => import("./pages/ScanDetails"));
const ScanHistory = lazy(() => import("./pages/ScanHistory"));
const Targets = lazy(() => import("./pages/Targets"));
const Vulnerabilities = lazy(() => import("./pages/Vulnerabilities"));
const Profile = lazy(() => import("./pages/Profile"));
const UserManagement = lazy(() => import("./pages/UserManagement"));
function ProtectedPage({
  children
}) {
  useLocale();
  return <ProtectedRoute>
      <Layout>{children}</Layout>
    </ProtectedRoute>;
}
export default function App() {
  useLocale();
  return <BrowserRouter>
      <LanguageSwitcher floating />
      <AuthProvider>
        <ServiceStatus />
        <WorkspaceErrorBoundary><Suspense fallback={<div role="status">{t("Loading workspace...")}</div>}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/register" element={<Register />} />

          <Route path="/dashboard" element={<ProtectedPage>
                <Dashboard />
              </ProtectedPage>} />

          <Route path="/targets" element={<ProtectedPage>
                <Targets />
              </ProtectedPage>} />

          <Route path="/scans" element={<ProtectedPage>
                <ScanHistory />
              </ProtectedPage>} />

          <Route path="/scans/:id" element={<ProtectedPage>
                <ScanDetails />
              </ProtectedPage>} />

          <Route path="/vulnerabilities" element={<ProtectedPage>
                <Vulnerabilities />
              </ProtectedPage>} />

          <Route path="/remediation" element={<ProtectedPage><Remediation /></ProtectedPage>} />
          <Route path="/reports" element={<ProtectedPage>
                <Reports />
              </ProtectedPage>} />

          <Route path="/profile" element={<ProtectedPage>
                <Profile />
              </ProtectedPage>} />

          <Route path="/users" element={<ProtectedPage>
                <UserManagement />
              </ProtectedPage>} />

          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
        </Suspense></WorkspaceErrorBoundary>
      </AuthProvider>
    </BrowserRouter>;
}
