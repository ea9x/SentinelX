import { t, useLocale } from "../i18n/language";
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/auth-context';
export default function ProtectedRoute({
  children
}) {
  useLocale();
  const {
    user,
    loading
  } = useAuth();
  if (loading) {
    return <div style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      height: '100vh',
      backgroundColor: '#0f172a',
      color: 'white'
    }}>{t("Loading...")}</div>;
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return children;
}
