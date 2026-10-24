import { t, useLocale } from "../i18n/language";
import { useEffect, useState } from "react";
import api from "../api/axios";
import { FaShieldAlt, FaSignOutAlt } from "react-icons/fa";
import "./AuthTransition.css";
import { AuthContext } from "./auth-context";
export function AuthProvider({
  children
}) {
  useLocale();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [signingOut, setSigningOut] = useState(false);
  const refreshUser = async () => {
    const response = await api.get("/auth/me");
    setUser(response.data);
    return response.data;
  };
  useEffect(() => {
    // Remove the legacy token left by older SentinelX versions.
    localStorage.removeItem("token");
    let active = true;
    api.get("/auth/me").then(response => {
      if (active) setUser(response.data);
    }).catch(() => {
      if (active) setUser(null);
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => {
      active = false;
    };
  }, []);
  const login = async (email, password) => {
    const response = await api.post("/auth/login", {
      email,
      password
    });
    localStorage.removeItem("token");
    setUser(response.data.user);
    return response.data;
  };
  const register = async (username, email, password) => {
    const response = await api.post("/auth/register", {
      username,
      email,
      password
    });
    return response.data;
  };
  const updateStoredUser = updatedUser => setUser(updatedUser);
  const logout = async () => {
    if (signingOut) return;
    setSigningOut(true);
    try {
      await api.post("/auth/logout");
    } catch (error) {
      console.error("Failed to close the server session:", error);
    }
    await new Promise(resolve => window.setTimeout(resolve, 900));
    localStorage.removeItem("token");
    setUser(null);
    setSigningOut(false);
  };
  return <AuthContext.Provider value={{
    user,
    loading,
    login,
    register,
    logout,
    refreshUser,
    updateStoredUser
  }}>
      {children}
      {signingOut && <div className="authLogoutOverlay" role="status" aria-live="polite">
          <div className="authLogoutCard">
            <div className="authLogoutIcon">
              <FaShieldAlt />
              <span><FaSignOutAlt /></span>
            </div>
            <p>{t("SECURE SESSION")}</p>
            <h2>{t("Signing Out")}</h2>
            <small>{t("Closing your SentinelX session safely...")}</small>
            <div className="authLogoutProgress"><span /></div>
          </div>
        </div>}
    </AuthContext.Provider>;
}
