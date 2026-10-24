import { t, useLocale } from "../i18n/language";
import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { FaBullseye, FaCircle, FaFileAlt, FaHome, FaHistory, FaBug, FaShieldAlt, FaUserCog, FaRobot, FaUser, FaUserSecret, FaUserTie, FaSignOutAlt, FaChevronDown, FaUsers } from "react-icons/fa";
import { getSystemHealth, getScans, getTargets, getVulnerabilityStats } from "../api/dashboard";
import PrivacyBadge from "./PrivacyBadge";
import LanguageSwitcher from './LanguageSwitcher';
import { useAuth } from "../context/auth-context";
import "./Sidebar.css";
export default function Sidebar() {
  useLocale();
  const location = useLocation();
  const navigate = useNavigate();
  const {
    user,
    logout
  } = useAuth();
  const [accountMenuPath, setAccountMenuPath] = useState(null);
  const accountMenuOpen = accountMenuPath === location.pathname;
  const avatarIcons = {
    shield: FaShieldAlt,
    user: FaUser,
    secret: FaUserSecret,
    robot: FaRobot,
    analyst: FaUserTie
  };
  const UserAvatarIcon = avatarIcons[user?.avatar_icon] || FaShieldAlt;
  const [statistics, setStatistics] = useState({
    targets: null,
    scans: null,
    findings: null
  });
  const [health, setHealth] = useState({
    status: "checking",
    available_services: 0,
    total_services: 6,
    checks: {}
  });
  useEffect(() => {
    let active = true;
    async function loadHealth() {
      try {
        const response = await getSystemHealth();
        if (active) setHealth(response.data);
      } catch (error) {
        console.error("Failed to load system health:", error);
        if (active) {
          setHealth({
            status: "offline",
            available_services: 0,
            total_services: 6,
            checks: {}
          });
        }
      }
    }
    loadHealth();

    // Refresh the service status automatically every five seconds.
    const intervalId = window.setInterval(loadHealth, 5000);

    // Refresh immediately when the user returns to the browser tab.
    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        loadHealth();
      }
    };
    window.addEventListener("focus", loadHealth);
    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      active = false;
      window.clearInterval(intervalId);
      window.removeEventListener("focus", loadHealth);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, []);
  useEffect(() => {
    let active = true;
    async function loadStatistics() {
      try {
        const [targetsResponse, scansResponse, findingsResponse] = await Promise.all([getTargets(), getScans(), getVulnerabilityStats()]);
        if (!active) return;
        setStatistics({
          targets: targetsResponse.data.length,
          scans: scansResponse.data.length,
          findings: findingsResponse.data.record_total ?? findingsResponse.data.total
        });
      } catch (error) {
        console.error("Failed to load sidebar statistics:", error);
        if (active) {
          setStatistics({
            targets: "—",
            scans: "—",
            findings: "—"
          });
        }
      }
    }
    loadStatistics();
    window.addEventListener('sentinelx:data-updated',loadStatistics);
    return () => {
      window.removeEventListener('sentinelx:data-updated',loadStatistics);
      active = false;
    };
  }, [location.pathname]);
  const menu = [{
    name: "Dashboard",
    path: "/dashboard",
    icon: <FaHome />
  }, {
    name: "Targets",
    path: "/targets",
    icon: <FaBullseye />
  }, {
    name: "Scan History",
    path: "/scans",
    icon: <FaHistory />
  }, {
    name: "Vulnerabilities",
    path: "/vulnerabilities",
    icon: <FaBug />
  }, {
    name: "Remediation",
    path: "/remediation",
    icon: <FaUserTie />
  }, {
    name: "Reports",
    path: "/reports",
    icon: <FaFileAlt />
  }, {
    name: "User Management",
    path: "/users",
    icon: <FaUsers />,
    adminOnly: true
  }];
  const healthLabels = {
    checking: "Checking",
    online: "Online",
    degraded: "Degraded",
    offline: "Offline"
  };
  return <aside className="sidebar">
      <LanguageSwitcher />
      <div className="logoSection">
        <FaShieldAlt className="shield" />
        <h2>SentinelX</h2>
        <p>{t("Security Operations Center")}</p>
        {user && <div className={`sidebarAccount ${accountMenuOpen ? "isOpen" : ""}`}>
            <button type="button" className="sidebarIdentity" onClick={() => setAccountMenuPath(accountMenuOpen ? null : location.pathname)} aria-expanded={accountMenuOpen} aria-controls="sidebar-account-menu">
            <span style={{
            backgroundColor: `${user.avatar_color || "#38bdf8"}22`,
            color: user.avatar_color || "#38bdf8"
          }}>
              <UserAvatarIcon />
            </span>
            <span className="sidebarIdentityText">
              <strong>{user.username}</strong>
              <small>{user.email}</small>
            </span>
              <FaChevronDown className="sidebarAccountChevron" />
            </button>

            {accountMenuOpen && <div className="sidebarAccountMenu" id="sidebar-account-menu">
                <button type="button" onClick={() => navigate("/profile")}>
                  <FaUserCog />
                  <span>{t("View Profile")}</span>
                </button>
                <button type="button" className="danger" onClick={() => {
            logout();
            navigate("/login", {
              replace: true
            });
          }}>
                  <FaSignOutAlt />
                  <span>{t("Log Out")}</span>
                </button>
              </div>}
          </div>}
      </div>

      <div className="statusBox">
        <span className="statusTitle">{t("System Status")}</span>
        <div className={`systemHealth systemHealth--${health.status}`}>
          <FaCircle />
          <span>{t(healthLabels[health.status]) || t("Unknown")}</span>
        </div>
        <p className="healthSummary">
          {health.status === "offline" ? t("Backend unavailable") : t("{0}/{1} services available", [health.available_services, health.total_services])}
        </p>

        {Object.keys(health.checks || {}).length > 0 && <div className="healthServices" aria-label={t("Service health")}>
            {Object.entries(health.checks).map(([key, check]) => <span key={key} className={`healthService ${check.available ? "isAvailable" : "isUnavailable"}`} title={t(`${check.label}: ${check.available ? "Available" : "Unavailable"}`)}>
                <i />
                {t(check.label)}
              </span>)}
          </div>}
      </div>

      <div className="stats">
        <div className="stat">
          <span>{t("Targets")}</span>
          <strong>{statistics.targets ?? "..."}</strong>
        </div>
        <div className="stat">
          <span>{t("Scans")}</span>
          <strong>{statistics.scans ?? "..."}</strong>
        </div>
        <div className="stat">
          <span>{t("Findings")}</span>
          <strong>{statistics.findings ?? "..."}</strong>
        </div>
      </div>

      <nav className="menu" aria-label={t("Main navigation")}>
        {menu.filter(item => !item.adminOnly || user?.role === "admin").map(item => <Link key={item.path} to={item.path} className={location.pathname === item.path ? "active" : ""}>
            {item.icon}
            <span>{t(item.name)}</span>
          </Link>)}
      </nav>

      <PrivacyBadge />
    </aside>;
}
