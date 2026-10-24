import { t, useLocale, getLocale } from "../i18n/language";
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/auth-context";
import { Doughnut } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";
import { getTargets, getScans, getVulnerabilityStats } from "../api/dashboard";
ChartJS.register(ArcElement, Tooltip, Legend);
export default function Dashboard() {
  useLocale();
  const navigate = useNavigate();
  const {
    user,
    logout
  } = useAuth();
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    by_severity: {}
  });
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    async function loadData() {
      try {
        const [targetsRes, scansRes, statsRes] = await Promise.all([getTargets(), getScans(), getVulnerabilityStats()]);
        if (!active) return;
        setTargets(targetsRes.data);
        setScans(scansRes.data);
        setStats(statsRes.data);
      } catch (error) {
        console.error("Failed to load dashboard data:", error);
      } finally {
        if (active) setLoading(false);
      }
    }
    loadData();
    return () => {
      active = false;
    };
  }, []);
  const openScanDetails = scanId => {
    navigate(`/scans/${scanId}`);
  };
  const severityColors = {
    Critical: "#dc2626",
    High: "#ea580c",
    Medium: "#eab308",
    Low: "#22c55e",
    Info: "#3b82f6"
  };
  const chartData = {
    labels: Object.keys(stats.by_severity || {}).map(level => t(level)),
    datasets: [{
      data: Object.values(stats.by_severity || {}),
      backgroundColor: Object.keys(stats.by_severity || {}).map(severity => severityColors[severity] || "#94a3b8"),
      borderWidth: 0
    }]
  };
  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "68%",
    plugins: {
      legend: {
        rtl: getLocale() === 'ar',
        textDirection: getLocale() === 'ar' ? 'rtl' : 'ltr',
        position: "bottom",
        labels: {
          color: "#94a3b8",
          boxWidth: 12,
          boxHeight: 12,
          padding: 16,
          usePointStyle: true
        }
      },
      tooltip: {
        callbacks: {
          label: context => ` ${context.label}: ${context.raw}`
        }
      }
    }
  };
  const recentScans = [...scans].sort((a, b) => b.id - a.id).slice(0, 8);
  if (loading) {
    return <div style={styles.loadingContainer}>{t("Loading dashboard data...")}</div>;
  }
  return <div style={styles.page}>
      {/* Header */}
      <div style={styles.header}>
        <div style={styles.headerLeft}>
          <h1 style={styles.headerTitle}>{t("\uD83D\uDEE1\uFE0F SentinelX Dashboard")}</h1>

          <button type="button" onClick={() => navigate("/targets")} style={styles.targetsLink}>{t("Targets and Scans")}</button>
        </div>

        <div style={styles.headerRight}>
          <span style={styles.userText}>{t("Welcome, ")}{user?.username || t("User")}
          </span>

          <button type="button" onClick={logout} style={styles.logoutBtn}>{t("Log Out")}</button>
        </div>
      </div>

      <p>{t('Risk totals use the last completed scan per target and tool, exclude information and manually suppressed findings, and merge matching locations.')}</p>
      {stats.incomplete_latest_scans > 0 && <p role="alert" style={{color:'#fbbf24'}}>{t('Some latest scans are incomplete. Previous completed findings are retained; current coverage is uncertain.')}</p>}
      {/* Statistics Cards */}
      <div style={styles.cardsRow}>
        <div style={{
        ...styles.card,
        borderTop: "4px solid #38bdf8"
      }}>
          <p style={styles.cardLabel}>{t("Total Targets")}</p>
          <h2 style={styles.cardValue}>{targets.length}</h2>
        </div>

        <div style={{
        ...styles.card,
        borderTop: "4px solid #a855f7"
      }}>
          <p style={styles.cardLabel}>{t("Total Scans")}</p>
          <h2 style={styles.cardValue}>{scans.length}</h2>
        </div>

        <div style={{
        ...styles.card,
        borderTop: "4px solid #dc2626"
      }}>
          <p style={styles.cardLabel}>{t("Active potential vulnerabilities")}</p>
          <h2 style={styles.cardValue}>{stats.total}</h2>
        </div>
      </div>

      {/* Chart and Recent Scans */}
      <div style={styles.contentRow}>
        {/* Vulnerability Chart */}
        <div style={styles.chartBox}>
          <h3 style={styles.boxTitle}>{t("Vulnerabilities by Severity")}</h3>

          {stats.total > 0 ? <div style={styles.chartCanvas}>
              <Doughnut data={chartData} options={chartOptions} />
            </div> : <p style={styles.emptyText}>{t("No active potential vulnerabilities in completed scans. This is not a security guarantee.")}</p>}
        </div>

        {/* Recent Scans Table */}
        <div style={styles.tableBox}>
          <div style={styles.panelHeader}>
            <h3 style={{
            ...styles.boxTitle,
            marginBottom: 0
          }}>{t("Recent Scans")}</h3>
            <button type="button" onClick={() => navigate("/scans")} style={styles.viewAllButton}>{t("View All")}</button>
          </div>

          {recentScans.length === 0 ? <p style={styles.emptyText}>{t("No scans are available yet.")}</p> : <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>{t("Scan ID")}</th>
                  <th style={styles.th}>{t("Tool")}</th>
                  <th style={styles.th}>{t("Status")}</th>
                  <th style={styles.th}>{t("Started At")}</th>
                </tr>
              </thead>

              <tbody>
                {recentScans.map(scan => <tr key={scan.id} onClick={() => openScanDetails(scan.id)} onKeyDown={event => {
              if (event.key === "Enter" || event.key === " ") {
                openScanDetails(scan.id);
              }
            }} tabIndex={0} role="button" title={t("Open scan {0}", [scan.id])} style={styles.clickableRow} onMouseEnter={event => {
              event.currentTarget.style.backgroundColor = "rgba(59, 130, 246, 0.12)";
            }} onMouseLeave={event => {
              event.currentTarget.style.backgroundColor = "transparent";
            }} onFocus={event => {
              event.currentTarget.style.backgroundColor = "rgba(59, 130, 246, 0.12)";
            }} onBlur={event => {
              event.currentTarget.style.backgroundColor = "transparent";
            }}>
                    <td style={styles.td}>{scan.id}</td>

                    <td style={styles.td}>
                      {scan.tool_used || t("Unknown")}
                    </td>

                    <td style={styles.td}>
                      <span style={{
                  ...styles.statusBadge,
                  backgroundColor: scan.status === "completed" ? "#14532d" : scan.status === "failed" ? "#7f1d1d" : "#334155",
                  color: scan.status === "completed" ? "#bbf7d0" : scan.status === "failed" ? "#fecaca" : "#cbd5e1"
                }}>
                        {t(scan.status) || t("unknown")}
                      </span>
                    </td>

                    <td style={styles.td}>
                      {scan.started_at || "-"}
                    </td>
                  </tr>)}
              </tbody>
            </table>}
        </div>
      </div>

      {/* Targets List */}
      <div style={styles.targetsBox}>
        <h3 style={styles.boxTitle}>{t("Registered Targets")}</h3>

        {targets.length === 0 ? <p style={styles.emptyText}>{t("No targets are available yet.")}</p> : <div style={styles.targetsGrid}>
            {targets.map(target => <div key={target.id} style={styles.targetCard}>
                <strong style={styles.targetName}>
                  {target.name}
                </strong>

                <p style={styles.targetAddress}>
                  {target.ip_address}
                  {target.hostname ? ` (${target.hostname})` : ""}
                </p>
              </div>)}
          </div>}
      </div>
    </div>;
}
const styles = {
  page: {
    backgroundColor: "#0f172a",
    minHeight: "100vh",
    color: "white",
    direction: "ltr",
    padding: "30px",
    width: "100%",
    maxWidth: "none",
    margin: 0,
    boxSizing: "border-box",
    fontFamily: "sans-serif"
  },
  loadingContainer: {
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    height: "100vh",
    backgroundColor: "#0f172a",
    color: "white"
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "30px",
    paddingBottom: "20px",
    borderBottom: "1px solid #334155"
  },
  headerLeft: {
    display: "flex",
    alignItems: "center",
    gap: "20px"
  },
  headerTitle: {
    margin: 0,
    fontSize: "24px"
  },
  targetsLink: {
    padding: 0,
    background: "none",
    border: "none",
    color: "#38bdf8",
    cursor: "pointer",
    fontSize: "14px"
  },
  headerRight: {
    display: "flex",
    alignItems: "center",
    gap: "15px"
  },
  userText: {
    color: "#94a3b8"
  },
  logoutBtn: {
    padding: "8px 16px",
    backgroundColor: "#334155",
    color: "white",
    border: "none",
    borderRadius: "6px",
    cursor: "pointer"
  },
  cardsRow: {
    display: "grid",
    gridTemplateColumns: "repeat(3, 1fr)",
    gap: "20px",
    marginBottom: "30px"
  },
  card: {
    backgroundColor: "#1e293b",
    padding: "20px",
    borderRadius: "10px"
  },
  cardLabel: {
    margin: 0,
    color: "#94a3b8",
    fontSize: "14px"
  },
  cardValue: {
    margin: "10px 0 0",
    fontSize: "32px"
  },
  contentRow: {
    display: "grid",
    gridTemplateColumns: "minmax(330px, 0.85fr) minmax(560px, 1.65fr)",
    gap: "20px",
    marginBottom: "30px"
  },
  chartBox: {
    backgroundColor: "#1e293b",
    padding: "20px",
    borderRadius: "10px",
    minHeight: "410px"
  },
  chartCanvas: {
    position: "relative",
    height: "340px",
    maxWidth: "430px",
    margin: "0 auto"
  },
  tableBox: {
    backgroundColor: "#1e293b",
    padding: "20px",
    borderRadius: "10px",
    overflowX: "auto"
  },
  panelHeader: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "16px",
    marginBottom: "8px"
  },
  viewAllButton: {
    padding: "7px 11px",
    border: "1px solid #0ea5e9",
    borderRadius: "7px",
    background: "rgba(14, 165, 233, 0.12)",
    color: "#7dd3fc",
    fontSize: "12px",
    cursor: "pointer"
  },
  targetsBox: {
    backgroundColor: "#1e293b",
    padding: "20px",
    borderRadius: "10px"
  },
  boxTitle: {
    marginTop: 0,
    marginBottom: "15px",
    fontSize: "16px",
    color: "#e2e8f0"
  },
  table: {
    width: "100%",
    borderCollapse: "collapse"
  },
  th: {
    textAlign: "left",
    padding: "10px",
    borderBottom: "1px solid #334155",
    color: "#94a3b8",
    fontSize: "13px"
  },
  td: {
    padding: "10px",
    borderBottom: "1px solid #334155",
    fontSize: "14px"
  },
  clickableRow: {
    cursor: "pointer",
    transition: "background-color 0.2s ease",
    outline: "none"
  },
  statusBadge: {
    display: "inline-block",
    padding: "4px 10px",
    borderRadius: "20px",
    fontSize: "12px",
    textTransform: "capitalize"
  },
  emptyText: {
    color: "#64748b",
    fontSize: "14px"
  },
  targetsGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))",
    gap: "15px"
  },
  targetCard: {
    backgroundColor: "#0f172a",
    padding: "15px",
    borderRadius: "8px",
    border: "1px solid #334155"
  },
  targetName: {
    color: "#38bdf8"
  },
  targetAddress: {
    margin: "5px 0 0",
    fontSize: "13px",
    color: "#94a3b8"
  }
};
