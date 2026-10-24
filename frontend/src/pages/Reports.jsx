import { t, useLocale, getLocale } from "../i18n/language";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { deleteReport, downloadReport, getReports } from "../api/dashboard";
function formatDate(value) {
  if (!value) return "Not available";
  return new Date(value).toLocaleString(getLocale());
}
export default function Reports() {
  useLocale();
  const navigate = useNavigate();
  const [reports, setReports] = useState([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [deletingId, setDeletingId] = useState(null);
  useEffect(() => {
    let active = true;
    async function initialize() {
      try {
        const response = await getReports();
        if (active) setReports(response.data);
      } catch (requestError) {
        if (active) {
          setError(requestError.response?.data?.error || "The report history could not be loaded.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    initialize();
    return () => {
      active = false;
    };
  }, []);
  async function loadReports() {
    setLoading(true);
    setError("");
    try {
      const response = await getReports();
      setReports(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.error || "The report history could not be loaded.");
    } finally {
      setLoading(false);
    }
  }
  const filteredReports = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return reports;
    return reports.filter(report => [report.id, report.scan_id, report.tool_used, report.target?.name, report.target?.ip_address, report.target?.hostname].filter(Boolean).join(" ").toLowerCase().includes(query));
  }, [reports, search]);
  async function removeReport(reportId) {
    const confirmed = window.confirm("Delete this report record? The scan and its findings will not be deleted.");
    if (!confirmed) return;
    setDeletingId(reportId);
    try {
      await deleteReport(reportId);
      setReports(current => current.filter(report => report.id !== reportId));
    } catch (requestError) {
      window.alert(requestError.response?.data?.error || "The report record could not be deleted.");
    } finally {
      setDeletingId(null);
    }
  }
  async function downloadSavedReport(report) {
    try {
      const response = await downloadReport(report.id);
      const url = window.URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = url;
      link.download = `sentinelx-report-${report.id}-scan-${report.scan_id}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (requestError) {
      window.alert(requestError.response?.data?.error || "The PDF file could not be downloaded.");
    }
  }
  if (loading) {
    return <main style={styles.statePage}>
        <h2>{t("Loading Reports")}</h2>
        <p style={styles.muted}>{t("Retrieving report history...")}</p>
      </main>;
  }
  if (error) {
    return <main style={styles.statePage}>
        <h2>{t("Unable to Load Reports")}</h2>
        <p style={styles.errorText}>{t(error)}</p>
        <button type="button" style={styles.primaryButton} onClick={loadReports}>{t("Try Again")}</button>
      </main>;
  }
  return <main style={styles.page}>
      <header style={styles.header}>
        <div>
          <p style={styles.eyebrow}>{t("REPORTS")}</p>
          <h1 style={styles.title}>{t("Report History")}</h1>
          <p style={styles.subtitle}>{t("Review reports registered when Scan Details were exported.")}</p>
        </div>
        <div style={styles.totalBox}>
          <span style={styles.totalLabel}>{t("Reports")}</span>
          <strong style={styles.totalValue}>{filteredReports.length}</strong>
        </div>
      </header>

      <section style={styles.searchPanel}>
        <label style={styles.field}>
          <span style={styles.fieldLabel}>{t("Search Reports")}</span>
          <input value={search} onChange={event => setSearch(event.target.value)} placeholder={t("Report ID, scan ID, target, IP, or tool")} style={styles.input} />
        </label>
      </section>

      <section style={styles.panel}>
        {filteredReports.length === 0 ? <div style={styles.emptyState}>{t("No report records are available yet. Export a report from Scan Details to create the first record.")}</div> : <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>{t("Report")}</th>
                  <th style={styles.th}>{t("Scan")}</th>
                  <th style={styles.th}>{t("Target")}</th>
                  <th style={styles.th}>{t("Tool")}</th>
                  <th style={styles.th}>{t("Created")}</th>
                  <th style={styles.th}>{t("Actions")}</th>
                </tr>
              </thead>
              <tbody>
                {filteredReports.map(report => <tr key={report.id}>
                    <td style={styles.td}>#{report.id}</td>
                    <td style={styles.td}>#{report.scan_id}</td>
                    <td style={styles.td}>
                      <strong style={styles.targetName}>
                        {report.target?.name || t("Unknown target")}
                      </strong>
                      <span style={styles.targetAddress}>
                        {report.target?.ip_address || report.target?.hostname || t("Address not available")}
                      </span>
                    </td>
                    <td style={styles.td}>
                      <span style={styles.toolBadge}>
                        {report.tool_used || t("unknown")}
                      </span>
                    </td>
                    <td style={styles.td}>
                      {formatDate(report.created_at)}
                    </td>
                    <td style={styles.td}>
                      <div style={styles.actions}>
                        <button type="button" style={styles.downloadButton} onClick={() => downloadSavedReport(report)}>{t("Download PDF")}</button>
                        <button type="button" style={styles.viewButton} onClick={() => navigate(`/scans/${report.scan_id}`)}>{t("View Scan")}</button>
                        <button type="button" style={styles.deleteButton} disabled={deletingId === report.id} onClick={() => removeReport(report.id)}>
                          {deletingId === report.id ? t("Deleting...") : t("Delete Record")}
                        </button>
                      </div>
                    </td>
                  </tr>)}
              </tbody>
            </table>
          </div>}
      </section>
    </main>;
}
const styles = {
  page: {
    minHeight: "100vh",
    padding: "28px",
    background: "#0f172a",
    color: "#f8fafc",
    direction: "ltr"
  },
  statePage: {
    minHeight: "70vh",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    padding: "24px",
    background: "#0f172a",
    color: "#f8fafc",
    textAlign: "center"
  },
  muted: {
    color: "#94a3b8"
  },
  errorText: {
    color: "#fca5a5"
  },
  primaryButton: {
    padding: "10px 15px",
    border: 0,
    borderRadius: "8px",
    background: "#2563eb",
    color: "#ffffff",
    cursor: "pointer"
  },
  header: {
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "space-between",
    gap: "24px",
    paddingBottom: "24px",
    marginBottom: "20px",
    borderBottom: "1px solid #334155"
  },
  eyebrow: {
    margin: "0 0 7px",
    color: "#38bdf8",
    fontSize: "12px",
    fontWeight: 800,
    letterSpacing: "0.12em"
  },
  title: {
    margin: 0,
    fontSize: "30px"
  },
  subtitle: {
    margin: "8px 0 0",
    color: "#94a3b8"
  },
  totalBox: {
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-end",
    gap: "4px",
    padding: "12px 16px",
    border: "1px solid #334155",
    borderRadius: "10px",
    background: "#1e293b"
  },
  totalLabel: {
    color: "#94a3b8",
    fontSize: "12px"
  },
  totalValue: {
    color: "#38bdf8",
    fontSize: "24px"
  },
  searchPanel: {
    padding: "18px",
    marginBottom: "20px",
    border: "1px solid #334155",
    borderRadius: "12px",
    background: "#1e293b"
  },
  field: {
    display: "flex",
    flexDirection: "column",
    gap: "7px"
  },
  fieldLabel: {
    color: "#94a3b8",
    fontSize: "12px",
    fontWeight: 700
  },
  input: {
    width: "100%",
    minHeight: "42px",
    padding: "10px 12px",
    border: "1px solid #475569",
    borderRadius: "8px",
    outline: "none",
    background: "#0f172a",
    color: "#f8fafc"
  },
  panel: {
    padding: "20px",
    border: "1px solid #334155",
    borderRadius: "12px",
    background: "#1e293b"
  },
  tableWrapper: {
    overflowX: "auto"
  },
  table: {
    width: "100%",
    borderCollapse: "collapse"
  },
  th: {
    padding: "11px 12px",
    borderBottom: "1px solid #475569",
    color: "#94a3b8",
    fontSize: "12px",
    textAlign: "left",
    textTransform: "uppercase"
  },
  td: {
    padding: "13px 12px",
    borderBottom: "1px solid #334155",
    color: "#cbd5e1",
    fontSize: "13px"
  },
  targetName: {
    display: "block",
    color: "#f8fafc",
    marginBottom: "4px"
  },
  targetAddress: {
    display: "block",
    color: "#94a3b8",
    fontSize: "12px"
  },
  toolBadge: {
    display: "inline-block",
    padding: "4px 9px",
    borderRadius: "999px",
    background: "#0c4a6e",
    color: "#bae6fd",
    fontSize: "12px",
    textTransform: "uppercase"
  },
  actions: {
    display: "flex",
    gap: "8px"
  },
  viewButton: {
    padding: "7px 10px",
    border: "1px solid #0ea5e9",
    borderRadius: "7px",
    background: "#075985",
    color: "#ffffff",
    cursor: "pointer"
  },
  downloadButton: {
    padding: "7px 10px",
    border: "1px solid #22c55e",
    borderRadius: "7px",
    background: "#166534",
    color: "#ffffff",
    cursor: "pointer"
  },
  deleteButton: {
    padding: "7px 10px",
    border: "1px solid #dc2626",
    borderRadius: "7px",
    background: "#7f1d1d",
    color: "#ffffff",
    cursor: "pointer"
  },
  emptyState: {
    padding: "36px",
    border: "1px dashed #475569",
    borderRadius: "10px",
    background: "#0f172a",
    color: "#94a3b8",
    textAlign: "center"
  }
};
