import { t, useLocale, getLocale } from "../i18n/language";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import ScanComparison from "../components/ScanComparison";
import { getScans, getTargets } from "../api/dashboard";
const PAGE_SIZE = 10;
function formatDate(value) {
  if (!value) return "Not available";
  return new Date(value).toLocaleString(getLocale());
}
export default function ScanHistory() {
  useLocale();
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [toolFilter, setToolFilter] = useState("all");
  const [requestedPage, setCurrentPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    async function loadHistory() {
      setLoading(true);
      setError("");
      try {
        const [scansResponse, targetsResponse] = await Promise.all([getScans(), getTargets()]);
        if (!active) return;
        setScans(scansResponse.data);
        setTargets(targetsResponse.data);
      } catch (requestError) {
        if (!active) return;
        setError(requestError.response?.data?.error || "The scan history could not be loaded.");
      } finally {
        if (active) setLoading(false);
      }
    }
    loadHistory();
    return () => {
      active = false;
    };
  }, []);
  const targetsById = useMemo(() => Object.fromEntries(targets.map(target => [String(target.id), target])), [targets]);
  const filteredScans = useMemo(() => {
    const query = search.trim().toLowerCase();
    return [...scans].sort((first, second) => {
      const firstDate = new Date(first.started_at || 0).getTime();
      const secondDate = new Date(second.started_at || 0).getTime();
      return secondDate - firstDate || second.id - first.id;
    }).filter(scan => {
      const target = targetsById[String(scan.target_id)];
      const searchableText = [scan.id, scan.tool_used, scan.status, target?.name, target?.ip_address, target?.hostname].filter(Boolean).join(" ").toLowerCase();
      const matchesSearch = query.length === 0 || searchableText.includes(query);
      const matchesStatus = statusFilter === "all" || scan.status === statusFilter;
      const matchesTool = toolFilter === "all" || scan.tool_used === toolFilter;
      return matchesSearch && matchesStatus && matchesTool;
    });
  }, [scans, search, statusFilter, toolFilter, targetsById]);
  const totalPages = Math.max(1, Math.ceil(filteredScans.length / PAGE_SIZE));
  const currentPage = Math.min(requestedPage, totalPages);
  const visibleScans = useMemo(() => {
    const startIndex = (currentPage - 1) * PAGE_SIZE;
    return filteredScans.slice(startIndex, startIndex + PAGE_SIZE);
  }, [currentPage, filteredScans]);
  const resetFilters = () => {
    setSearch("");
    setStatusFilter("all");
    setToolFilter("all");
    setCurrentPage(1);
  };
  if (loading) {
    return <main style={styles.statePage}>
        <div className="history-spinner" style={styles.spinner} />
        <h2 style={styles.stateTitle}>{t("Loading Scan History")}</h2>
        <p style={styles.muted}>{t("Retrieving saved scans...")}</p>
        <style>{spinnerStyles}</style>
      </main>;
  }
  if (error) {
    return <main style={styles.statePage}>
        <div style={styles.errorIcon}>!</div>
        <h2 style={styles.stateTitle}>{t("Unable to Load History")}</h2>
        <p style={styles.errorText}>{t(error)}</p>
      </main>;
  }
  return <main style={styles.page}>
      <style>{`
        ${spinnerStyles}

        .scan-history-row:hover {
          background: rgba(56, 189, 248, 0.08);
        }

        .scan-history-row:focus {
          outline: 2px solid #38bdf8;
          outline-offset: -2px;
        }

        @media (max-width: 760px) {
          .scan-history-filters {
            grid-template-columns: 1fr !important;
          }

          .scan-history-pagination {
            flex-direction: column;
            align-items: stretch !important;
          }
        }
      `}</style>

      <header style={styles.header}>
        <div>
          <p style={styles.eyebrow}>{t("SCANS")}</p>
          <h1 style={styles.title}>{t("Scan History")}</h1>
          <p style={styles.subtitle}>{t("Search, filter, and review all saved security scans.")}</p>
        </div>
        <div style={styles.totalBox}>
          <span style={styles.totalLabel}>{t("Visible Scans")}</span>
          <strong style={styles.totalValue}>{filteredScans.length}</strong>
        </div>
      </header>
      <ScanComparison scans={scans}/>

      <section className="scan-history-filters" style={styles.filters}>
        <label style={styles.field}>
          <span style={styles.fieldLabel}>{t("Search")}</span>
          <input value={search} onChange={event => {
          setSearch(event.target.value);
          setCurrentPage(1);
        }} placeholder={t("Target, IP, tool, status, or scan ID")} style={styles.input} />
        </label>

        <label style={styles.field}>
          <span style={styles.fieldLabel}>{t("Status")}</span>
          <select value={statusFilter} onChange={event => {
          setStatusFilter(event.target.value);
          setCurrentPage(1);
        }} style={styles.input}>
            <option value="all">{t("All statuses")}</option>
            <option value="completed">{t("Completed")}</option>
            <option value="running">{t("Running")}</option>
            <option value="pending">{t("Pending")}</option>
            <option value="failed">{t("Failed")}</option>
          </select>
        </label>

        <label style={styles.field}>
          <span style={styles.fieldLabel}>{t("Tool")}</span>
          <select value={toolFilter} onChange={event => {
          setToolFilter(event.target.value);
          setCurrentPage(1);
        }} style={styles.input}>
            <option value="all">{t("All tools")}</option>
            <option value="nmap">Nmap</option>
            <option value="whatweb">WhatWeb</option>
            <option value="zap">ZAP</option>
            <option value="nuclei">Nuclei</option>
            <option value="sslyze">SSLyze</option>
          </select>
        </label>

        <button type="button" onClick={resetFilters} style={styles.resetButton}>{t("Reset Filters")}</button>
      </section>

      <section style={styles.panel}>
        {filteredScans.length === 0 ? <div style={styles.emptyState}>{t("No scans match the selected filters.")}</div> : <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>{t("Scan ID")}</th>
                  <th style={styles.th}>{t("Target")}</th>
                  <th style={styles.th}>{t("Tool")}</th>
                  <th style={styles.th}>{t("Status")}</th>
                  <th style={styles.th}>{t("Started")}</th>
                  <th style={styles.th}>{t("Finished")}</th>
                </tr>
              </thead>
              <tbody>
                {visibleScans.map(scan => {
              const target = targetsById[String(scan.target_id)];
              return <tr key={scan.id} className="scan-history-row" tabIndex={0} role="button" onClick={() => navigate(`/scans/${scan.id}`)} onKeyDown={event => {
                if (event.key === "Enter" || event.key === " ") {
                  navigate(`/scans/${scan.id}`);
                }
              }} style={styles.row}>
                      <td style={styles.td}>#{scan.id}</td>
                      <td style={styles.td}>
                        <strong style={styles.targetName}>
                          {target?.name || t("Target {0}", [scan.target_id])}
                        </strong>
                        <span style={styles.targetAddress}>
                          {target?.ip_address || target?.hostname || t("Address not available")}
                        </span>
                      </td>
                      <td style={styles.td}>
                        <span style={styles.toolBadge}>
                          {scan.tool_used || t("unknown")}
                        </span>
                      </td>
                      <td style={styles.td}>
                        <StatusBadge status={scan.status} />
                      </td>
                      <td style={styles.td}>{formatDate(scan.started_at)}</td>
                      <td style={styles.td}>{formatDate(scan.finished_at)}</td>
                    </tr>;
            })}
              </tbody>
            </table>
          </div>}

        {filteredScans.length > 0 && <div className="scan-history-pagination" style={styles.pagination}>
            <span style={styles.paginationText}>{t("Showing ")}{(currentPage - 1) * PAGE_SIZE + 1}-
              {Math.min(currentPage * PAGE_SIZE, filteredScans.length)}{t(" of")}{" "}
              {filteredScans.length}
            </span>

            <div style={styles.paginationControls}>
              <button type="button" onClick={() => setCurrentPage(page => Math.max(1, page - 1))} disabled={currentPage === 1} style={{
            ...styles.pageButton,
            ...(currentPage === 1 ? styles.disabledButton : {})
          }}>{t("Previous")}</button>

              <span style={styles.pageIndicator}>{t("Page ")}{currentPage}{t(" of ")}{totalPages}
              </span>

              <button type="button" onClick={() => setCurrentPage(page => Math.min(totalPages, page + 1))} disabled={currentPage === totalPages} style={{
            ...styles.pageButton,
            ...(currentPage === totalPages ? styles.disabledButton : {})
          }}>{t("Next")}</button>
            </div>
          </div>}
      </section>
    </main>;
}
function StatusBadge({
  status
}) {
  useLocale();
  const colors = {
    completed: {
      background: "#14532d",
      color: "#bbf7d0"
    },
    failed: {
      background: "#7f1d1d",
      color: "#fecaca"
    },
    running: {
      background: "#1e3a8a",
      color: "#bfdbfe"
    },
    pending: {
      background: "#713f12",
      color: "#fef08a"
    }
  };
  return <span style={{
    ...styles.statusBadge,
    ...(colors[status] || {
      background: "#334155",
      color: "#cbd5e1"
    })
  }}>
      {t(status) || t("unknown")}
    </span>;
}
const spinnerStyles = `
  @keyframes history-spin {
    to { transform: rotate(360deg); }
  }

  .history-spinner {
    animation: history-spin 0.8s linear infinite;
  }
`;
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
  spinner: {
    width: "42px",
    height: "42px",
    border: "4px solid #334155",
    borderTopColor: "#38bdf8",
    borderRadius: "50%"
  },
  errorIcon: {
    width: "44px",
    height: "44px",
    display: "grid",
    placeItems: "center",
    borderRadius: "50%",
    background: "#7f1d1d",
    color: "#fecaca",
    fontSize: "24px",
    fontWeight: 800
  },
  stateTitle: {
    margin: "18px 0 6px"
  },
  errorText: {
    color: "#fca5a5"
  },
  muted: {
    margin: 0,
    color: "#94a3b8"
  },
  header: {
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "space-between",
    gap: "24px",
    paddingBottom: "24px",
    marginBottom: "22px",
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
  filters: {
    display: "grid",
    gridTemplateColumns: "minmax(240px, 2fr) 1fr 1fr auto",
    gap: "14px",
    alignItems: "end",
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
  resetButton: {
    minHeight: "42px",
    padding: "10px 14px",
    border: "1px solid #475569",
    borderRadius: "8px",
    background: "#334155",
    color: "#f8fafc",
    fontWeight: 700,
    cursor: "pointer"
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
    textTransform: "uppercase",
    letterSpacing: "0.05em"
  },
  td: {
    padding: "13px 12px",
    borderBottom: "1px solid #334155",
    color: "#cbd5e1",
    fontSize: "13px"
  },
  row: {
    cursor: "pointer",
    transition: "background-color 0.2s ease"
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
  statusBadge: {
    display: "inline-block",
    padding: "4px 9px",
    borderRadius: "999px",
    fontSize: "12px",
    textTransform: "capitalize"
  },
  emptyState: {
    padding: "36px",
    border: "1px dashed #475569",
    borderRadius: "10px",
    color: "#94a3b8",
    textAlign: "center",
    background: "#0f172a"
  },
  pagination: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "16px",
    paddingTop: "18px"
  },
  paginationText: {
    color: "#94a3b8",
    fontSize: "13px"
  },
  paginationControls: {
    display: "flex",
    alignItems: "center",
    gap: "10px"
  },
  pageButton: {
    padding: "8px 12px",
    border: "1px solid #0ea5e9",
    borderRadius: "7px",
    background: "#075985",
    color: "#ffffff",
    fontWeight: 700,
    cursor: "pointer"
  },
  disabledButton: {
    borderColor: "#475569",
    background: "#334155",
    color: "#94a3b8",
    cursor: "not-allowed",
    opacity: 0.65
  },
  pageIndicator: {
    minWidth: "92px",
    color: "#cbd5e1",
    fontSize: "13px",
    textAlign: "center"
  }
};
