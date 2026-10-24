import { t, useLocale, getLocale } from "../i18n/language";
import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { getScanDetails } from "../api/dashboard";
import ExportPdfButton from "../components/ExportPdfButton";
import FindingReview from "../components/FindingReview";
import { typeLabel } from "../i18n/finding-labels";
import FindingLocation from "../components/FindingLocation";
const severityColors = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#22c55e",
  Info: "#3b82f6"
};
const confidenceColors = {
  High: "#22c55e",
  Medium: "#eab308",
  Low: "#94a3b8"
};
function formatVerificationStatus(value) {
  return {
    confirmed: "Confirmed",
    needs_review: "Needs review",
    informational: "Informational",
    false_positive: "False positive"
  }[value] || "Needs review";
}
const MINIMUM_LOADING_TIME = 500;
const animations = `
  @keyframes scan-details-spin {
    to { transform: rotate(360deg); }
  }

  @keyframes scan-details-pulse {
    0%, 100% { opacity: 0.55; transform: scale(0.96); }
    50% { opacity: 1; transform: scale(1); }
  }

  @keyframes scan-details-enter {
    from { opacity: 0; transform: translateY(12px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .scan-details-spinner {
    animation: scan-details-spin 0.8s linear infinite;
  }

  .scan-details-loading-text {
    animation: scan-details-pulse 1.25s ease-in-out infinite;
  }

  .scan-details-page-enter {
    animation: scan-details-enter 0.35s ease-out both;
  }

  @media (prefers-reduced-motion: reduce) {
    .scan-details-spinner,
    .scan-details-loading-text,
    .scan-details-page-enter {
      animation: none;
    }
  }

  @media (max-width: 760px) {
    .scan-details-header {
      flex-direction: column;
    }

    .scan-details-actions {
      width: 100%;
      justify-content: space-between;
    }
  }
`;
function formatDate(value) {
  if (!value) return "Not available";
  return new Date(value).toLocaleString(getLocale());
}
function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return "Not available";
  if (seconds < 60) return `${seconds} sec`;
  return `${Math.floor(seconds / 60)} min ${seconds % 60} sec`;
}
function getRiskLevel(counts) {
  if (counts?.Critical) return "Critical";
  if (counts?.High) return "High";
  if (counts?.Medium) return "Medium";
  if (counts?.Low) return "Low";
  return "Info";
}
function cleanFindingDescription(description) {
  if (!description) return "No description is available.";
  const metadataLine = /^(Affected URL|Path|Port|HTTP Method|Confidence|Parameter|Evidence|Source Tool)\s*:\s*.*$/gim;
  const cleaned = description.replace(metadataLine, "").replace(/\n{3,}/g, "\n\n").trim();
  return cleaned || "No additional description is available.";
}
function getLocationKey(finding) {
  return String(finding.id);
}
function groupFindings(findings = []) {
  const groups = new Map();
  findings.forEach(finding => {
    const key = finding.fingerprint || String(finding.id);
    if (!groups.has(key)) {
      groups.set(key, {
        ...finding,
        description: cleanFindingDescription(finding.description),
        locations: [],
        locationKeys: new Set()
      });
    }
    const group = groups.get(key);
    const locationKey = getLocationKey(finding);
    if (!group.locationKeys.has(locationKey)) {
      group.locationKeys.add(locationKey);
      group.locations.push(finding);
    }
  });
  return [...groups.values()].map(entry => ({
    ...entry,
    locationKeys: undefined
  }));
}
export default function ScanDetails() {
  useLocale();
  const {
    id
  } = useParams();
  const navigate = useNavigate();
  const [details, setDetails] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    async function loadScan() {
      setLoading(true);
      setError("");
      try {
        const [response] = await Promise.all([getScanDetails(id), new Promise(resolve => window.setTimeout(resolve, MINIMUM_LOADING_TIME))]);
        if (active) setDetails(response.data);
      } catch (requestError) {
        if (active) {
          setError(requestError.response?.data?.error || "The scan details could not be loaded.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    loadScan();
    return () => {
      active = false;
    };
  }, [id]);
  const recommendations = useMemo(() => {
    if (!details?.vulnerabilities) return [];
    return [...new Set(details.vulnerabilities.map(finding => finding.ai_recommendation).filter(Boolean))];
  }, [details]);
  const groupedFindings = useMemo(() => groupFindings(details?.vulnerabilities || []), [details]);
  if (loading) {
    return <main style={styles.statePage}>
        <style>{animations}</style>
        <div className="scan-details-spinner" style={styles.spinner} />
        <h2 className="scan-details-loading-text" style={styles.stateTitle}>{t("Loading Scan...")}</h2>
        <p style={styles.muted}>{t("Retrieving the latest saved scan data...")}</p>
      </main>;
  }
  if (error) {
    return <main style={styles.statePage}>
        <style>{animations}</style>
        <div style={styles.errorIcon}>!</div>
        <h2 style={styles.stateTitle}>{t("Unable to Load Scan")}</h2>
        <p style={styles.errorText}>{t(error)}</p>
        <button type="button" style={styles.primaryButton} onClick={() => navigate("/dashboard")}>{t("Back to Dashboard")}</button>
      </main>;
  }
  const {
    scan,
    target,
    ports = [],
    services = [],
    vulnerabilities = []
  } = details;
  const riskLevel = getRiskLevel(details.potential_severity_counts || details.severity_counts);
  return <main data-scan-report className="scan-details-page-enter" style={styles.page}>
      <style>{animations}</style>

      <header className="scan-details-header" style={styles.header}>
        <div>
          <button type="button" style={styles.backButton} onClick={() => navigate(-1)}>
            {t("\u2190 Back")}
          </button>

          <p style={styles.eyebrow}>{t("SCAN #")}{scan.id}</p>
          <h1 style={styles.title}>{t("Scan Details")}</h1>
          <p style={styles.subtitle}>{t("Review the target, detected services, findings, and recommended actions.")}</p>
        </div>

        <div className="scan-details-actions" style={styles.headerActions}>
          <ExportPdfButton scanId={scan.id} />

          <span style={{
          ...styles.statusBadge,
          ...(scan.status === "completed" ? styles.completed : scan.status === "failed" ? styles.failed : styles.running)
        }}>
            {t(scan.status)}
          </span>
        </div>
      </header>

      <section style={styles.summaryGrid}>
        <SummaryCard label={t("Target")} value={target.name} detail={target.ip_address || target.hostname} />
        <SummaryCard label={t("Tool")} value={scan.tool_used?.toUpperCase()} detail={`Port ${target.port || "N/A"}`} />
        <SummaryCard label={t("Duration")} value={formatDuration(scan.duration_seconds)} detail={formatDate(scan.started_at)} />
        <SummaryCard label={t("Risk Level")} value={riskLevel} accent={severityColors[riskLevel]} detail={`${vulnerabilities.length} findings`} />
      </section>

      <Panel title={t("Open Ports")} subtitle="Network services parsed from the saved Nmap result." count={ports.length}>
        {ports.length ? <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>{t("Port")}</th>
                  <th style={styles.th}>{t("Protocol")}</th>
                  <th style={styles.th}>{t("Service")}</th>
                  <th style={styles.th}>{t("Version")}</th>
                  <th style={styles.th}>{t("State")}</th>
                </tr>
              </thead>
              <tbody>
                {ports.map(port => <tr key={`${port.port}-${port.protocol}`}>
                    <td style={styles.td}>{port.port}</td>
                    <td style={styles.td}>{port.protocol.toUpperCase()}</td>
                    <td style={styles.td}>{port.service || t("Unknown")}</td>
                    <td style={styles.td}>
                      {port.version || t("Not detected")}
                    </td>
                    <td style={styles.td}>
                      <span style={styles.openBadge}>{port.state}</span>
                    </td>
                  </tr>)}
              </tbody>
            </table>
          </div> : <EmptyState text={t(scan.tool_used === "nmap" ? t("No open ports were found in the saved result.") : t("Port data is only available for Nmap scans."))} />}
      </Panel>

      <Panel title={t("Detected Services")} subtitle="Services and versions identified during this scan." count={services.length}>
        {services.length ? <div style={styles.serviceGrid}>
            {services.map(service => <article key={`${service.port}-${service.protocol}`} style={styles.serviceCard}>
                <span style={styles.servicePort}>
                  {service.port}/{service.protocol}
                </span>
                <strong style={styles.serviceName}>
                  {service.name || t("Unknown service")}
                </strong>
                <span style={styles.muted}>
                  {service.version || t("Version not detected")}
                </span>
              </article>)}
          </div> : <EmptyState text={t("No structured service data is available for this scan.")} />}
      </Panel>

      <Panel title={t("Security Findings")} subtitle="Saved vulnerabilities and informational findings for this scan." count={vulnerabilities.length}>
        {vulnerabilities.length ? <div style={styles.findingsList}>
            {groupedFindings.map(finding => <article key={finding.id} style={styles.findingCard}>
                <div style={styles.findingTop}>
                  <div>
                    <h3 style={styles.findingTitle}>{finding.title}</h3>
                    {finding.cve_id && <span style={styles.cve}>{finding.cve_id}</span>}
                  </div>

                  <div style={styles.findingBadges}>
                    <span style={{
                ...styles.severityBadge,
                backgroundColor: `${severityColors[finding.severity] || "#64748b"}22`,
                color: severityColors[finding.severity] || "#cbd5e1"
              }}>
                      {t(finding.severity)}
                    </span>
                    <span style={{
                ...styles.qualityBadge,
                color: confidenceColors[finding.confidence] || "#e2e8f0"
              }}>{t("Confidence: ")}{t(finding.confidence) || t("Medium")}
                    </span>
                    <span style={styles.reviewBadge}>
                      {t("Scanner assessment")}: {t(formatVerificationStatus(finding.verification_status))}
                    </span>
                    <span style={styles.riskBadge}>{t("Risk ")}{finding.risk_score ?? "-"}/10
                    </span>
                  </div>
                </div>

                <p>{typeLabel(finding.finding_type)}</p>
                <FindingLocations finding={finding} />
                {(finding.locations || [finding]).map(entry=><FindingReview key={`${entry.id}-${entry.review_revision || 0}`} finding={entry} onSaved={async ()=>{try{const response=await getScanDetails(id);setDetails(response.data);}catch{setError('The scan details could not be loaded.');}}}/>)}

                <p style={styles.description}>
                  {finding.description || t("No description is available.")}
                </p>

                {finding.ai_recommendation && <div style={styles.recommendationInline}>
                    <strong>{t("Recommendation")}</strong>
                    <span>{finding.ai_recommendation}</span>
                  </div>}
              </article>)}
          </div> : <EmptyState text={t("No findings were saved for this scan.")} />}
      </Panel>

      <Panel title={t("Recommended Actions")} subtitle="Consolidated remediation guidance from the saved findings.">
        {recommendations.length ? <ol style={styles.recommendationList}>
            {recommendations.map((recommendation, index) => <li key={`${index}-${recommendation}`} style={styles.recommendationItem}>
                <span style={styles.check}>{"\u2713"}</span>
                <span>{recommendation}</span>
              </li>)}
          </ol> : <EmptyState text={t("No remediation guidance is available for this scan.")} />}
      </Panel>
    </main>;
}
function SummaryCard({
  label,
  value,
  detail,
  accent = "#38bdf8"
}) {
  useLocale();
  return <article style={{
    ...styles.summaryCard,
    borderTopColor: accent
  }}>
      <span style={styles.summaryLabel}>{t(label)}</span>
      <strong style={styles.summaryValue}>{t(value) || t("Not available")}</strong>
      <span style={styles.summaryDetail}>{detail || t("Not available")}</span>
    </article>;
}
function Panel({
  title,
  subtitle,
  count,
  children
}) {
  useLocale();
  return <section style={styles.panel}>
      <div style={styles.panelHeader}>
        <div>
          <h2 style={styles.panelTitle}>{t(title)}</h2>
          <p style={styles.muted}>{subtitle}</p>
        </div>
        {count !== undefined && <span style={styles.countBadge}>{count}</span>}
      </div>
      {children}
    </section>;
}
function EmptyState({
  text
}) {
  useLocale();
  return <div style={styles.emptyState}>{t(text)}</div>;
}
function FindingLocations({
  finding
}) {
  useLocale();
  const [expanded, setExpanded] = useState(false);
  const [copiedKey, setCopiedKey] = useState("");
  const locations = finding.locations || [];
  const visibleLocations = expanded ? locations : locations.slice(0, 1);
  const hiddenCount = Math.max(locations.length - 1, 0);
  async function copyUrl(location, locationIndex) {
    if (!location.affected_url) return;
    const key = `${finding.id}-${locationIndex}`;
    try {
      await navigator.clipboard.writeText(location.affected_url);
      setCopiedKey(key);
      window.setTimeout(() => setCopiedKey(""), 1600);
    } catch (copyError) {
      console.error("Unable to copy the affected URL:", copyError);
    }
  }
  function openUrl(location) {
    const url = location.affected_url || "";
    if (!/^https?:\/\//i.test(url)) return;
    window.open(url, "_blank", "noopener,noreferrer");
  }
  return <div>
      {locations.length > 1 && <div style={styles.locationSummary}>
          <div style={styles.locationSummaryText}>
            <strong>{locations.length}{t(" affected locations")}</strong>
            <span>{t("The scanner reported this finding on multiple resources.")}</span>
          </div>

          <button type="button" style={styles.locationToggleButton} onClick={() => setExpanded(current => !current)} aria-expanded={expanded}>
            {expanded ? t("Hide additional locations") : t("Show {0} more {1}", [hiddenCount, hiddenCount === 1 ? "location" : "locations"])}
          </button>
        </div>}

      <div style={styles.locationList}>
        {visibleLocations.map((location, locationIndex) => {
        const copyKey = `${finding.id}-${locationIndex}`;
        return <div key={`${finding.id}-${getLocationKey(location)}-${locationIndex}`} style={styles.locationItem}>
              <div style={styles.locationToolbar}>
                {locations.length > 1 && <span style={styles.locationNumber}>{t("Location ")}{locationIndex + 1}
                  </span>}

                {location.affected_url && <div style={styles.locationActions}>
                    {/^https?:\/\//i.test(location.affected_url) && <button type="button" style={styles.openUrlButton} onClick={() => openUrl(location)} title={t("Open affected URL in a new tab")}>{t("Open URL")}</button>}

                    <button type="button" style={styles.copyUrlButton} onClick={() => copyUrl(location, locationIndex)} title={t("Copy affected URL")}>
                      {copiedKey === copyKey ? t("Copied!") : t("Copy URL")}
                    </button>
                  </div>}
              </div>

              <FindingLocation finding={location} />

              <p style={styles.validationNotice}>{t("Scanner-reported location. Validate the finding before treating it as a confirmed vulnerability.")}</p>
            </div>;
      })}
      </div>
    </div>;
}
const styles = {
  page: {
    minHeight: "100vh",
    padding: "28px",
    color: "#f8fafc",
    background: "#0f172a",
    direction: "ltr"
  },
  statePage: {
    minHeight: "70vh",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    color: "#f8fafc",
    background: "#0f172a",
    textAlign: "center",
    padding: "24px"
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
    fontWeight: 800,
    fontSize: "24px"
  },
  stateTitle: {
    margin: "18px 0 6px"
  },
  errorText: {
    color: "#fca5a5",
    maxWidth: "520px"
  },
  primaryButton: {
    marginTop: "14px",
    padding: "10px 16px",
    border: 0,
    borderRadius: "8px",
    color: "#ffffff",
    background: "#2563eb",
    cursor: "pointer"
  },
  header: {
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "space-between",
    gap: "24px",
    paddingBottom: "24px",
    borderBottom: "1px solid #334155",
    marginBottom: "24px"
  },
  headerActions: {
    display: "flex",
    alignItems: "center",
    gap: "12px"
  },
  backButton: {
    padding: 0,
    border: 0,
    background: "transparent",
    color: "#38bdf8",
    cursor: "pointer",
    fontSize: "14px"
  },
  eyebrow: {
    margin: "20px 0 6px",
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
    color: "#94a3b8",
    maxWidth: "680px"
  },
  statusBadge: {
    padding: "8px 13px",
    borderRadius: "999px",
    fontSize: "12px",
    fontWeight: 800,
    textTransform: "capitalize"
  },
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
  summaryGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
    gap: "16px",
    marginBottom: "20px"
  },
  summaryCard: {
    display: "flex",
    flexDirection: "column",
    gap: "8px",
    minWidth: 0,
    padding: "20px",
    background: "#1e293b",
    border: "1px solid #334155",
    borderTop: "4px solid #38bdf8",
    borderRadius: "12px"
  },
  summaryLabel: {
    color: "#94a3b8",
    fontSize: "12px",
    textTransform: "uppercase",
    letterSpacing: "0.08em"
  },
  summaryValue: {
    overflow: "hidden",
    textOverflow: "ellipsis",
    fontSize: "21px"
  },
  summaryDetail: {
    overflow: "hidden",
    textOverflow: "ellipsis",
    color: "#94a3b8",
    fontSize: "13px"
  },
  panel: {
    marginTop: "20px",
    padding: "22px",
    background: "#1e293b",
    border: "1px solid #334155",
    borderRadius: "12px"
  },
  panelHeader: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "18px",
    marginBottom: "18px"
  },
  panelTitle: {
    margin: "0 0 5px",
    fontSize: "18px"
  },
  muted: {
    margin: 0,
    color: "#94a3b8",
    fontSize: "13px"
  },
  countBadge: {
    minWidth: "30px",
    padding: "5px 9px",
    textAlign: "center",
    borderRadius: "999px",
    color: "#bae6fd",
    background: "#0c4a6e",
    fontSize: "12px",
    fontWeight: 800
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
    textAlign: "left",
    color: "#94a3b8",
    borderBottom: "1px solid #475569",
    fontSize: "12px",
    textTransform: "uppercase",
    letterSpacing: "0.05em"
  },
  td: {
    padding: "13px 12px",
    borderBottom: "1px solid #334155",
    fontSize: "14px"
  },
  openBadge: {
    padding: "4px 9px",
    borderRadius: "999px",
    color: "#bbf7d0",
    background: "#14532d",
    fontSize: "12px",
    textTransform: "capitalize"
  },
  serviceGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
    gap: "12px"
  },
  serviceCard: {
    display: "flex",
    flexDirection: "column",
    gap: "7px",
    padding: "16px",
    border: "1px solid #334155",
    borderRadius: "10px",
    background: "#0f172a"
  },
  servicePort: {
    color: "#38bdf8",
    fontSize: "12px",
    fontWeight: 800
  },
  serviceName: {
    fontSize: "16px"
  },
  findingsList: {
    display: "grid",
    gap: "12px"
  },
  findingCard: {
    padding: "18px",
    border: "1px solid #334155",
    borderRadius: "10px",
    background: "#0f172a"
  },
  findingTop: {
    display: "flex",
    alignItems: "flex-start",
    justifyContent: "space-between",
    gap: "14px"
  },
  locationSummary: {
    display: "flex",
    flexWrap: "wrap",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "8px 16px",
    marginTop: "16px",
    padding: "11px 13px",
    border: "1px solid #075985",
    borderRadius: "9px",
    background: "rgba(3, 105, 161, 0.14)",
    color: "#bae6fd",
    fontSize: "13px"
  },
  locationSummaryText: {
    display: "flex",
    flexDirection: "column",
    gap: "4px"
  },
  locationToggleButton: {
    padding: "8px 12px",
    border: "1px solid #0284c7",
    borderRadius: "8px",
    background: "#075985",
    color: "#e0f2fe",
    cursor: "pointer",
    fontSize: "12px",
    fontWeight: 800
  },
  locationList: {
    display: "grid",
    gap: "10px",
    marginTop: "12px"
  },
  locationItem: {
    minWidth: 0
  },
  locationToolbar: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "10px",
    marginBottom: "6px"
  },
  locationActions: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    marginLeft: "auto"
  },
  locationNumber: {
    display: "inline-block",
    marginBottom: "6px",
    padding: "4px 8px",
    borderRadius: "999px",
    background: "#0c4a6e",
    color: "#bae6fd",
    fontSize: "11px",
    fontWeight: 800
  },
  copyUrlButton: {
    padding: "6px 10px",
    border: "1px solid #334155",
    borderRadius: "7px",
    background: "#172033",
    color: "#7dd3fc",
    cursor: "pointer",
    fontSize: "11px",
    fontWeight: 800
  },
  openUrlButton: {
    padding: "6px 10px",
    border: "1px solid #0284c7",
    borderRadius: "7px",
    background: "#0369a1",
    color: "#e0f2fe",
    cursor: "pointer",
    fontSize: "11px",
    fontWeight: 800
  },
  validationNotice: {
    margin: "8px 0 0",
    color: "#94a3b8",
    fontSize: "11px",
    lineHeight: 1.5
  },
  findingTitle: {
    margin: 0,
    fontSize: "16px"
  },
  cve: {
    display: "inline-block",
    marginTop: "7px",
    color: "#7dd3fc",
    fontSize: "12px"
  },
  findingBadges: {
    display: "flex",
    flexWrap: "wrap",
    justifyContent: "flex-end",
    gap: "7px",
    maxWidth: "55%"
  },
  severityBadge: {
    padding: "5px 9px",
    borderRadius: "999px",
    fontSize: "12px",
    fontWeight: 800
  },
  qualityBadge: {
    padding: "5px 9px",
    border: "1px solid #334155",
    borderRadius: "999px",
    background: "#172033",
    fontSize: "11px",
    fontWeight: 800
  },
  reviewBadge: {
    padding: "5px 9px",
    border: "1px solid #7c3aed55",
    borderRadius: "999px",
    background: "#4c1d952e",
    color: "#c4b5fd",
    fontSize: "11px",
    fontWeight: 800
  },
  riskBadge: {
    padding: "5px 9px",
    border: "1px solid #0ea5e955",
    borderRadius: "999px",
    background: "#0759852e",
    color: "#7dd3fc",
    fontSize: "11px",
    fontWeight: 800
  },
  description: {
    margin: "14px 0",
    color: "#cbd5e1",
    lineHeight: 1.65,
    whiteSpace: "pre-line",
    overflowWrap: "anywhere",
    textAlign: "left"
  },
  recommendationInline: {
    display: "flex",
    flexDirection: "column",
    gap: "6px",
    padding: "12px 14px",
    borderLeft: "3px solid #38bdf8",
    background: "#172033",
    color: "#cbd5e1",
    fontSize: "13px"
  },
  recommendationList: {
    display: "grid",
    gap: "10px",
    listStyle: "none",
    padding: 0,
    margin: 0
  },
  recommendationItem: {
    display: "flex",
    gap: "11px",
    alignItems: "flex-start",
    padding: "13px",
    borderRadius: "9px",
    background: "#0f172a",
    color: "#cbd5e1"
  },
  check: {
    color: "#22c55e",
    fontWeight: 900
  },
  emptyState: {
    padding: "28px",
    border: "1px dashed #475569",
    borderRadius: "10px",
    color: "#94a3b8",
    textAlign: "center",
    background: "#0f172a"
  }
};
