import { t, useLocale, getLocale } from "../i18n/language";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { reviewLabel } from "../i18n/finding-labels";
import FindingReview from "../components/FindingReview";
import { getVulnerabilities } from "../api/dashboard";
const PAGE_SIZE = 10;
const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
const severityColors = {
  Critical: {
    background: "#7f1d1d",
    color: "#fecaca",
    accent: "#ef4444"
  },
  High: {
    background: "#7c2d12",
    color: "#fed7aa",
    accent: "#f97316"
  },
  Medium: {
    background: "#713f12",
    color: "#fef08a",
    accent: "#eab308"
  },
  Low: {
    background: "#14532d",
    color: "#bbf7d0",
    accent: "#22c55e"
  },
  Info: {
    background: "#1e3a8a",
    color: "#bfdbfe",
    accent: "#3b82f6"
  }
};
function formatDate(value) {
  if (!value) return "Not available";
  return new Date(value.replace(" ", "T")).toLocaleString(getLocale());
}
export default function Vulnerabilities() {
  useLocale();
  const navigate = useNavigate();
  const [findings, setFindings] = useState([]);
  const [findingType,setFindingType]=useState('potential_vulnerability');
  const onReviewed = data => setFindings(rows=>rows.map(item=>item.id===data.id ? {...item,...data} : item));
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [tool, setTool] = useState("all");
  const [status, setStatus] = useState("all");
  const [requestedPage, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [groupSimilar, setGroupSimilar] = useState(true);
  useEffect(() => {
    let active = true;
    async function loadFindings() {
      try {
        const response = await getVulnerabilities();
        if (active) setFindings(response.data);
      } catch (requestError) {
        if (active) {
          setError(requestError.response?.data?.error || "The vulnerability data could not be loaded.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    loadFindings();
    return () => {
      active = false;
    };
  }, []);
  const tools = useMemo(() => [...new Set(findings.map(item => item.tool_used).filter(Boolean))].sort(), [findings]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return findings.filter(item => {
      const text = [item.id, item.scan_id, item.cve_id, item.title, item.description, item.tool_used, item.target?.name, item.target?.ip_address, item.target?.hostname].filter(Boolean).join(" ").toLowerCase();
      return (!query || text.includes(query)) && (severity === "all" || item.severity === severity) && (tool === "all" || item.tool_used === tool) && (status === "all" || item.review_state === status) && item.finding_type === findingType;
    });
  }, [findings, search, severity, tool, status, findingType]);
  const grouped = useMemo(() => {
    if (!groupSimilar) return filtered;
    const groups = new Map();
    for (const item of filtered) {
      const key = item.fingerprint || String(item.id);
      if (!groups.has(key)) groups.set(key, {
        ...item,
        occurrences: []
      });
      const group=groups.get(key);
      if(SEVERITIES.indexOf(item.severity)<SEVERITIES.indexOf(group.severity))group.severity=item.severity;
      group.occurrences.push(item);
    }
    return [...groups.values()];
  }, [filtered, groupSimilar]);
  const counts = useMemo(() => Object.fromEntries(SEVERITIES.map(level => [level, grouped.filter(item => item.severity === level).length])), [grouped]);
  const totalPages = Math.max(1, Math.ceil(grouped.length / PAGE_SIZE));
  const page = Math.min(requestedPage, totalPages);
  const visible = grouped.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const reset = () => {
    setPage(1);
    setSearch("");
    setSeverity("all");
    setTool("all");
    setStatus("all");
  };
  if (loading) return <StateView title={t("Loading Vulnerabilities")} text={t("Retrieving saved security findings...")} />;
  if (error) return <StateView title={t("Unable to Load Vulnerabilities")} text={t(error)} error />;
  return <main style={styles.page}>
      <style>{`
        .vulnerability-filters { grid-template-columns: minmax(0, 2fr) repeat(3, minmax(0, 1fr)) auto; }
        @media (max-width: 1200px) {
          .vulnerability-filters { grid-template-columns: repeat(2, minmax(0, 1fr)); }
          .vulnerability-filter-search { grid-column: 1 / -1; }
        }
        @media (max-width: 640px) {
          .vulnerability-filters { grid-template-columns: minmax(0, 1fr); }
        }
        .vulnerability-row:hover { background: rgba(56,189,248,.08); }
        .vulnerability-row:focus { outline: 2px solid #38bdf8; outline-offset: -2px; }
      `}</style>

      <header style={styles.header}>
        <div>
          <p style={styles.eyebrow}>{t("SECURITY FINDINGS")}</p>
          <h1 style={styles.title}>{t("Vulnerabilities")}</h1>
          <p style={styles.subtitle}>{t("Review and prioritize findings from every integrated scanner.")}</p>
        </div>
        <div style={styles.totalBox}>
          <span style={styles.totalLabel}>{t("Visible Findings")}</span>
          <strong style={styles.totalValue}>{grouped.length}</strong>
        </div>
      </header>

      <section className="quality-tabs" style={{display:'flex',gap:12,flexWrap:'wrap',marginBlock:16}}>
        <button type="button" aria-pressed={findingType==='potential_vulnerability'} onClick={()=>{setFindingType('potential_vulnerability');setPage(1);}}>{t('Potential vulnerabilities')}</button>
        <button type="button" aria-pressed={findingType==='information'} onClick={()=>{setFindingType('information');setPage(1);}}>{t('Informational observations')}</button>
        <p>{t('Historical occurrences are retained. Grouping preserves each tool, location and evidence.')}</p>
      </section>
      <section style={styles.summaryGrid}>
        {SEVERITIES.map(level => <button type="button" key={level} onClick={() => {
        setSeverity(severity === level ? "all" : level);
        setPage(1);
      }} style={{
        ...styles.summaryCard,
        borderTop: `3px solid ${severityColors[level].accent}`,
        ...(severity === level ? styles.selectedCard : {})
      }}>
            <span style={styles.summaryLabel}>{t(level)}</span>
            <strong style={styles.summaryValue}>{counts[level]}</strong>
          </button>)}
      </section>

      <section className="vulnerability-filters" style={styles.filters}>
        <Field label={t("Search")} className="vulnerability-filter-search">
          <input style={styles.input} value={search} onChange={e => {
          setSearch(e.target.value);
          setPage(1);
        }} placeholder={t("Title, CVE, target, IP, scan ID, or tool")} />
        </Field>
        <Field label={t("Severity")}>
          <select style={styles.input} value={severity} onChange={e => {
          setSeverity(e.target.value);
          setPage(1);
        }}>
            <option value="all">{t("All severities")}</option>
            {SEVERITIES.map(level => <option key={level} value={level}>{t(level)}</option>)}
          </select>
        </Field>
        <Field label={t("Tool")}>
          <select style={styles.input} value={tool} onChange={e => {
          setTool(e.target.value);
          setPage(1);
        }}>
            <option value="all">{t("All tools")}</option>
            {tools.map(name => <option key={name} value={name}>{name.toUpperCase()}</option>)}
          </select>
        </Field>
        <Field label={t("Review state")}>
          <select style={styles.input} value={status} onChange={e => {
          setStatus(e.target.value);
          setPage(1);
        }}>
            <option value="all">{t("All statuses")}</option>
            <option value="needs_review">{reviewLabel("needs_review")}</option>
            <option value="confirmed">{reviewLabel("confirmed")}</option>
            <option value="fixed">{t("Fixed")}</option>
            <option value="false_positive">{reviewLabel("false_positive")}</option>
          </select>
        </Field>
        <button type="button" onClick={reset} style={styles.resetButton}>{t("Reset Filters")}</button>
      </section>

      <section style={styles.panel}>
        <label style={{
        display: 'block',
        marginBottom: 16
      }}><input type="checkbox" checked={groupSimilar} onChange={event => {
          setGroupSimilar(event.target.checked);
          setPage(1);
        }} />{t(" Group similar findings")}</label>
        <p>{t("Severity counts describe displayed historical groups, not active dashboard risk.")}</p>
        <p style={styles.meta}>{filtered.length}{t(" records \xB7 ")}{grouped.length}{t(" displayed groups. Confidence is not confirmation; review the evidence and scan completion state.")}</p>
        {filtered.length === 0 ? <div style={styles.empty}>{t("No findings match the selected filters.")}</div> : <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead><tr>
                <th style={styles.th}>{t("Finding")}</th><th style={styles.th}>{t("Severity")}</th>
                <th style={styles.th}>{t("Target")}</th><th style={styles.th}>{t("Tool")}</th>
                <th style={styles.th}>{t("Status / Review")}</th><th style={styles.th}>{t("Detected")}</th>
              </tr></thead>
              <tbody>{visible.map(item => <tr key={item.id} className="vulnerability-row" tabIndex={0} role="button" onClick={() => navigate(`/scans/${item.scan_id}`)} onKeyDown={e => {
              if (e.key === "Enter" || e.key === " ") navigate(`/scans/${item.scan_id}`);
            }} style={styles.row}>
                  <td style={styles.td}>
                    <strong style={styles.findingTitle}>{item.title}</strong>
                    <span style={styles.meta}>{item.cve_id || t("Finding #{0}", [item.id])}{t(" \xB7 Scan #")}{item.scan_id}</span>
                    {item.occurrences?.length > 1 && <details onClick={event => event.stopPropagation()} onKeyDown={event => event.stopPropagation()}><summary>{item.occurrences.length}{t(" occurrences")}</summary>{item.occurrences.map(entry => <button type="button" key={entry.id} onClick={() => navigate(`/scans/${entry.scan_id}`)} style={{
                    display: 'block'
                  }}>{t("Scan #")}{entry.scan_id}: {entry.source_tool} · {entry.affected_url || entry.affected_path || '/'}</button>)}</details>}
                  </td>
                  <td style={styles.td}><SeverityBadge value={item.severity} /></td>
                  <td style={styles.td}>
                    <strong style={styles.targetName}>{item.target?.name || t("Unknown target")}</strong>
                    <span style={styles.meta}>{item.target?.ip_address || item.target?.hostname || t("Address unavailable")}</span>
                  </td>
                  <td style={styles.td}><span style={styles.toolBadge}>{[...new Set((item.occurrences || [item]).map(entry=>entry.source_tool || entry.tool_used))].join(', ') || t("unknown")}</span></td>
                  <td style={styles.td}><span style={styles.statusBadge}>{t(item.status) || t("open")}</span><span style={styles.meta}>{item.occurrences?.some(entry=>entry.review_state!==item.review_state) ? t('Mixed reviews') : reviewLabel(item.review_state)} · {t(item.confidence) || t("Medium")}{t(" confidence")}</span></td>
                  <td style={styles.td}>{formatDate(item.created_at)}<details onClick={event=>event.stopPropagation()} onKeyDown={event=>event.stopPropagation()}><summary>{t('Evidence and review')}</summary>{(item.occurrences || [item]).map(entry=><section key={entry.id}><p>#{entry.id} · {entry.source_tool} · {entry.affected_url || entry.affected_path}</p><pre dir="ltr" style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere',maxWidth:360}}>{entry.evidence}</pre><FindingReview key={`${entry.id}-${entry.review_revision || 0}`} finding={entry} onSaved={onReviewed}/></section>)}</details></td>
                </tr>)}</tbody>
            </table>
          </div>}

        {filtered.length > 0 && <div style={styles.pagination}>
          <span style={styles.meta}>{t("Showing ")}{(page - 1) * PAGE_SIZE + 1}-{Math.min(page * PAGE_SIZE, grouped.length)}{t(" of ")}{grouped.length} {groupSimilar ? t('groups') : t('records')}</span>
          <div style={styles.pageControls}>
            <button style={styles.pageButton} disabled={page === 1} onClick={() => setPage(p => p - 1)}>{t("Previous")}</button>
            <span style={styles.pageText}>{t("Page ")}{page}{t(" of ")}{totalPages}</span>
            <button style={styles.pageButton} disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>{t("Next")}</button>
          </div>
        </div>}
      </section>
    </main>;
}
function Field({
  label,
  children,
  className
}) {
  useLocale();
  return <label className={className} style={styles.field}><span style={styles.fieldLabel}>{t(label)}</span>{children}</label>;
}
function SeverityBadge({
  value
}) {
  useLocale();
  return <span style={{
    ...styles.badge,
    ...(severityColors[value] || severityColors.Info)
  }}>{t(value) || t("Info")}</span>;
}
function StateView({
  title,
  text,
  error
}) {
  useLocale();
  return <main style={styles.statePage}><div style={error ? styles.errorIcon : styles.spinner}>{error ? "!" : ""}</div><h2>{t(title)}</h2><p style={error ? styles.errorText : styles.subtitle}>{t(text)}</p></main>;
}
const styles = {
  page: {
    boxSizing: "border-box",
    minWidth: 0,
    textAlign: "start",
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif",
    minHeight: "100vh",
    padding: "28px",
    background: "#0f172a",
    color: "#f8fafc",
    direction: "inherit"
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
    width: 42,
    height: 42,
    border: "4px solid #334155",
    borderTopColor: "#38bdf8",
    borderRadius: "50%"
  },
  errorIcon: {
    width: 44,
    height: 44,
    display: "grid",
    placeItems: "center",
    borderRadius: "50%",
    background: "#7f1d1d",
    color: "#fecaca",
    fontSize: 24,
    fontWeight: 800
  },
  errorText: {
    color: "#fca5a5"
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    gap: 24,
    paddingBottom: 24,
    marginBottom: 20,
    borderBottom: "1px solid #334155"
  },
  eyebrow: {
    margin: "0 0 7px",
    color: "#38bdf8",
    fontSize: 12,
    fontWeight: 800,
    letterSpacing: ".12em"
  },
  title: {
    margin: 0,
    fontSize: 30,
    color: "#f8fafc"
  },
  subtitle: {
    margin: "8px 0 0",
    color: "#94a3b8"
  },
  totalBox: {
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-end",
    padding: "12px 16px",
    border: "1px solid #334155",
    borderRadius: 10,
    background: "#1e293b"
  },
  totalLabel: {
    color: "#94a3b8",
    fontSize: 12
  },
  totalValue: {
    color: "#38bdf8",
    fontSize: 24
  },
  summaryGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(5, 1fr)",
    gap: 12,
    marginBottom: 20
  },
  summaryCard: {
    padding: "14px 16px",
    border: "1px solid #334155",
    borderRadius: 10,
    background: "#1e293b",
    color: "#f8fafc",
    textAlign: "left",
    cursor: "pointer"
  },
  selectedCard: {
    boxShadow: "0 0 0 2px rgba(56,189,248,.45)"
  },
  summaryLabel: {
    display: "block",
    color: "#94a3b8",
    fontSize: 12
  },
  summaryValue: {
    display: "block",
    marginTop: 6,
    fontSize: 24
  },
  filters: {
    display: "grid",
    gap: 12,
    alignItems: "end",
    padding: 18,
    marginBottom: 20,
    border: "1px solid #334155",
    borderRadius: 12,
    background: "#1e293b"
  },
  field: {
    display: "flex",
    flexDirection: "column",
    minWidth: 0,
    gap: 7,
    margin: 0,
    textAlign: "left"
  },
  fieldLabel: {
    color: "#94a3b8",
    fontSize: 12,
    fontWeight: 700
  },
  input: {
    boxSizing: "border-box",
    width: "100%",
    minWidth: 0,
    height: 44,
    margin: 0,
    fontFamily: "inherit",
    fontSize: 14,
    lineHeight: "20px",
    padding: "10px 12px",
    border: "1px solid #475569",
    borderRadius: 8,
    background: "#0f172a",
    color: "#f8fafc",
    outline: "none"
  },
  resetButton: {
    boxSizing: "border-box",
    height: 44,
    margin: 0,
    fontFamily: "inherit",
    fontSize: 14,
    lineHeight: "20px",
    whiteSpace: "nowrap",
    padding: "10px 14px",
    border: "1px solid #475569",
    borderRadius: 8,
    background: "#334155",
    color: "#f8fafc",
    fontWeight: 700,
    cursor: "pointer"
  },
  panel: {
    padding: 20,
    border: "1px solid #334155",
    borderRadius: 12,
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
    fontSize: 12,
    textAlign: "left",
    textTransform: "uppercase"
  },
  td: {
    padding: "13px 12px",
    borderBottom: "1px solid #334155",
    color: "#cbd5e1",
    fontSize: 13,
    verticalAlign: "top"
  },
  row: {
    cursor: "pointer",
    transition: "background .2s"
  },
  findingTitle: {
    display: "block",
    maxWidth: 330,
    color: "#f8fafc",
    marginBottom: 5
  },
  targetName: {
    display: "block",
    color: "#f8fafc",
    marginBottom: 4
  },
  meta: {
    display: "block",
    color: "#94a3b8",
    fontSize: 12
  },
  badge: {
    display: "inline-block",
    padding: "4px 9px",
    borderRadius: 999,
    fontSize: 12
  },
  toolBadge: {
    display: "inline-block",
    padding: "4px 9px",
    borderRadius: 999,
    background: "#0c4a6e",
    color: "#bae6fd",
    fontSize: 12,
    textTransform: "uppercase"
  },
  statusBadge: {
    display: "inline-block",
    padding: "4px 9px",
    borderRadius: 999,
    background: "#334155",
    color: "#cbd5e1",
    fontSize: 12,
    textTransform: "capitalize"
  },
  empty: {
    padding: 36,
    border: "1px dashed #475569",
    borderRadius: 10,
    color: "#94a3b8",
    textAlign: "center",
    background: "#0f172a"
  },
  pagination: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 16,
    paddingTop: 18
  },
  pageControls: {
    display: "flex",
    alignItems: "center",
    gap: 10
  },
  pageButton: {
    padding: "8px 12px",
    border: "1px solid #0ea5e9",
    borderRadius: 7,
    background: "#075985",
    color: "white",
    cursor: "pointer"
  },
  pageText: {
    color: "#cbd5e1",
    fontSize: 13
  }
};
