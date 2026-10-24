import { t, useLocale } from "../i18n/language";
function displayValue(value) {
  if (value === null || value === undefined || value === "") {
    return "Not available";
  }
  return value;
}
export default function FindingLocation({
  finding
}) {
  useLocale();
  const locationFields = [{
    label: "Affected URL",
    value: finding.affected_url,
    fullWidth: true
  }, {
    label: "Path",
    value: finding.affected_path
  }, {
    label: "Port",
    value: finding.affected_port
  }, {
    label: "HTTP Method",
    value: finding.http_method
  }, {
    label: "Parameter",
    value: finding.parameter_name
  }, {
    label: "Evidence",
    value: finding.evidence,
    fullWidth: true
  }, {
    label: "Source Tool",
    value: finding.source_tool ? finding.source_tool.toUpperCase() : null
  }];
  const hasLocationData = locationFields.some(field => field.value !== null && field.value !== undefined && field.value !== "");
  if (!hasLocationData) {
    return null;
  }
  return <section style={styles.container}>
      <div style={styles.header}>
        <div style={styles.icon}>⌖</div>

        <div>
          <h4 style={styles.title}>{t("Affected Location")}</h4>

          <p style={styles.subtitle}>{t("Exact location information reported by the scanner.")}</p>
        </div>
      </div>

      <div style={styles.grid}>
        {locationFields.map(field => <div key={field.label} style={{
        ...styles.field,
        ...(field.fullWidth ? styles.fullWidth : {})
      }}>
            <span style={styles.label}>
              {t(field.label)}
            </span>

            <span style={styles.value}>
              {displayValue(field.value)}
            </span>
          </div>)}
      </div>
    </section>;
}
const styles = {
  container: {
    marginTop: "16px",
    marginBottom: "16px",
    padding: "16px",
    border: "1px solid rgba(56, 189, 248, 0.38)",
    borderLeft: "4px solid #38bdf8",
    borderRadius: "10px",
    background: "linear-gradient(135deg, rgba(14, 116, 144, 0.14), rgba(30, 58, 138, 0.12))"
  },
  header: {
    display: "flex",
    alignItems: "center",
    gap: "11px",
    marginBottom: "15px"
  },
  icon: {
    width: "34px",
    height: "34px",
    display: "grid",
    placeItems: "center",
    flexShrink: 0,
    borderRadius: "9px",
    color: "#e0f2fe",
    background: "#0369a1",
    fontSize: "20px",
    fontWeight: 800
  },
  title: {
    margin: 0,
    color: "#7dd3fc",
    fontSize: "14px",
    textTransform: "uppercase",
    letterSpacing: "0.06em"
  },
  subtitle: {
    margin: "4px 0 0",
    color: "#94a3b8",
    fontSize: "12px"
  },
  grid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
    gap: "11px"
  },
  field: {
    minWidth: 0,
    display: "flex",
    flexDirection: "column",
    gap: "5px",
    padding: "11px",
    border: "1px solid rgba(71, 85, 105, 0.55)",
    borderRadius: "8px",
    background: "rgba(15, 23, 42, 0.55)"
  },
  fullWidth: {
    gridColumn: "1 / -1"
  },
  label: {
    color: "#94a3b8",
    fontSize: "10px",
    fontWeight: 700,
    textTransform: "uppercase",
    letterSpacing: "0.06em"
  },
  value: {
    color: "#e2e8f0",
    fontSize: "13px",
    lineHeight: 1.55,
    overflowWrap: "anywhere",
    whiteSpace: "pre-wrap"
  }
};
