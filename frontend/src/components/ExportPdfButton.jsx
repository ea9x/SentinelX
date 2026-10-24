import { t, useLocale } from "../i18n/language";
import { useState } from "react";
import { FaFilePdf } from "react-icons/fa";
import { createReport, downloadReport } from "../api/dashboard";
function saveBlob(response, fallbackName) {
  const disposition = response.headers["content-disposition"] || "";
  const filenameMatch = disposition.match(/filename\*?=(?:UTF-8''|")?([^";]+)/i);
  const filename = filenameMatch ? decodeURIComponent(filenameMatch[1].replace(/"/g, "")) : fallbackName;
  const url = window.URL.createObjectURL(response.data);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}
export default function ExportPdfButton({
  scanId
}) {
  useLocale();
  const [exporting, setExporting] = useState(false);
  async function exportPdf() {
    setExporting(true);
    try {
      const createResponse = await createReport(scanId);
      const reportId = createResponse.data.report.id;
      const downloadResponse = await downloadReport(reportId);
      saveBlob(downloadResponse, `sentinelx-report-${reportId}-scan-${scanId}.pdf`);
    } catch (error) {
      console.error("Failed to export PDF report:", error);
      window.alert(error.response?.data?.error || "The PDF report could not be generated.");
    } finally {
      setExporting(false);
    }
  }
  return <button type="button" onClick={exportPdf} style={{
    ...styles.button,
    ...(exporting ? styles.disabledButton : {})
  }} disabled={exporting}>
      <FaFilePdf />
      <span>{exporting ? t("Generating...") : t("Export PDF")}</span>
    </button>;
}
const styles = {
  button: {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    gap: "8px",
    padding: "10px 14px",
    border: "1px solid #0ea5e9",
    borderRadius: "8px",
    background: "#075985",
    color: "#ffffff",
    fontSize: "13px",
    fontWeight: 700,
    cursor: "pointer"
  },
  disabledButton: {
    cursor: "wait",
    opacity: 0.7
  }
};
