import api from "./axios";


export const getSystemHealth = () => api.get("/health");
export const getTargets = () => api.get("/targets/");
export const getScans = () => api.get("/scans/");
export const getScanDetails = (scanId) => api.get(`/scans/${scanId}`);
export const getVulnerabilities = () => api.get("/vulnerabilities/");
export const getVulnerabilityStats = () =>
  api.get("/vulnerabilities/stats");
export const addTarget = (data) => api.post("/targets/", data);
async function runScan(tool, targetId, options = {}, onProgress) {
  const queued = await api.post(`/scans/${tool}/${targetId}`, options);
  const jobId = queued.data.job_id;
  onProgress?.({ job_id: jobId, status: 'queued', stage: 'Queued', progress: 0 });
  while (true) {
    await new Promise((resolve) => window.setTimeout(resolve, 1500));
    const response = await api.get(`/scans/jobs/${jobId}`);
    onProgress?.(response.data);
    if (['completed', 'partial', 'cancelled'].includes(response.data.status)) {
      return { ...response, data: { ...response.data.result, status: response.data.status } };
    }
    if (response.data.status === "failed") {
      const error = new Error(response.data.result?.error || "The scan failed.");
      error.response = { data: response.data.result, status: response.data.response_status };
      throw error;
    }
  }
}

export const runNmapScan = (id, update) => runScan("nmap", id, {}, update);
export const runWhatwebScan = (id, update) => runScan("whatweb", id, {}, update);
export const runZapScan = (id, options, update) => runScan("zap", id, options, update);
export const runNucleiScan = (id, update) => runScan("nuclei", id, {}, update);
export const runSslyzeScan = (id, update) => runScan("sslyze", id, {}, update);
export const runFullScan = (id, options, update) => runScan("full", id, options, update);
export const cancelScan = (jobId) => api.post(`/scans/jobs/${jobId}/cancel`);
export const getScanJobs = () => api.get('/scans/jobs');

export const getReports = () => api.get("/reports/");
export const createReport = (scanId) =>
  api.post("/reports/", { scan_id: scanId });
export const deleteReport = (reportId) =>
  api.delete(`/reports/${reportId}`);
export const downloadReport = (reportId) =>
  api.get(`/reports/${reportId}/download`, { responseType: "blob" });

export const updateTarget = (id, data) => api.put(`/targets/${id}`, data);
export const deleteTarget = (id) => api.delete(`/targets/${id}`);

export const checkTargetReadiness = id => api.post(`/targets/${id}/readiness`, {}, {timeout:15000});

export const reviewFinding = (id,data) => api.put(`/vulnerabilities/${id}/review`,data);
export const getFindingReviews = id => api.get(`/vulnerabilities/${id}/reviews`);
export const compareScans = (baseline,current,includeInformation=false) => api.get('/scans/compare',{params:{baseline,current,include_information:includeInformation}});

export const getRemediation = () => api.get('/remediation/');
export const createRemediation = data => api.post('/remediation/',data);
export const updateRemediation = (id,data) => api.put(`/remediation/${id}`,data);
export const getRemediationHistory = id => api.get(`/remediation/${id}/history`);
export const retestRemediation = (id,options={}) => api.post(`/remediation/${id}/retest`,options);
