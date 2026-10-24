import { t, useLocale, getLocale } from "../i18n/language";
import { useState, useEffect } from 'react';
import { useAuth } from '../context/auth-context';
import { getTargets, checkTargetReadiness, addTarget, updateTarget, deleteTarget, runNmapScan, runWhatwebScan, runZapScan, runNucleiScan, runSslyzeScan, runFullScan } from '../api/dashboard';
import { Link } from 'react-router-dom';
import WebScanSettings from '../components/WebScanSettings';
import ScanJobs from '../components/ScanJobs';
import { cancelScan } from '../api/dashboard';
export default function Targets() {
  useLocale();
  const {
    logout
  } = useAuth();
  const [targets, setTargets] = useState([]);
  const [checkingId,setCheckingId]=useState(null);
  const [readiness,setReadiness]=useState(null);
  const [editingId, setEditingId] = useState(null);
  const [saving, setSaving] = useState(false);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [deleting, setDeleting] = useState(null);
  const visibleTargets = targets.filter(target => (!search.trim() || [target.name,target.ip_address,target.hostname,String(target.port)].some(value => (value || '').toLowerCase().includes(search.trim().toLowerCase()))) && (statusFilter === 'all' || (target.last_activity?.status || target.last_scan?.status || 'never') === statusFilter));
  const resetForm = () => { setEditingId(null); setName(''); setIp(''); setHostname(''); setPort('80'); };
  const editTarget = target => { setEditingId(target.id); setName(target.name); setIp(target.ip_address || ''); setHostname(target.hostname || ''); setPort(String(target.port)); document.getElementById('target-editor')?.scrollIntoView({behavior:'smooth'}); };


  const [name, setName] = useState('');
  const [ip, setIp] = useState('');
  const [hostname, setHostname] = useState('');
  const [port, setPort] = useState('80');
  const [loading, setLoading] = useState(true);
  const [scanningId, setScanningId] = useState(null);
  const [scanningTool, setScanningTool] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [resultKey, setResultKey] = useState(0);
  const [error, setError] = useState('');
  const [webOptions, setWebOptions] = useState('{}');
  const [optionsError, setOptionsError] = useState('');
  const [scanProgress, setScanProgress] = useState(null);
  const [cancelPending, setCancelPending] = useState(false);
  const [mounted, setMounted] = useState(false);
  const [toasts, setToasts] = useState([]);
  const [browserNotificationsEnabled, setBrowserNotificationsEnabled] = useState(typeof Notification !== 'undefined' && Notification.permission === 'granted');
  useEffect(() => {
    loadTargets();
    // Animate the page after the initial render.
    const t = setTimeout(() => setMounted(true), 10);
    return () => clearTimeout(t);
  }, []);
  async function loadTargets() {
    try {
      const res = await getTargets();
      setTargets(res.data);
      window.dispatchEvent(new Event("sentinelx:data-updated"));
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.error || "Unable to load targets.");
    } finally {
      setLoading(false);
    }
  }
  ;
  const removeTarget = async () => { try { setSaving(true); await deleteTarget(deleting.id); setDeleting(null); if (editingId === deleting.id) resetForm(); await loadTargets(); } catch(err) { setError(err.response?.data?.error || 'Unable to delete target.'); } finally { setSaving(false); } };
  const handleAddTarget = async e => {
    e.preventDefault();
    setError('');
    setSaving(true);
    try {
      const saveTarget = editingId ? data => updateTarget(editingId, data) : addTarget;
      await saveTarget({
        name,
        ip_address: ip,
        hostname,
        port: Number(port)
      });
      resetForm();
      await loadTargets();
    } catch (err) {
      setError(err.response?.data?.error || 'Unable to add the target.');
    } finally { setSaving(false); }
  };
  const removeToast = toastId => {
    setToasts(current => current.filter(toast => toast.id !== toastId));
  };
  const showNotification = (type, title, message) => {
    const toastId = window.crypto.randomUUID();
    setToasts(current => [...current.slice(-2), {
      id: toastId,
      type,
      title,
      message
    }]);
    window.setTimeout(() => removeToast(toastId), 5500);
    if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
      const notification = new Notification(t(title), {
        body: t(message),
        icon: '/icons.svg',
        tag: 'sentinelx-scan-result'
      });
      window.setTimeout(() => notification.close(), 7000);
    }
  };
  const enableBrowserNotifications = async () => {
    if (typeof Notification === 'undefined') {
      showNotification('error', 'Notifications unavailable', 'This browser does not support desktop notifications.');
      return;
    }
    const permission = await Notification.requestPermission();
    const enabled = permission === 'granted';
    setBrowserNotificationsEnabled(enabled);
    showNotification(enabled ? 'success' : 'error', enabled ? 'Notifications enabled' : 'Notifications blocked', enabled ? 'SentinelX will notify you when a scan finishes.' : 'Allow notifications from the browser settings to enable them.');
  };
  const handleScan = async (targetId, tool, override=false) => {
    if (!override) {
      setCheckingId(targetId);setReadiness(null);
      try {
        const {data}=await checkTargetReadiness(targetId);
        const unsuitable=!data.tcp_open || (tool==='sslyze' ? !data.tls : tool==='full' ? false : ['zap','whatweb','nuclei'].includes(tool) && !data.http);
        setReadiness({...data,targetId,tool,needsConfirmation:unsuitable,message:data.tcp_open && tool==='sslyze' && !data.tls ? 'TLS was not confirmed on this port. SSLyze requires a TLS-enabled service.' : data.tcp_open && tool==='full' && (!data.http || !data.tls) ? 'Full scan checks available protocols and lists skipped tools as incomplete coverage.' : data.message});
        if(unsuitable)return;
      } catch {setReadiness({targetId,tool,needsConfirmation:true,message:'Unable to check target readiness. Verify the service before continuing.'});return;}
      finally {setCheckingId(null);}
    } else { setReadiness(current=>({...current,needsConfirmation:false})); }

    let options = {};
    if (tool === 'zap' || tool === 'full') {
      try {
        options = JSON.parse(webOptions);
        if (!options || typeof options !== 'object' || Array.isArray(options)) throw new Error();
        setOptionsError('');
      } catch {
        setOptionsError('Enter a valid JSON object for web scan settings.');
        return;
      }
      setWebOptions('{}');
    }
    const selectedTarget = targets.find(target => target.id === targetId);
    const targetName = selectedTarget?.name || `Target #${targetId}`;
    setScanningId(targetId);
    setScanningTool(tool);
    setScanResult(null);
    setScanProgress(null);
    setCancelPending(false);
    try {
      let res;
      if (tool === 'nmap') res = await runNmapScan(targetId, setScanProgress);else if (tool === 'whatweb') res = await runWhatwebScan(targetId, setScanProgress);else if (tool === 'zap') res = await runZapScan(targetId, options, setScanProgress);else if (tool === 'nuclei') res = await runNucleiScan(targetId, setScanProgress);else if (tool === 'sslyze') res = await runSslyzeScan(targetId, setScanProgress);else if (tool === 'full') res = await runFullScan(targetId, options, setScanProgress);
      setScanResult({
        ...res.data,
        tool
      });
      setResultKey(k => k + 1); // Replay the transition for each new result.
      const findings = tool === 'whatweb' ? res.data.technologies_found : tool === 'full' ? res.data.total_vulnerabilities_found : res.data.vulnerabilities_found;
      const incomplete = ['partial', 'failed', 'cancelled'].includes(res.data.status);
      showNotification(incomplete ? 'error' : 'success', `${toolLabel(tool)} scan ${res.data.status === 'cancelled' ? 'cancelled' : incomplete ? 'incomplete' : 'completed'}`, incomplete ? `${targetName}: ${res.data.message || 'Review the partial results in scan history.'}` : `${targetName}: ${findings ?? 0} result${findings === 1 ? '' : 's'} found.`);
    } catch (err) {
      const errorMessage = err.response?.data?.error || 'The scan failed.';
      setScanResult({
        ...err.response?.data,
        error: errorMessage,
        tool
      });
      setResultKey(k => k + 1);
      showNotification('error', `${toolLabel(tool)} scan failed`, `${targetName}: ${errorMessage}`);
    } finally {
      loadTargets();
      setScanningId(null);
      setScanningTool(null);
    }
  };
  return <div style={{
    ...styles.page,
    ...(mounted ? styles.pageVisible : styles.pageHidden)
  }}>
            <style>{animationStyles}</style>

            <div className="scan-toast-viewport" aria-live="polite">
                {toasts.map(toast => <article key={toast.id} className={`scan-toast scan-toast--${toast.type}`}>
                        <span className="scan-toast-icon">{toast.type === 'success' ? '✓' : '!'}</span>
                        <div>
                            <strong>{t(toast.title)}</strong>
                            <p>{t(toast.message)}</p>
                        </div>
                        <button type="button" onClick={() => removeToast(toast.id)} aria-label={t("Dismiss notification")}>×</button>
                    </article>)}
            </div>

            <div style={styles.header}>
                <h1 style={styles.headerTitle}>{t("\uD83C\uDFAF Target Management")}</h1>
                <div style={styles.headerRight}>
                    <button type="button" onClick={enableBrowserNotifications} style={styles.notificationBtn} disabled={browserNotificationsEnabled}>
                        {browserNotificationsEnabled ? t("Notifications Enabled") : t("Enable Notifications")}
                    </button>
                    <Link to="/dashboard" style={styles.navLink}>{t("Dashboard")}</Link>
                    <button onClick={logout} style={styles.logoutBtn}>{t("Log Out")}</button>
                </div>
            </div>

            <details style={styles.formBox}>
                <summary style={{
        cursor: 'pointer',
        fontWeight: 600
      }}>{t("Web scan settings \u2014 next ZAP or Full scan")}</summary>
                <WebScanSettings value={webOptions} onChange={setWebOptions} />
                {optionsError && <p role="alert" style={styles.error}>{t(optionsError)}</p>}
            </details>
            {scanProgress && <section aria-live="polite" style={styles.formBox}>
                <h3>{t("Scan progress")}</h3>
                <p>{t(scanProgress.stage) || t(scanProgress.status)} — {scanProgress.progress || 0}%</p>
                <progress aria-label={t("Scan completion")} max="100" value={scanProgress.progress || 0} style={{
        width: '100%'
      }} />
                <p>{t("The percentage describes progress through the scan steps, not a guarantee of complete vulnerability coverage.")}</p>
                {["queued", "running"].includes(scanProgress.status) && <button type="button" disabled={cancelPending || scanProgress.cancel_requested} onClick={async () => {
        setCancelPending(true);
        try {
          await cancelScan(scanProgress.job_id);
        } catch {
          setCancelPending(false);
          showNotification('error', 'Unable to cancel', 'Try again. The scan may have already finished.');
        }
      }}>{cancelPending || scanProgress.cancel_requested ? t("Cancellation requested") : t("Cancel scan")}</button>}
                {(cancelPending || scanProgress.cancel_requested) && <p>{t("ZAP stops at its next check. Other tools finish their current step before stopping.")}</p>}
            </section>}
            {checkingId !== null && <p role="status">{t("Checking target readiness...")}</p>}
            {readiness && <section style={styles.formBox} role="status">
              <h3>{t("Target readiness")}</h3><p>{t(readiness.message)}</p>
              {readiness.service && <p>{t("Detected service")}: {readiness.service.toUpperCase()} · {readiness.host}:{readiness.port}</p>}
              <p>{t("Protocol detection does not validate certificates or establish target security. TLS tools require a TLS service; web tools require HTTP or HTTPS.")}</p>
              {readiness.needsConfirmation && <><button type="button" disabled={scanningId !== null} onClick={()=>handleScan(readiness.targetId,readiness.tool,true)}>{t("Continue scan anyway")}</button> <button type="button" onClick={()=>setReadiness(null)}>{t("Cancel")}</button></>}
            </section>}
            <ScanJobs />
            {/* Add Target Form */}
            <form id="target-editor" onSubmit={handleAddTarget} style={styles.formBox}>
                <h3 style={styles.boxTitle}>{editingId ? t("Edit target") : t("Add a New Target")}</h3>
                {t(error) && <div style={styles.error}>{t(error)}</div>}
                <div style={styles.formRow}>
                    <input placeholder={t("Target name")} value={name} onChange={e => setName(e.target.value)} required style={styles.input} />
                    <input dir="ltr" placeholder={t("IP address")} value={ip} onChange={e => setIp(e.target.value)} style={styles.input} />
                    <input dir="ltr" placeholder={t("Hostname (optional)")} value={hostname} onChange={e => setHostname(e.target.value)} style={styles.input} />
                    <input type="number" min="1" max="65535" placeholder={t("Port")} value={port} onChange={e => setPort(e.target.value)} required style={{
          ...styles.input,
          maxWidth: '130px'
        }} title={t("Use port 443 for HTTPS and SSLyze scans")} />
                    <button type="submit" disabled={saving} style={styles.addBtn}>{editingId ? t("Save changes") : t("+ Add")}</button>
                </div>
                {editingId && <button type="button" onClick={resetForm}>{t("Cancel edit")}</button>}
                <p>{t("Enter an IP address or hostname. Targets with scan history can be renamed only.")}</p>
            </form>

            {/* Scan Result */}
            {scanResult && <div key={resultKey} style={styles.resultBox} className="result-fade-in">
                    <h3 style={styles.boxTitle}>
                        {scanResult.error || ["partial", "failed"].includes(scanResult.status) ? t("\u26A0 Scan result: {0}", [toolLabel(scanResult.tool)]) : t("\u2705 Scan result: {0}", [toolLabel(scanResult.tool)])}
                    </h3>

                    {scanResult.error ? <p style={{
        color: '#fecaca'
      }}>{t(scanResult.error)}</p> : scanResult.tool === 'nmap' ? <>
                            <p>{t("Detected ")}<strong>{scanResult.vulnerabilities_found}</strong>{t(" potential findings on target ")}<strong>{scanResult.target}</strong></p>
                            <div style={styles.vulnList}>
                                {scanResult.vulnerabilities?.map(v => <div key={v.id} style={styles.vulnItem} className="vuln-item-in">
                                        <span style={{
              ...styles.severityBadge,
              backgroundColor: severityColors[v.severity] || '#64748b'
            }}>
                                            {t(v.severity)}
                                        </span>
                                        <div>
                                            <strong>{v.title}</strong>
                                            <p style={{
                margin: '4px 0 0',
                fontSize: '13px',
                color: '#94a3b8'
              }}>{v.recommendation}</p>
                                        </div>
                                    </div>)}
                            </div>
                        </> : scanResult.tool === 'whatweb' ? <>
                            <p>{t("Detected ")}<strong>{scanResult.technologies_found}</strong>{t(" technologies on target ")}<strong>{scanResult.target}</strong></p>
                            <div style={styles.vulnList}>
                                {scanResult.technologies?.map((t, i) => <div key={i} style={styles.vulnItem} className="vuln-item-in">
                                        <span style={{
              ...styles.severityBadge,
              backgroundColor: '#3b82f6'
            }}>
                                            {t.technology}
                                        </span>
                                        <div>
                                            <strong>{t.details}</strong>
                                        </div>
                                    </div>)}
                            </div>
                        </> : scanResult.tool === 'zap' || scanResult.tool === 'nuclei' || scanResult.tool === 'sslyze' ? <>
                            <p>{t("Detected ")}<strong>{scanResult.vulnerabilities_found}</strong>{t(" findings on target ")}<strong>{scanResult.target}</strong></p>
                            <div style={styles.vulnList}>
                                {scanResult.vulnerabilities?.map(v => <div key={v.id} style={styles.vulnItem} className="vuln-item-in">
                                        <span style={{
              ...styles.severityBadge,
              backgroundColor: severityColors[v.severity] || '#64748b'
            }}>
                                            {t(v.severity)}
                                        </span>
                                        <div>
                                            <strong>{v.title}</strong>
                                            <p style={{
                margin: '4px 0 0',
                fontSize: '13px',
                color: '#94a3b8'
              }}>{v.recommendation}</p>
                                        </div>
                                    </div>)}
                            </div>
                        </> : scanResult.tool === 'full' ? <>
                            {scanResult.status !== "completed" && <p role="alert" style={{
          color: '#fca5a5'
        }}>{t("Incomplete coverage. Review failed and skipped tools below.")}</p>}
                            <p role="note">{t("Zero findings do not establish that the target is secure. Check failed tools and verify the target service and port before rescanning.")}</p>
                            <p>{t("Total findings across all tools:")}<strong> {scanResult.total_vulnerabilities_found}</strong>{t(" on target ")}<strong>{scanResult.target}</strong>
                            </p>
                            <div style={styles.vulnList}>
                                {Object.entries(scanResult.tools || {}).map(([toolName, info]) => <div key={toolName} style={styles.vulnItem} className="vuln-item-in">
                                        <span style={{
              ...styles.severityBadge,
              backgroundColor: info.status === 'completed' ? '#22c55e' : info.status === 'failed' ? '#dc2626' : '#64748b'
            }}>
                                            {toolLabel(toolName)}
                                        </span>
                                        <div>
                                            {info.status === "completed" && <strong>{t("Detected ")}{info.found}{t(" findings")}</strong>}
                                            {info.scan_id && <Link to={`/scans/${info.scan_id}`} style={styles.navLink}>{t("View scan details")}</Link>}
                                            {info.status === "failed" && <p style={{
                margin: 0,
                color: '#fecaca',
                fontSize: '13px'
              }}>{t("Failed: ")}{t(publicScanError(info.error))}</p>}
                                            {info.status === 'skipped' && <p style={{
                margin: 0,
                color: '#94a3b8',
                fontSize: '13px'
              }}>{t("Skipped: ")}{t(info.reason)}</p>}
                                        </div>
                                    </div>)}
                            </div>
                        </> : null}
                </div>}

            {/* Targets List */}
            <div style={styles.listBox}>
                <h3 style={styles.boxTitle}>{t("Current Targets")}</h3>
                <div style={styles.formRow}>
                  <input aria-label={t("Search targets")} placeholder={t("Search targets")} value={search} onChange={e=>setSearch(e.target.value)} style={styles.input}/>
                  <select aria-label={t("Scan status")} value={statusFilter} onChange={e=>setStatusFilter(e.target.value)} style={styles.input}>
                    {['all','never','queued','running','completed','partial','failed','cancelled'].map(status=><option key={status} value={status}>{t(status === 'all' ? 'All statuses' : status === 'never' ? 'Never scanned' : status)}</option>)}
                  </select>
                </div>
                {!loading && targets.length > 0 && visibleTargets.length === 0 && <p>{t("No matching targets.")}</p>}
                {deleting && <section tabIndex="-1" ref={node=>node?.focus()} role="alertdialog" aria-label={t("Delete target")} style={styles.error}>
                  <p>{t("Delete target")}: {deleting.name}?</p>{error && <p role="alert">{t(error)}</p>}<p>{t("The target will be removed from this list. Scan history and reports will be preserved.")}</p>
                  <button type="button" disabled={saving} onClick={removeTarget}>{t("Confirm deletion")}</button>
                  <button type="button" disabled={saving} onClick={()=>setDeleting(null)}>{t("Cancel")}</button>
                </section>}
                {loading ? <p style={styles.emptyText}>{t("Loading...")}</p> : targets.length === 0 ? <p style={styles.emptyText}>{t("No targets yet. Add one above.")}</p> : <div style={styles.targetsGrid}>
                        {visibleTargets.map((target, idx) => <div key={target.id} style={{
          ...styles.targetCard,
          animationDelay: `${idx * 60}ms`
        }} className="card-fade-in">
                                <div>
                                    <strong style={{
              color: '#38bdf8'
            }}>{target.name}</strong>
                                    <p style={{
              margin: '5px 0 0',
              fontSize: '13px',
              color: '#94a3b8'
            }}>
                                        {target.ip_address} {target.hostname && `(${target.hostname})`} :{target.port}
                                    </p>
                                </div>
                                <div>
                                  <button type="button" disabled={scanningId !== null || checkingId !== null} onClick={()=>editTarget(target)}>{t("Edit target")}</button>
                                  <button type="button" disabled={scanningId !== null || checkingId !== null} title={t("The target will be removed from this list. Scan history and reports will be preserved.")} onClick={()=>{setError('');setDeleting(target);}}>{t("Delete target")}</button>
                                  <p>{t("Last scan")}: {(target.last_activity || target.last_scan) ? <>{t((target.last_activity || target.last_scan).status)} · {(target.last_activity || target.last_scan).tool} · {new Date((target.last_activity || target.last_scan).date).toLocaleString(getLocale())}</> : t("Never scanned")}</p>
                                  {target.last_scan && <><p>{t("Findings from the latest tool scan")}</p><div style={{display:'flex',flexWrap:'wrap',gap:8}}>{Object.entries(target.last_scan.findings).map(([severity,count])=><span key={severity} style={{color:severityColors[severity]}}>{t(severity)}: {count}</span>)}</div></>}
                                </div>
                                <div style={styles.scanBtnRow}>
                                    <button onClick={() => handleScan(target.id, 'nmap')} disabled={scanningId !== null || checkingId !== null} style={styles.scanBtn}>
                                        {scanningId === target.id && scanningTool === 'nmap' ? <Spinner /> : t("\uD83D\uDD0D Nmap")}
                                    </button>
                                    <button onClick={() => handleScan(target.id, 'whatweb')} disabled={scanningId !== null || checkingId !== null} style={{
              ...styles.scanBtn,
              backgroundColor: '#3b82f6'
            }}>
                                        {scanningId === target.id && scanningTool === 'whatweb' ? <Spinner /> : t("\uD83C\uDF10 WhatWeb")}
                                    </button>
                                    <button onClick={() => handleScan(target.id, 'zap')} disabled={scanningId !== null || checkingId !== null} style={{
              ...styles.scanBtn,
              backgroundColor: '#f97316'
            }}>
                                        {scanningId === target.id && scanningTool === 'zap' ? <Spinner /> : t("\uD83D\uDEE1\uFE0F ZAP")}
                                    </button>
                                    <button onClick={() => handleScan(target.id, 'nuclei')} disabled={scanningId !== null || checkingId !== null} style={{
              ...styles.scanBtn,
              backgroundColor: '#0f766e'
            }}>
                                        {scanningId === target.id && scanningTool === 'nuclei' ? <Spinner /> : t("\u269B Nuclei")}
                                    </button>
                                    <button onClick={() => handleScan(target.id, 'sslyze')} disabled={scanningId !== null || checkingId !== null} style={{
              ...styles.scanBtn,
              backgroundColor: '#0891b2'
            }} title={t("Analyze TLS certificates and HTTPS configuration")}>
                                        {scanningId === target.id && scanningTool === 'sslyze' ? <Spinner /> : t("\uD83D\uDD10 SSLyze")}
                                    </button>
                                </div>
                                <button onClick={() => handleScan(target.id, 'full')} disabled={scanningId !== null || checkingId !== null} style={styles.fullScanBtn}>
                                    {scanningId === target.id && scanningTool === 'full' ? <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px'
            }}>
                                            <Spinner />{t(" Running full scan... This may take several minutes.")}</span> : t("\u26A1 Full Scan (Available Protocols)")}
                                </button>
                            </div>)}
                    </div>}
            </div>
        </div>;
}
function Spinner() {
  useLocale();
  return <span className="spinner" aria-label={t("Loading")} />;
}
function publicScanError(error) {
  const text = String(error || 'The scanner failed.');
  if (/actively refused|connection refused|serverrejectedconnection|server rejected the connection/i.test(text)) return 'The target refused the connection. Check that the service is running on the configured port. TLS scans require a TLS-enabled port, usually 443.';
  if (/traceback|connectivity_error_trace|file "/i.test(text)) return 'The TLS scan could not complete. Verify that this port supports TLS; HTTPS usually uses port 443.';
  return text;
}
function toolLabel(tool) {
  const labels = {
    nmap: 'Nmap',
    whatweb: 'WhatWeb',
    zap: 'ZAP',
    nuclei: 'Nuclei',
    sslyze: 'SSLyze',
    full: 'Full Scan'
  };
  return labels[tool] || tool;
}
const severityColors = {
  Critical: '#dc2626',
  High: '#ea580c',
  Medium: '#eab308',
  Low: '#22c55e',
  Info: '#3b82f6'
};

// Shared animation keyframes and transitions.
const animationStyles = `
@keyframes fadeSlideUp {
    from { opacity: 0; transform: translateY(14px); }
    to   { opacity: 1; transform: translateY(0); }
}
@keyframes spin {
    from { transform: rotate(0deg); }
    to   { transform: rotate(360deg); }
}
.result-fade-in {
    animation: fadeSlideUp 0.35s ease-out;
}
.card-fade-in {
    animation: fadeSlideUp 0.4s ease-out both;
}
.vuln-item-in {
    animation: fadeSlideUp 0.3s ease-out both;
}
.spinner {
    display: inline-block;
    width: 14px;
    height: 14px;
    border: 2px solid rgba(255,255,255,0.35);
    border-top-color: #ffffff;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    vertical-align: middle;
}
.scan-toast-viewport {
    position: fixed;
    z-index: 12000;
    top: 22px;
    left: 22px;
    display: grid;
    width: min(390px, calc(100vw - 44px));
    gap: 11px;
    direction: ltr;
}
.scan-toast {
    display: grid;
    grid-template-columns: 38px minmax(0, 1fr) 30px;
    align-items: center;
    gap: 11px;
    padding: 14px;
    border: 1px solid #334155;
    border-left: 4px solid #38bdf8;
    border-radius: 12px;
    background: rgba(15, 23, 42, 0.97);
    color: #f8fafc;
    box-shadow: 0 20px 55px rgba(0, 0, 0, 0.42);
    backdrop-filter: blur(14px);
    animation: scanToastEnter 0.3s ease-out both;
}
.scan-toast--success { border-left-color: #22c55e; }
.scan-toast--error { border-left-color: #ef4444; }
.scan-toast-icon {
    display: grid;
    width: 36px;
    height: 36px;
    place-items: center;
    border-radius: 50%;
    background: #14532d;
    color: #bbf7d0;
    font-weight: 900;
}
.scan-toast--error .scan-toast-icon { background: #7f1d1d; color: #fecaca; }
.scan-toast strong { display: block; font-size: 14px; }
.scan-toast p { margin: 4px 0 0; color: #94a3b8; font-size: 12px; line-height: 1.45; }
.scan-toast button { border: 0; background: transparent; color: #94a3b8; font-size: 22px; cursor: pointer; }
@keyframes scanToastEnter {
    from { opacity: 0; transform: translateX(-18px) scale(0.97); }
    to { opacity: 1; transform: translateX(0) scale(1); }
}
`;
const styles = {
  page: {
    backgroundColor: '#0f172a',
    minHeight: '100vh',
    color: 'white',
    direction: 'inherit',
    padding: 'clamp(12px, 3vw, 30px)',
    minWidth: 0,
    fontFamily: 'sans-serif',
    transition: 'opacity 0.4s ease, transform 0.4s ease'
  },
  pageHidden: {
    opacity: 0,
    transform: 'translateY(10px)'
  },
  pageVisible: {
    opacity: 1,
    transform: 'translateY(0)'
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: '16px',
    marginBottom: '30px',
    paddingBottom: '20px',
    borderBottom: '1px solid #334155'
  },
  headerTitle: {
    margin: 0,
    fontSize: '24px'
  },
  headerRight: {
    display: 'flex',
    alignItems: 'center',
    gap: '15px',
    flexWrap: 'wrap'
  },
  navLink: {
    color: '#38bdf8',
    textDecoration: 'none'
  },
  notificationBtn: {
    padding: '8px 12px',
    border: '1px solid #0284c7',
    borderRadius: '7px',
    backgroundColor: '#0c4a6e',
    color: '#bae6fd',
    cursor: 'pointer',
    fontSize: '12px',
    fontWeight: 'bold'
  },
  logoutBtn: {
    padding: '8px 16px',
    backgroundColor: '#334155',
    color: 'white',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer'
  },
  formBox: {
    backgroundColor: '#1e293b',
    padding: '20px',
    borderRadius: '10px',
    marginBottom: '20px'
  },
  formRow: {
    display: 'flex',
    gap: '10px',
    flexWrap: 'wrap'
  },
  input: {
    flex: '1',
    minWidth: '150px',
    padding: '10px',
    borderRadius: '6px',
    border: '1px solid #334155',
    backgroundColor: '#0f172a',
    color: 'white'
  },
  addBtn: {
    padding: '10px 20px',
    backgroundColor: '#38bdf8',
    color: '#0f172a',
    border: 'none',
    borderRadius: '6px',
    fontWeight: 'bold',
    cursor: 'pointer'
  },
  boxTitle: {
    marginTop: 0,
    marginBottom: '15px',
    fontSize: '16px'
  },
  error: {
    backgroundColor: '#7f1d1d',
    color: '#fecaca',
    padding: '10px',
    borderRadius: '8px',
    marginBottom: '15px',
    fontSize: '13px'
  },
  resultBox: {
    backgroundColor: '#1e293b',
    padding: '20px',
    borderRadius: '10px',
    marginBottom: '20px'
  },
  vulnList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
    marginTop: '15px'
  },
  vulnItem: {
    display: 'flex',
    gap: '12px',
    alignItems: 'flex-start',
    backgroundColor: '#0f172a',
    padding: '12px',
    borderRadius: '8px'
  },
  severityBadge: {
    padding: '4px 10px',
    borderRadius: '20px',
    fontSize: '12px',
    whiteSpace: 'nowrap'
  },
  listBox: {
    backgroundColor: '#1e293b',
    padding: '20px',
    borderRadius: '10px'
  },
  targetsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(min(250px, 100%), 1fr))',
    gap: '15px',
    flexWrap: 'wrap'
  },
  targetCard: {
    backgroundColor: '#0f172a',
    padding: '15px',
    borderRadius: '8px',
    border: '1px solid #334155',
    display: 'flex',
    flexDirection: 'column',
    gap: '10px'
  },
  scanBtnRow: {
    display: 'grid',
    gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
    gap: '8px',
    width: '100%'
  },
  scanBtn: {
    width: '100%',
    minWidth: 0,
    padding: '8px',
    backgroundColor: '#a855f7',
    color: 'white',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '12px',
    whiteSpace: 'nowrap',
    overflow: 'hidden'
  },
  fullScanBtn: {
    padding: '10px',
    backgroundColor: '#059669',
    color: 'white',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '13px',
    fontWeight: 'bold'
  },
  emptyText: {
    color: '#64748b',
    fontSize: '14px'
  }
};
