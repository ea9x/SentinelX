import { t, useLocale } from "../i18n/language";
import { useEffect, useState } from 'react';
import { getScanJobs, cancelScan } from '../api/dashboard';
import { Link } from 'react-router-dom';
export default function ScanJobs() {
  useLocale();
  const [jobs, setJobs] = useState([]);
  const [error, setError] = useState('');
  const [pending, setPending] = useState(null);
  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const response = await getScanJobs();
        if (active) {
          setJobs(response.data);
          setError('');
        }
      } catch {
        if (active) setError('Unable to load scan jobs. Retrying...');
      }
    }
    load();
    const timer = window.setInterval(load, 3000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);
  return <section style={{
    padding: 18,
    margin: '18px 0',
    border: '1px solid #475569',
    borderRadius: 10,
    color: '#e2e8f0',
    background: '#1e293b'
  }} aria-label={t("Recent scan jobs")}>
        <h3>{t("Recent scan jobs")}</h3><p>{t("Latest 20 jobs. Progress and cancellation remain available after a page reload. ")}<Link to="/scans" style={{
        color: '#7dd3fc'
      }}>{t("View saved results")}</Link></p>
        {t(error) && <p role="status">{t(error)}</p>}
        {!jobs.length ? <p>{t("No scan jobs yet.")}</p> : <div style={{
      overflowX: 'auto'
    }}><table style={{
        width: '100%',
        textAlign: 'left',
        borderCollapse: 'collapse'
      }}>
            <thead><tr>{[t("Target"), t("Tool"), t("Stage"), t("Progress"), t("Status"), t("Action")].map(label => <th key={label} style={{
              padding: 8
            }}>{t(label)}</th>)}</tr></thead>
            <tbody>{jobs.map(job => <tr key={job.job_id}>
                <td style={{
              padding: 8
            }}>{job.target_name}</td><td style={{
              padding: 8
            }}>{job.tool.toUpperCase()}</td><td style={{
              padding: 8
            }}>{t(job.stage)}</td>
                <td style={{
              padding: 8
            }}><progress aria-label={t("{0} progress", [job.target_name])} max="100" value={job.progress} /> {job.progress}%</td><td style={{
              padding: 8
            }}>{t(job.status)}</td>
                <td style={{
              padding: 8
            }}>{["queued", "running"].includes(job.status) && <button type="button" style={{
                padding: '7px 12px',
                border: '1px solid #0ea5e9',
                borderRadius: 7,
                background: '#075985',
                color: '#e0f2fe'
              }} disabled={job.cancel_requested || pending === job.job_id} onClick={async () => {
                setPending(job.job_id);
                try {
                  await cancelScan(job.job_id);
                  setJobs(rows => rows.map(row => row.job_id === job.job_id ? {
                    ...row,
                    cancel_requested: true
                  } : row));
                } catch {
                  setError('Cancellation could not be requested. Try again.');
                } finally {
                  setPending(null);
                }
              }}>{job.cancel_requested ? t("Stopping after current step") : t("Cancel")}</button>}</td>
            </tr>)}</tbody>
        </table></div>}
    </section>;
}
