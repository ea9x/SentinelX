import "./finding-quality.css";
import { useState } from 'react';
import { t, useLocale } from '../i18n/language';
import { comparisonLabel,typeLabel } from '../i18n/finding-labels';
import { compareScans } from '../api/dashboard';
import { Link, useSearchParams } from 'react-router-dom';
export default function ScanComparison({scans}){
  useLocale();
  const [params]=useSearchParams();
  const [baseline,setBaseline]=useState(params.get('baseline') || '');const [current,setCurrent]=useState(params.get('current') || '');
  const [includeInformation,setIncludeInformation]=useState(false);const [result,setResult]=useState(null);
  const [error,setError]=useState('');const [pending,setPending]=useState(false);
  const completed=scans.filter(scan=>scan.status==='completed');
  const selected=completed.find(scan=>String(scan.id)===baseline);
  const candidates=completed.filter(scan=>scan.target_id===selected?.target_id && scan.tool_used===selected?.tool_used && scan.id!==selected?.id && (new Date(scan.started_at || 0)>new Date(selected.started_at || 0) || (scan.started_at===selected.started_at && scan.id>selected.id)));
  async function compare(){setPending(true);setError('');setResult(null);try{const response=await compareScans(baseline,current,includeInformation);setResult(response.data);}catch(err){setError(err.response?.data?.error || 'Unable to compare scans.');}finally{setPending(false);}}
  return <section className="quality-panel" style={{padding:20,marginBlock:20,border:'1px solid #475569',borderRadius:12,background:'#1e293b',color:'#f8fafc'}}>
    <h2>{t('Compare scans')}</h2>
    <p>{t('Choose completed scans for the same target and tool. Not observed does not prove remediation or equivalent coverage.')}</p>
    <div style={{display:'flex',gap:12,flexWrap:'wrap'}}>
      <label>{t('Older scan')}<select aria-label={t('Older scan')} value={baseline} disabled={pending} onChange={event=>{setBaseline(event.target.value);setCurrent('');setResult(null);}}><option value="">{t('Choose a scan')}</option>{completed.map(scan=><option key={scan.id} value={String(scan.id)}>#{scan.id} · {scan.target_name} · {scan.tool_used}</option>)}</select></label>
      <label>{t('Newer scan')}<select aria-label={t('Newer scan')} value={current} disabled={pending} onChange={event=>{setCurrent(event.target.value);setResult(null);}}><option value="">{t('Choose a scan')}</option>{candidates.map(scan=><option key={scan.id} value={String(scan.id)}>#{scan.id} · {scan.target_name} · {scan.tool_used}</option>)}</select></label>
      <label><input type="checkbox" checked={includeInformation} disabled={pending} onChange={event=>{setIncludeInformation(event.target.checked);setResult(null);}}/>{t('Include informational observations')}</label>
      <button type="button" disabled={!baseline || !current || pending} onClick={compare}>{t('Compare')}</button>
    </div>
    {error && <p role="alert">{t(error)}</p>}
    {result && <><p role="note">{t(result.warning)}</p>{Object.entries(result.groups).map(([category,groups])=><section key={category}>
      <h3>{comparisonLabel(category)}: {groups.length}</h3>{groups.map(group=><details key={group.fingerprint}><summary>{group.title} · {t(group.severity)} · {typeLabel(group.finding_type)}</summary>{group.occurrences.map(entry=><div key={entry.id}><Link to={`/scans/${entry.scan_id}`}>{t('Scan #')}{entry.scan_id}</Link><p>{entry.source_tool} · {entry.affected_url || entry.affected_path}</p><pre dir="ltr" style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{entry.evidence}</pre></div>)}</details>)}
    </section>)}</>}
  </section>;
}
