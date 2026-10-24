import { useEffect,useState } from 'react';
import { Link } from 'react-router-dom';
import { t,useLocale,getLocale } from '../i18n/language';
import { reviewLabel } from '../i18n/finding-labels';
import { getRemediation,createRemediation,updateRemediation,getRemediationHistory,retestRemediation } from '../api/dashboard';
import WebScanSettings from '../components/WebScanSettings';
import '../components/finding-quality.css';
const states=['planned','in_progress','ready_for_retest','completed'];
function taskState(state){
  if(state==='in_progress')return t('In progress');
  if(state==='ready_for_retest')return t('Ready for recheck');
  if(state==='completed')return t('Completed');
  return t('Planned');
}
const severityOrder={Critical:0,High:1,Medium:2,Low:3,Info:4};
export default function Remediation(){
  useLocale();
  const [data,setData]=useState({tasks:[],candidates:[]});const [error,setError]=useState('');const [pending,setPending]=useState(null);
  const [filter,setFilter]=useState('active');
  async function reload(){try{const response=await getRemediation();setData(response.data);setError('');}catch(err){setError(err.response?.data?.error || 'Unable to load remediation tasks.');}}
  useEffect(()=>{let active=true;async function load(){try{const response=await getRemediation();if(active){setData(response.data);setError('');}}catch{if(active)setError('Unable to load remediation tasks.');}}load();const timer=setInterval(load,5000);return()=>{active=false;clearInterval(timer);};},[]);
  async function add(finding){setPending(finding.finding_id);setError('');try{await createRemediation({finding_id:finding.finding_id});await reload();}catch(err){setError(err.response?.data?.error || 'Unable to create task.');}finally{setPending(null);}}
  const visible=data.tasks.filter(task=>filter==='all' || (filter==='active' ? task.state!=='completed' : task.state==='completed')).sort((a,b)=>severityOrder[a.severity]-severityOrder[b.severity] || Number(b.review_state==='confirmed')-Number(a.review_state==='confirmed') || (a.due_date || '9999').localeCompare(b.due_date || '9999'));
  return <main className="quality-panel" style={{padding:24,color:'#f8fafc',background:'#0f172a',minHeight:'100vh'}}>
    <h1>{t('Remediation')}</h1><p>{t('Track responsibility and progress. Assignee names do not grant account access.')}</p>
    {error && <p role="alert">{t(error)}</p>}
    <section><h2>{t('Prioritized active findings')}</h2><p>{t('The last completed scan per target and tool is used. Information and suppressed findings are excluded; incomplete scans still require review.')}</p>
      {!data.candidates.length && <p>{t('No active candidates. This is not a security guarantee.')}</p>}
      {data.candidates.map(finding=><article key={finding.finding_id} style={{border:'1px solid #334155',padding:14,marginBlock:10,borderRadius:10}}><strong>{finding.title}</strong><p>{finding.target_name} · {t(finding.severity)} · {reviewLabel(finding.review_state)}</p><Link to={`/scans/${finding.scan_id}`}>{t('View scan details')}</Link>{' '}<button type="button" disabled={pending!==null || data.tasks.some(task=>task.finding_id===finding.finding_id)} onClick={()=>add(finding)}>{t('Create task')}</button></article>)}
    </section>
    <h2>{t('Remediation tasks')}</h2><label>{t('Task filter')}<select aria-label={t('Task filter')} value={filter} onChange={event=>setFilter(event.target.value)}><option value="active">{t('Active tasks')}</option><option value="completed">{t('Completed tasks')}</option><option value="all">{t('All tasks')}</option></select></label>
    {!visible.length && <p>{t('No tasks match this filter.')}</p>}
    {visible.map(task=><TaskCard key={task.id} task={task} onSaved={reload}/>)}
  </main>;
}
function TaskCard({task,onSaved}){
  useLocale();
  const [draft,setDraft]=useState(task);const [options,setOptions]=useState('{}');const [history,setHistory]=useState(null);
  const [error,setError]=useState('');const [pending,setPending]=useState(false);
  const dirty=['assignee','due_date','notes','state'].some(key=>draft[key]!==task[key]);
  async function save(){setPending(true);setError('');try{const response=await updateRemediation(task.id,{assignee:draft.assignee,due_date:draft.due_date,notes:draft.notes,state:draft.state,revision:draft.revision});setDraft(response.data);setHistory(null);await onSaved();}catch(err){setError(err.response?.data?.error || 'Unable to save task.');}finally{setPending(false);}}
  async function retest(){setPending(true);setError('');try{const parsed=JSON.parse(options);const response=await retestRemediation(task.id,parsed);setDraft(response.data);setOptions('{}');await onSaved();}catch(err){setError(err.response?.data?.error || 'Unable to queue the recheck. Check the scan settings.');}finally{setPending(false);}}
  async function historyLoad(){try{const response=await getRemediationHistory(task.id);setHistory(response.data);}catch{setError('Unable to load task history.');}}
  return <article style={{border:'1px solid #475569',padding:18,marginBlock:18,borderRadius:12,background:'#1e293b'}}>
    <h3>#{task.id} · {task.title}</h3><p>{task.target_name} · {t(task.severity)} · {reviewLabel(task.review_state)} · {taskState(task.state)}</p>
    <p>{t('This task tracks one occurrence. New scans require a new review.')}</p>
    <div style={{display:'flex',gap:12,flexWrap:'wrap'}}>
      <label>{t('Assignee name')}<input aria-label={t('Assignee name')} maxLength={100} value={draft.assignee} disabled={pending} onChange={event=>setDraft({...draft,assignee:event.target.value})}/></label>
      <label>{t('Target date')}<input aria-label={t('Target date')} type="date" value={draft.due_date} disabled={pending} onInput={event=>setDraft(previous=>({...previous,due_date:event.target.value}))} onChange={event=>setDraft(previous=>({...previous,due_date:event.target.value}))}/></label>
      <label>{t('Progress state')}<select aria-label={t('Progress state')} value={draft.state} disabled={pending} onChange={event=>setDraft({...draft,state:event.target.value})}>{states.map(state=><option key={state} value={state}>{taskState(state)}</option>)}</select></label>
    </div>
    <label>{t('Progress notes')}<textarea aria-label={t('Progress notes')} maxLength={4000} rows={3} value={draft.notes} disabled={pending} onChange={event=>setDraft({...draft,notes:event.target.value})} style={{width:'100%'}}/></label>
    <button type="button" disabled={pending || !dirty} onClick={save}>{t('Save task')}</button>{' '}<button type="button" disabled={pending} onClick={()=>setDraft(task)}>{t('Reload task')}</button>{' '}<button type="button" onClick={historyLoad}>{t('Task history')}</button>
    {error && <p role="alert">{t(error)}</p>}
    <p>{t('Save changes before rechecking. Previous authentication settings are not reused automatically.')}</p>
    {task.tool==='zap' && <details><summary>{t('Recheck scan settings')}</summary><WebScanSettings value={options} onChange={setOptions}/></details>}
    <button type="button" disabled={pending || dirty || task.target_deleted || ['queued','running'].includes(task.last_job_status)} onClick={retest}>{t('Recheck target')}</button>{' '}
    {task.last_job_id && <Link to="/targets">{t('View scan progress')}</Link>}
    {task.last_job_status && <p>{t('Recheck status')}: {t(task.last_job_status)}</p>}
    {task.comparison_scan_id && <Link to={`/scans?baseline=${task.baseline_scan_id}&current=${task.comparison_scan_id}`}>{t('Compare with baseline')}</Link>}
    <p><Link to={`/scans/${task.baseline_scan_id}`}>{t('Review original finding')}</Link></p>
    {task.state==='completed' && task.review_state!=='fixed' && <p role="alert">{t('The finding review changed. Reassess task completion.')}</p>}
    {history && <ol>{history.map(entry=><li key={entry.id}>{taskState(entry.state)} · {entry.assignee} · {entry.due_date} · {new Date(entry.created_at).toLocaleString(getLocale())}<p style={{whiteSpace:'pre-wrap'}}>{entry.notes}</p></li>)}</ol>}
  </article>;
}
