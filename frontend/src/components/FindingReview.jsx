import "./finding-quality.css";
import { useState } from 'react';
import { t, useLocale, getLocale } from '../i18n/language';
import { reviewLabel } from '../i18n/finding-labels';
import { reviewFinding, getFindingReviews } from '../api/dashboard';
const states=['needs_review','confirmed','false_positive','fixed'];
export default function FindingReview({finding,onSaved}){
  useLocale();
  const [state,setState]=useState(finding.review_state || 'needs_review');
  const [note,setNote]=useState(finding.review_note || '');
  const [pending,setPending]=useState(false);
  const [error,setError]=useState('');
  const [history,setHistory]=useState(null);
  async function save(){
    setPending(true);setError('');
    try {const response=await reviewFinding(finding.id,{review_state:state,review_note:note,review_revision:finding.review_revision || 0});onSaved(response.data);setHistory(null);window.dispatchEvent(new Event('sentinelx:data-updated'));}
    catch(err){setError(err.response?.data?.error || 'Unable to save review.');}
    finally{setPending(false);}
  }
  async function loadHistory(){
    try{const response=await getFindingReviews(finding.id);setHistory(response.data);setError('');}
    catch{setError('Unable to load review history.');}
  }
  return <details className="quality-review" onClick={event=>event.stopPropagation()} onKeyDown={event=>event.stopPropagation()} style={{marginBlock:8,minWidth:220}}>
    <summary>{t('Review occurrence')} #{finding.id} · {reviewLabel(finding.review_state)}</summary>
    <p>{t('Applies to this occurrence only. A new scan requires a new review.')}</p>
    <label>{t('Review state')}<select aria-label={t('Review state')} value={state} disabled={pending} onChange={event=>setState(event.target.value)}>{states.map(value=><option key={value} value={value}>{reviewLabel(value)}</option>)}</select></label>
    <label style={{display:'block'}}>{t('Review note')}<textarea aria-label={t('Review note')} value={note} maxLength={2000} rows={3} disabled={pending} onChange={event=>setNote(event.target.value)} style={{display:'block',width:'100%',boxSizing:'border-box'}}/></label>
    <p>{t('A reason is required for false positive or fixed. Maximum 2000 characters.')}</p>
    <button type="button" disabled={pending} onClick={save}>{t('Save review')}</button>{' '}
    <button type="button" disabled={pending} onClick={loadHistory}>{t('Review history')}</button>
    {error && <p role="alert">{t(error)}</p>}
    {history && (history.length ? <ol>{history.map(entry=><li key={entry.id}>{reviewLabel(entry.previous_state)} → {reviewLabel(entry.review_state)} · {new Date(entry.reviewed_at).toLocaleString(getLocale())}<p style={{whiteSpace:'pre-wrap'}}>{entry.review_note}</p></li>)}</ol> : <p>{t('No manual reviews yet.')}</p>)}
  </details>;
}
