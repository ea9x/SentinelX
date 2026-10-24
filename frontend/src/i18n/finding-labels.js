import { t } from './language';
export function reviewLabel(state){
  if(state==='confirmed')return t('Confirmed');
  if(state==='false_positive')return t('False positive');
  if(state==='fixed')return t('Fixed');
  return t('Needs review');
}
export function comparisonLabel(state){
  if(state==='new')return t('New findings');
  if(state==='persistent')return t('Persistent findings');
  if(state==='not_observed')return t('Not observed in newer scan');
  if(state==='insufficient_location')return t('Insufficient location data');
  return state;
}
export function typeLabel(value){return value==='information' ? t('Informational observations') : t('Potential vulnerabilities');}
