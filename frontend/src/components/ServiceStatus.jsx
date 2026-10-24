import { useEffect, useState } from 'react';
import { t, useLocale } from '../i18n/language';
import api from '../api/axios';
export default function ServiceStatus(){
  useLocale();
  const [state,setState]=useState(null);
  useEffect(()=>{
    let active=true;
    async function check(){
      try {const response=await api.get('/health',{timeout:6000});if(active)setState({offline:false,missing:Object.values(response.data.checks || {}).filter(service=>!service.available).map(service=>service.label)});}
      catch(error){if(active)setState(error.response?.status===401 || error.response?.status===403 ? null : {offline:true,missing:[]});}
    }
    check(); const timer=setInterval(check,15000);
    return()=>{active=false;clearInterval(timer);};
  },[]);
  if(!state || (!state.offline && !state.missing.length))return null;
  return <aside role="status" style={{position:'relative',zIndex:13000,padding:14,marginBottom:16,border:'1px solid #f59e0b',borderRadius:10,background:'#422006',color:'#fef3c7'}}>
    <strong>{t(state.offline ? 'The backend is unavailable. Open SentinelX using the launcher and retry.' : 'Some scan services are unavailable:')}</strong> {state.missing.join(', ')}
    <p>{t('This status updates automatically. Unavailable services do not imply that targets are secure.')}</p>
  </aside>;
}
