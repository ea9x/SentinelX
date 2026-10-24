import { Component } from 'react';
import { t, useLocale } from '../i18n/language';
function Recovery(){
  useLocale();
  return <main role="alert" style={{padding:32,color:'#f8fafc',background:'#0f172a',minHeight:'100vh'}}>
    <h1>{t('The workspace could not load.')}</h1>
    <p>{t('Reload to get the latest version. Your saved scans are not affected.')}</p>
    <button type="button" onClick={()=>window.location.reload()}>{t('Reload workspace')}</button>
  </main>;
}
export default class WorkspaceErrorBoundary extends Component {
  state={failed:false};
  static getDerivedStateFromError(){return {failed:true};}
  render(){return this.state.failed ? <Recovery/> : this.props.children;}
}
