import { t, useLocale } from "../i18n/language";
const inputStyle = {
  width: '100%',
  boxSizing: 'border-box',
  padding: 10,
  marginTop: 5,
  color: '#e2e8f0',
  background: '#0f172a',
  border: '1px solid #475569',
  borderRadius: 7
};
const gridStyle = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
  gap: 14
};
const field = (label, value, change, type = 'text') => <label style={{
  display: 'block',
  marginBottom: 12
}}>{t(label)}<input type={type} value={value || ''} onChange={e => change(e.target.value)} style={inputStyle} autoComplete="off" /></label>;
export default function WebScanSettings({
  value,
  onChange
}) {
  useLocale();
  let options;
  try {
    options = JSON.parse(value);
  } catch {
    options = {};
  }
  if (!options || typeof options !== 'object' || Array.isArray(options)) options = {};
  const update = (key, next) => onChange(JSON.stringify({
    ...options,
    [key]: next
  }, null, 2));
  const accountList = Array.isArray(options.accounts) ? options.accounts.filter(item => item && typeof item === 'object') : [];
  const changeAccount = (index, change) => update('accounts', accountList.map((account, i) => i === index ? {
    ...account,
    ...change
  } : account));
  const lines = text => text.split('\n').map(line => line.trim()).filter(Boolean);
  const cases = Array.isArray(options.authorization_checks) ? options.authorization_checks.filter(item => item && typeof item === 'object') : [];
  return <div className="web-scan-form">
        <style>{`.web-scan-form button { background:#075985; color:#e0f2fe; border:1px solid #0ea5e9; border-radius:7px; padding:8px 12px; cursor:pointer; } .web-scan-form button:disabled { opacity:.5; cursor:default; } .web-scan-form legend { color:#bae6fd; padding:0 5px; }`}</style>
        <p>{t("Configure the next ZAP or Full scan for the target you select below. Use dedicated test accounts.")}</p>
        <div style={gridStyle}>
            <label>{t("Scan coverage")}<select style={inputStyle} value={options.scan_mode || 'focused'} onChange={e => update('scan_mode', e.target.value)}>
                <option value="focused">{t("Focused \u2014 fewer active probes")}</option><option value="comprehensive">{t("Comprehensive \u2014 default ZAP policy")}</option>
            </select></label>
            {field(t("OpenAPI definition path (optional)"), options.openapi_path, next => update('openapi_path', next))}
        </div>
        <div style={gridStyle}>
            <label>{t("API paths \u2014 one per line")}<textarea style={inputStyle} rows={3} value={(Array.isArray(options.paths) ? options.paths : []).join('\n')} onChange={e => update('paths', lines(e.target.value))} /></label>
            <label>{t("Query checks \u2014 one URL path per line")}<textarea style={inputStyle} rows={3} value={(Array.isArray(options.query_checks) ? options.query_checks : []).join('\n')} onChange={e => update('query_checks', lines(e.target.value))} /></label>
        </div>
        <label style={{
      display: 'block',
      marginTop: 14
    }}>{t("Test accounts")}<select style={inputStyle} value={accountList.length} onChange={e => {
        const count = Number(e.target.value);
        const accounts = Array.from({
          length: count
        }, (_, i) => accountList[i] || {
          headers: {
            Authorization: ''
          },
          verify_path: '',
          verify_marker: ''
        });
        onChange(JSON.stringify({
          ...options,
          accounts,
          authorization_checks: count === 2 ? cases : [],
          authenticated_zap: count ? !!options.authenticated_zap : false,
          login_injection_checks: count ? !!options.login_injection_checks : false
        }, null, 2));
      }}><option value="0">{t("Public checks only")}</option><option value="1">{t("One test account")}</option><option value="2">{t("Two accounts \u2014 authorization comparison")}</option></select></label>
        {accountList.map((account, index) => <fieldset key={index} style={{
      border: '1px solid #475569',
      borderRadius: 8,
      padding: 14,
      marginTop: 16
    }}>
            <legend>{t("Account ")}{index + 1}</legend>
            <label>{t("Authentication method")}<select style={inputStyle} value={account.login ? 'login' : account.headers?.Cookie !== undefined ? 'cookie' : 'bearer'} onChange={e => {
          const next = {
            ...account
          };
          delete next.headers;
          delete next.login;
          if (e.target.value === 'login') next.login = {
            path: '/api/login',
            json: {
              email: '',
              password: ''
            },
            token_field: 'authentication.token'
          };else next.headers = e.target.value === 'cookie' ? {
            Cookie: ''
          } : {
            Authorization: ''
          };
          onChange(JSON.stringify({
            ...options,
            accounts: accountList.map((item, i) => i === index ? next : item),
            authenticated_zap: index === 0 && e.target.value !== 'login' ? false : !!options.authenticated_zap,
            login_injection_checks: index === 0 && e.target.value !== 'login' ? false : !!options.login_injection_checks
          }, null, 2));
        }}><option value="bearer">{t('Bearer token')}</option><option value="cookie">{t("Session cookie")}</option><option value="login">{t("JSON login")}</option></select></label>
            {account.login ? <div style={gridStyle}>
                {field(t("Login path"), account.login.path, path => changeAccount(index, {
          login: {
            ...account.login,
            path
          }
        }))}
                {field(t("Token response field"), account.login.token_field, token_field => changeAccount(index, {
          login: {
            ...account.login,
            token_field
          }
        }))}
                {field(t("Email"), account.login.json?.email, email => changeAccount(index, {
          login: {
            ...account.login,
            json: {
              ...account.login.json,
              email
            }
          }
        }))}
                {field(t("Password"), account.login.json?.password, password => changeAccount(index, {
          login: {
            ...account.login,
            json: {
              ...account.login.json,
              password
            }
          }
        }), 'password')}
            </div> : field(account.headers?.Cookie !== undefined ? t("Session cookie") : t('Bearer token (without Bearer prefix)'), account.headers?.Cookie ?? (account.headers?.Authorization || '').replace(/^Bearer /, ''), next => changeAccount(index, {
        headers: account.headers?.Cookie !== undefined ? {
          Cookie: next
        } : {
          Authorization: 'Bearer ' + next
        }
      }), 'password')}
            <div style={gridStyle}>
                {field(t("Private verification path"), account.verify_path, verify_path => changeAccount(index, {
          verify_path
        }))}
                {field(t("Unique account marker in response"), account.verify_marker, verify_marker => changeAccount(index, {
          verify_marker
        }))}
            </div>
        </fieldset>)}
        <label style={{
      display: 'block',
      margin: '16px 0'
    }}><input type="checkbox" disabled={!accountList[0]?.login} checked={!!options.authenticated_zap} onChange={e => update('authenticated_zap', e.target.checked)} />{t(" Run ZAP crawling and active checks as account 1 (requires JSON login)")}</label>
        <p>{t("Authentication must pass verification first. A private per-scan ZAP context is removed after the scan. Existing token and cookie accounts support direct API checks. ZAP history may contain login requests and tokens.")}</p>
        {accountList.length === 2 && <div><h4>{t("Private resource comparisons")}</h4>{cases.map((item, index) => <fieldset key={index} style={{
        border: '1px solid #475569',
        padding: 12,
        marginBottom: 12
      }}><legend>{t("Comparison ")}{index + 1}</legend><div style={gridStyle}>{[['path_a', t("Account 1 owned resource path")], ['marker_a', t("Resource 1 unique marker")], ['path_b', t("Account 2 owned resource path")], ['marker_b', t("Resource 2 unique marker")]].map(([key, label]) => <div key={key}>{field(label, item[key], next => update('authorization_checks', cases.map((row, i) => i === index ? {
              ...row,
              [key]: next
            } : row)))}</div>)}</div><button type="button" onClick={() => update('authorization_checks', cases.filter((_, i) => i !== index))}>{t("Remove comparison")}</button></fieldset>)}<button type="button" disabled={cases.length >= 10} onClick={() => update('authorization_checks', [...cases, {
        path_a: '',
        path_b: '',
        marker_a: '',
        marker_b: ''
      }])}>{t("Add private resource comparison")}</button></div>}
        <label style={{display:'block',marginTop:16}}><input type="checkbox" disabled={!accountList[0]?.login} checked={!!options.login_injection_checks} onChange={event=>update('login_injection_checks',event.target.checked)}/> {t('Check JSON login injection')}</label>
        <p>{t('Optional probes use invalid credentials and paired controls for account 1. Use dedicated test accounts; login attempts may trigger rate limits.')}</p>
        <details style={{
      marginTop: 16
    }}><summary>{t("Advanced JSON settings")}</summary><textarea aria-label={t("Advanced web scan JSON")} style={{
        ...inputStyle,
        fontFamily: 'monospace'
      }} rows={10} value={value} onChange={e => onChange(e.target.value)} spellCheck={false} /></details>
        <button type="button" style={{
      marginTop: 12
    }} onClick={() => onChange('{}')}>{t("Clear all settings")}</button>
        <p>{t("Settings are cleared from this form when a web scan starts.")}</p>
    </div>;
}
