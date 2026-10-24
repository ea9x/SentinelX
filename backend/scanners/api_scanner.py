"""Bounded same-origin API discovery and identity-aware read checks."""
import hashlib
import json
import re
import time
import secrets as random_secrets
from urllib.parse import urlsplit, urlencode, parse_qsl, urlunsplit
import requests
import yaml
from scan_options import local_path, validate_options
from job_control import check_cancelled, ScanCancelled

MAX_BODY = 1024 * 1024
SQL_ERROR = re.compile(r'SQLITE_ERROR|SQL syntax.*MySQL|unterminated quoted string|SequelizeDatabaseError|ORA-\d{5}', re.I)


def run_api_scan(target_url, options=None, seed=None, on_authenticated=None):
    options = validate_options(options or {})
    base = target_url.rstrip('/')
    if urlsplit(base).path not in {'', '/'}:
        raise ValueError('The API scanner requires a target origin.')
    session = requests.Session(); session.trust_env = False
    started = time.monotonic(); observations = []; findings = []; discovered = set()
    secrets = []
    def clean(value):
        text = str(value)
        for secret in sorted(set(secrets), key=len, reverse=True):
            if secret: text = text.replace(secret, '[REDACTED]')
        return text
    def fetch(path, headers=None, body=None):
        check_cancelled()
        local_path(path)
        if time.monotonic() - started > 100:
            raise TimeoutError('API checks exceeded their time budget.')
        session.cookies.clear()
        with session.request('POST' if body is not None else 'GET', base+path, headers=headers or {},
                             json=body, timeout=10, allow_redirects=False, stream=True) as response:
            content = bytearray()
            for chunk in response.iter_content(16384):
                content.extend(chunk)
                if len(content) > MAX_BODY: raise ValueError('Response exceeds API scan size limit.')
            return response.status_code, bytes(content).decode('utf-8', errors='replace'), response.headers.get('Content-Type','')
    def add(title, path, cwe, evidence, severity='Medium'):
        findings.append({'title':title,'severity':severity,'cve_id':cwe,'description':evidence,
                         'recommendation':'Restrict access on the server and verify the result manually.',
                         'affected_url':base+path,'affected_path':urlsplit(path).path,'http_method':'GET',
                         'source_tool':'zap','confidence':'High','evidence':evidence})
    def visit(path, headers=None):
        status, body, mime = fetch(path, headers)
        discovered.add(path)
        if seed:
            seed(path, headers or {})
        return status, body, mime
    try:
        paths = list(options.get('paths', []))
        spec_paths = [options['openapi_path']] if options.get('openapi_path') else ['/openapi.json','/swagger.json','/api-docs/swagger.yaml','/api-docs/swagger-ui-init.js']
        found_spec=False
        for spec_path in spec_paths:
            status, body, mime = fetch(spec_path)
            if status != 200:
                continue
            if 'html' in mime:
                continue
            embedded = re.search(r'[\"\']swaggerDoc[\"\']\s*:\s*',body)
            spec = json.JSONDecoder().raw_decode(body[embedded.end():].lstrip())[0] if embedded else yaml.safe_load(body)
            if not isinstance(spec, dict) or not isinstance(spec.get('paths'), dict) or not ('openapi' in spec or 'swagger' in spec):
                continue
            found_spec=True
            # Parse the definition locally. Never resolve external $refs or trust server hosts.
            prefix = spec.get('basePath', '')
            if spec.get('servers'):
                prefix = urlsplit(spec['servers'][0].get('url','')).path.rstrip('/')
            if prefix: local_path(prefix)
            read_count=0; skipped=0
            for path, methods in list(spec['paths'].items())[:200]:
                if not isinstance(methods, dict) or 'get' not in methods or '{' in path:
                    skipped+=1; continue
                candidate=local_path(prefix+path)
                operation = methods['get']
                if isinstance(operation, dict):
                    parameters = list(methods.get('parameters', [])) + list(operation.get('parameters', []))
                    query = []
                    for parameter in parameters[:10]:
                        if not isinstance(parameter, dict) or parameter.get('in') != 'query' or not parameter.get('name'): continue
                        schema = parameter.get('schema', parameter)
                        sample = parameter.get('example', schema.get('default', (schema.get('enum') or ['sentinelx-test'])[0]))
                        if isinstance(sample, (str, int, float, bool)): query.append((parameter['name'], str(sample)))
                    if query: candidate=local_path(candidate+'?'+urlencode(query))
                if len(paths)<30: paths.append(candidate); read_count+=1
            observations.append({'openapi_path':spec_path,'read_operations':read_count,'skipped_operations':skipped,
                                 'note':'GET operations only; external references and write operations are not executed.'})
            break
        if options.get('openapi_path') and not found_spec:
            raise ValueError('The configured path did not return an OpenAPI definition.')
        # General exposure checks also provide useful results without an API profile.
        for path in dict.fromkeys(['/metrics','/ftp/']+paths):
            status, body, mime = visit(path)
            if status==200 and '# HELP' in body and '# TYPE' in body:
                add('Unauthenticated Prometheus metrics',path,'CWE-200','Prometheus metrics were returned without authentication.')
            if status==200 and re.search(r'(Index of|listing directory|Directory listing)',body,re.I):
                links=re.findall(r'href=[\"\']([^\"\']+)[\"\']',body)
                add('Unauthenticated directory listing',path,'CWE-548','A directory index listed files without authentication.')
                for link in links[:10]:
                    if link.startswith(('/', 'http:', 'https:', '//')) or '..' in link or not link.lower().endswith(('.md','.txt','.csv')): continue
                    child=local_path(path.rstrip('/')+'/'+link)
                    child_status, child_body, _ = visit(child)
                    if child_status==200 and re.search(r'\bconfidential\b|internal use only',child_body,re.I):
                        add('Potential confidential document exposure',child,'CWE-200','A publicly retrievable document contains a confidentiality marker. Review its intended visibility.')
        for path in options.get('query_checks', []):
            parsed=urlsplit(path); pairs=parse_qsl(parsed.query,keep_blank_values=True)
            for index,(name,value) in enumerate(pairs[:5]):
                changed=pairs[:]; changed[index]=(name,value+"'))")
                probe=urlunsplit(('', '', parsed.path, urlencode(changed), ''))
                status,body,_=visit(probe)
                if status>=500 and SQL_ERROR.search(body):
                    add('SQL error disclosure',path,'CWE-209',f'A bounded syntax probe for parameter {name} returned HTTP {status} and a database error signature.')
        accounts=[]
        for number,account in enumerate(options.get('accounts', [])):
            headers=dict(account.get('headers',{})); secrets.extend(headers.values())
            if account.get('login'):
                login=account['login']; secrets.extend(str(v) for v in login['json'].values())
                status,body,_=fetch(login['path'],body=login['json'])
                if status!=200: raise ValueError('Test account login failed.')
                token=json.loads(body)
                for part in login['token_field'].split('.'): token=token[part]
                if not isinstance(token,str) or not token or any(ord(c)<32 for c in token): raise ValueError('Login token is invalid.')
                secrets.append(token);headers={'Authorization':'Bearer '+token};secrets.extend(headers.values())
            status,body,_=visit(account['verify_path'],headers)
            anonymous_status,anonymous,_=fetch(account['verify_path'])
            if status!=200 or account['verify_marker'] not in body or (anonymous_status==200 and account['verify_marker'] in anonymous):
                raise ValueError('Authentication verification failed or the verification resource is public.')
            accounts.append(headers)
            if number==0 and on_authenticated: on_authenticated(headers)
            observations.append({'account':number+1,'authenticated_verification':'passed','path':account['verify_path']})
        if len(accounts)==2 and accounts[0]==accounts[1]: raise ValueError('The two test accounts must have distinct sessions.')
        if options.get('login_injection_checks'):
            account=options['accounts'][0];login=account['login']
            if fetch(account['verify_path'])[0] not in {401,403,404}:
                raise ValueError('Login injection verification resource must deny anonymous access.')
            field='email' if 'email' in login['json'] else 'username'
            invalid_password=random_secrets.token_urlsafe(24);secrets.append(invalid_password)
            def usable_login(identifier):
                payload={**login['json'],field:identifier,'password':invalid_password}
                status,body,_=fetch(login['path'],body=payload)
                if status==429 or status>=500:raise ValueError('Login probe was rate limited or failed.')
                if status!=200:return False
                try:
                    token=json.loads(body)
                    for part in login['token_field'].split('.'):token=token[part]
                except (ValueError,KeyError,TypeError):return False
                if not isinstance(token,str) or not token or any(ord(c)<32 for c in token):return False
                secrets.append(token)
                verified,resource,_=fetch(account['verify_path'],{'Authorization':'Bearer '+token})
                if verified==429 or verified>=500:raise ValueError('Login verification was rate limited or failed.')
                return verified==200 and account['verify_marker'] in resource
            # Independent invalid credentials and paired false/true predicates prevent
            # treating HTTP 200, token-shaped text or a public resource as a bypass.
            if usable_login('sentinelx-invalid-'+random_secrets.token_hex(12)):
                raise ValueError('Invalid login control produced a usable session.')
            found=False
            for positive,negative in [("' OR 1=1-- ","' OR 1=2-- "),("' OR '1'='1'-- ","' OR '1'='2'-- ")]:
                if usable_login(negative):raise ValueError('False login predicate produced a usable session.')
                if usable_login(positive):
                    add('Potential SQL injection authentication bypass',login['path'],'CWE-89',
                        'Invalid credentials and a false predicate were rejected. A paired true login predicate produced a session that accessed a private verification resource. Manual confirmation is required.','High')
                    findings[-1].update(http_method='POST',parameter_name=field)
                    found=True;break
            observations.append({'login_injection_check':login['path'],'result':'paired_login_bypass_observed' if found else 'no_validated_login_bypass','manual_review_required':found})
        for check in options.get('authorization_checks', []):
            a_status,a_body,_=fetch(check['path_a'],accounts[0]);b_status,b_body,_=fetch(check['path_b'],accounts[1])
            anon_status,anon_body,_=fetch(check['path_b'])
            cross_status,cross_body,_=fetch(check['path_b'],accounts[0])
            owned=a_status==b_status==200 and check['marker_a'] in a_body and check['marker_b'] in b_body and check['marker_b'] not in a_body
            private=anon_status in {401,403,404}
            if owned and private and cross_status==200 and check['marker_b'] in cross_body:
                add('Cross-account private resource access',check['path_b'],'CWE-639','Two distinct verified sessions were used. The owner could read resource B; anonymous access was denied, but account A retrieved the owner-specific marker from B.','High')
                observations.append({'authorization_check':check['path_b'],'result':'cross_account_access_confirmed'})
            else:
                observations.append({'authorization_check':check['path_b'],'result':'no_confirmed_cross_account_access',
                                     'owned_resources_verified':owned,'anonymous_access_denied':private,'cross_status':cross_status})
        return {'success':True,'vulnerabilities':findings,'observations':observations,'paths':sorted(discovered)}
    except (requests.RequestException,ValueError,KeyError,TypeError,TimeoutError,yaml.YAMLError,ScanCancelled):
        # Do not stringify exceptions or server payloads that may contain credentials.
        return {'success':False,'error':'API coverage checks could not complete. Check the configured paths and test accounts.',
                'vulnerabilities':findings,'observations':observations,'paths':sorted(discovered)}
    finally:
        session.close()
        # Marker values, login payloads and response bodies are never exported.
        for finding in findings:
            for key,value in list(finding.items()):
                if isinstance(value,str): finding[key]=clean(value)
