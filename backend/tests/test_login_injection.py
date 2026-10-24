"""Independent SQLite-backed login targets, including parameterized controls."""
import json,sqlite3,threading,unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from scanners.api_scanner import run_api_scan
from scan_options import validate_options
from scanners import zap_scanner


class LoginTarget(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def send(self,status,body):
        self.send_response(status);self.send_header('Content-Type','application/json');self.end_headers()
        self.wfile.write(json.dumps(body).encode())
    def do_GET(self):
        if self.path=='/private':
            if self.server.mode=='public' or self.headers.get('Authorization') in {'Bearer fixture-token-1','Bearer fixture-token-2'}:
                return self.send(200,{'marker':'private-fixture-marker'})
            return self.send(401,{})
        return self.send(404,{})
    def do_POST(self):
        body=json.loads(self.rfile.read(int(self.headers['Content-Length'])));self.server.logins.append(body)
        identity=body.get(self.server.field,'');password=body.get('password','')
        mode=self.server.mode
        if mode=='rate_limit' and identity!='test@example.test':return self.send(429,{})
        if mode=='accept_all':row=(1,)
        elif mode=='false_accept' and identity.startswith("' OR"):row=(1,)
        elif mode=='vulnerable':
            try:row=self.server.database.execute(f"SELECT id FROM users WHERE email='{identity}' AND password='{password}'").fetchone()
            except sqlite3.Error:return self.send(400,{})
        else:row=self.server.database.execute('SELECT id FROM users WHERE email=? AND password=?',(identity,password)).fetchone()
        if not row:
            if mode in {'generic_200','fake_token'}:return self.send(200,{'authentication':{'token':'not-a-usable-session'}})
            return self.send(401,{})
        return self.send(200,{'authentication':{'token':'fixture-token-'+str(row[0])}})


class LoginInjectionTests(unittest.TestCase):
    def run_target(self,mode,enabled=True,field='email'):
        server=ThreadingHTTPServer(('127.0.0.1',0),LoginTarget)
        server.mode=mode;server.field=field;server.logins=[]
        server.database=sqlite3.connect(':memory:',check_same_thread=False)
        server.database.executescript("CREATE TABLE users(id INTEGER,email TEXT,password TEXT);INSERT INTO users VALUES(1,'admin@example.test','admin-private'),(2,'test@example.test','fixture-password');")
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        profile={'accounts':[{'login':{'path':'/login','json':{field:'test@example.test','password':'fixture-password'},'token_field':'authentication.token'},'verify_path':'/private','verify_marker':'private-fixture-marker'}]}
        if enabled:profile['login_injection_checks']=True
        try:
            result=run_api_scan('http://127.0.0.1:'+str(server.server_port),profile)
            return result,list(server.logins)
        finally:server.shutdown();server.server_close();thread.join();server.database.close()

    def test_actual_sqlite_bypass_requires_paired_controls_and_private_access(self):
        result,logins=self.run_target('vulnerable')
        self.assertTrue(result['success']);self.assertEqual(len(result['vulnerabilities']),1)
        finding=result['vulnerabilities'][0]
        self.assertEqual(finding['cve_id'],'CWE-89');self.assertEqual(finding['http_method'],'POST');self.assertEqual(finding['parameter_name'],'email')
        self.assertTrue(any(body['email']=="' OR 1=2-- " for body in logins))
        exported=json.dumps(result)
        for secret in ['fixture-password','fixture-token-1','fixture-token-2','private-fixture-marker']:self.assertNotIn(secret,exported)

    def test_parameterized_and_generic_200_targets_do_not_trigger(self):
        for mode in ['parameterized','generic_200','fake_token']:
            with self.subTest(mode=mode):
                result,_=self.run_target(mode)
                self.assertTrue(result['success']);self.assertEqual(result['vulnerabilities'],[])

    def test_accepted_invalid_and_false_controls_are_incomplete_not_injection(self):
        for mode in ['accept_all','false_accept']:
            with self.subTest(mode=mode):
                result,_=self.run_target(mode)
                self.assertFalse(result['success']);self.assertEqual(result['vulnerabilities'],[])

    def test_rate_limit_and_public_verification_cannot_prove_bypass(self):
        for mode in ['rate_limit','public']:
            with self.subTest(mode=mode):
                result,_=self.run_target(mode)
                self.assertFalse(result['success']);self.assertEqual(result['vulnerabilities'],[])

    def test_disabled_by_default_and_username_login_supported(self):
        result,logins=self.run_target('vulnerable',enabled=False)
        self.assertTrue(result['success']);self.assertEqual(len(logins),1);self.assertEqual(result['vulnerabilities'],[])
        result,_=self.run_target('vulnerable',field='username')
        self.assertTrue(result['success']);self.assertEqual(result['vulnerabilities'][0]['parameter_name'],'username')

    def test_option_rejects_non_boolean_and_non_login_accounts(self):
        for value in ['true',1,[],None]:
            with self.assertRaises(ValueError):validate_options({'login_injection_checks':value})
        with self.assertRaises(ValueError):validate_options({'login_injection_checks':True})

    def test_incomplete_api_controls_keep_zap_scan_incomplete(self):
        api={'success':False,'vulnerabilities':[],'observations':[]}
        with patch.object(zap_scanner,'_zap_get',return_value={'version':'fixture'}),patch.object(zap_scanner,'run_api_scan',return_value=api),patch.object(zap_scanner,'_run_spider',return_value={'success':True}),patch.object(zap_scanner,'_run_active_scan',return_value={'success':True}),patch.object(zap_scanner,'_get_alerts',return_value=[]):
            result=zap_scanner.run_zap_scan('http://127.0.0.1:1')
        self.assertFalse(result['success'])
